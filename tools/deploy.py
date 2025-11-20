#!/usr/bin/env python3
"""
deploy.py - branch-aware, MFA/keypair ready Snowflake CD runner
Supports:
- branch → schema mapping (dev/test/main → respective schemas)
- password auth, MFA fallback, key-pair auth
- preflight dry-run
- per-file selective execution of SQL & Python
- MIGRATION_LOG / PIPELINE_DEPLOYMENT_LOG management
"""

import os, sys, glob, logging, subprocess, time, argparse, re
from datetime import datetime
import snowflake.connector
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# --- Helpers ---
def get_env(name, default=None):
    val = os.environ.get(name, default)
    if val is None:
        logging.debug("Env %s not set", name)
    return val

def _load_private_key_bytes():
    path = os.environ.get("SNOWFLAKE_PRIVATE_KEY_FILE")
    base64_env = os.environ.get("SNOWFLAKE_PRIVATE_KEY")
    pem_bytes = None

    if path and os.path.exists(path):
        logging.info("Loading private key from file: %s", path)
        with open(path, "rb") as fh:
            pem_bytes = fh.read()
    elif base64_env:
        logging.info("Loading private key from SNOWFLAKE_PRIVATE_KEY env (base64)")
        pem_bytes = base64.b64decode(base64_env)

    if not pem_bytes:
        return None

    passphrase = os.environ.get("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE") or None
    if passphrase == "":
        passphrase = None
    if passphrase is not None:
        passphrase = passphrase.encode()

    p_key = serialization.load_pem_private_key(pem_bytes, password=passphrase, backend=default_backend())
    return p_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def connect_with_password(account, user, password, warehouse, database, schema, role=None):
    logging.info("Connecting via password auth (user=%s)", user)
    return snowflake.connector.connect(user=user, password=password, account=account,
                                       warehouse=warehouse, database=database, schema=schema, role=role)

def connect_with_keypair(account, user, private_key_der, warehouse, database, schema, role=None):
    logging.info("Connecting via key-pair auth (user=%s)", user)
    return snowflake.connector.connect(user=user, private_key=private_key_der, account=account,
                                       warehouse=warehouse, database=database, schema=schema, role=role)

def is_mfa_error(exc):
    msg = str(exc).upper() if exc else ""
    return any(x in msg for x in ["MFA", "TOTP", "250001", "MUST AUTHENTICATE", "MULTI-FACTOR", "MFA_REQUIRED"])

def qualify(db, schema, name):
    return f"{db}.{schema}.{name}"

# --- Logs ---
def ensure_deploy_log(conn, database, schema):
    fq = qualify(database, schema, "PIPELINE_DEPLOYMENT_LOG")
    cur = conn.cursor()
    try:
        logging.info("Ensuring deploy log exists: %s", fq)
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {fq} (
                DEPLOY_ID STRING,
                BRANCH STRING,
                COMMIT_SHA STRING,
                START_TS TIMESTAMP_LTZ,
                END_TS TIMESTAMP_LTZ,
                STATUS STRING,
                LOG_MESSAGE STRING
            )
        """)
        conn.commit()
    finally:
        cur.close()

def ensure_migration_log(conn, database, schema):
    fq = qualify(database, schema, "MIGRATION_LOG")
    cur = conn.cursor()
    try:
        logging.info("Ensuring migration log exists: %s", fq)
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {fq} (
                SCRIPT_NAME STRING PRIMARY KEY,
                APPLIED_AT TIMESTAMP_LTZ
            )
        """)
        conn.commit()
    finally:
        cur.close()

def log_deploy(conn, database, schema, deploy_id, branch, commit_sha, start_ts, end_ts, status, msg):
    fq = qualify(database, schema, "PIPELINE_DEPLOYMENT_LOG")
    cur = conn.cursor()
    try:
        cur.execute(f"""
            INSERT INTO {fq} (DEPLOY_ID, BRANCH, COMMIT_SHA, START_TS, END_TS, STATUS, LOG_MESSAGE)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (deploy_id, branch, commit_sha, start_ts, end_ts, status, msg))
        conn.commit()
    finally:
        cur.close()

# --- SQL discovery ---
RE_CREATE_TABLE = re.compile(r'create\s+(?:or\s+replace\s+)?table\s+([^\s(;]+)', re.IGNORECASE)
RE_CREATE_STAGE = re.compile(r'create\s+(?:or\s+replace\s+)?stage\s+([^\s;]+)', re.IGNORECASE)
RE_COPY_FROM_STAGE = re.compile(r'copy\s+into\s+[^\s]+\s+from\s+@([^\s;]+)', re.IGNORECASE)
RE_STREAM_ON_TABLE = re.compile(r'create\s+(?:or\s+replace\s+)?stream\s+[^\s]+\s+on\s+table\s+([^\s;]+)', re.IGNORECASE)
RE_USE_SCHEMA = re.compile(r'^\s*use\s+schema\s+([^\s;]+)', re.IGNORECASE | re.MULTILINE)

def discover_objects_in_sql(sql_text):
    tables = set(m.group(1).strip().upper() for m in RE_CREATE_TABLE.finditer(sql_text))
    stages = set(m.group(1).strip().upper() for m in RE_CREATE_STAGE.finditer(sql_text))
    streams = set(m.group(1).strip().upper() for m in RE_STREAM_ON_TABLE.finditer(sql_text))
    copy_froms = set(m.group(1).strip().upper() for m in RE_COPY_FROM_STAGE.finditer(sql_text))
    return {"tables": tables, "stages": stages, "streams": streams, "copy_froms": copy_froms}

def load_existing_objects(conn, database, schema):
    cur = conn.cursor()
    tables, stages = set(), set()
    try:
        cur.execute("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=%s", (schema.upper(),))
        tables = set(r[0].upper() for r in cur)
        cur.execute("SELECT STAGE_NAME FROM INFORMATION_SCHEMA.STAGES WHERE STAGE_SCHEMA=%s", (schema.upper(),))
        stages = set(r[0].upper() for r in cur)
        return {"tables": tables, "stages": stages}
    finally:
        cur.close()

# --- SQL & Python runners ---
def run_sql_files(conn, database, schema, sql_glob="sql/*.sql", dry=False):
    ensure_migration_log(conn, database, schema)
    cur = conn.cursor()
    migration_fq = qualify(database, schema, "MIGRATION_LOG")
    try:
        db_name = conn.database or database
        cur.execute(f"USE DATABASE {db_name}")
        cur.execute(f"USE SCHEMA {schema}")
        existing = load_existing_objects(conn, db_name, schema)
        existing_tables, existing_stages = set(existing["tables"]), set(existing["stages"])
        sql_files = sorted(glob.glob(sql_glob))
        logging.info("Found %d SQL files", len(sql_files))

        for path in sql_files:
            file_name = os.path.basename(path)
            file_name_upper = file_name.upper()
            cur.execute(f"SELECT 1 FROM {migration_fq} WHERE UPPER(SCRIPT_NAME)=%s", (file_name_upper,))
            if cur.fetchone():
                continue  # skip already applied
            with open(path, "r", encoding="utf-8") as fh:
                sql_text = fh.read()
            if RE_USE_SCHEMA.search(sql_text):
                raise RuntimeError(f"{file_name} contains 'USE SCHEMA'; remove it")
            if dry:
                logging.info("[DRY RUN] Would execute %s", file_name)
                continue
            statements = [s.strip() for s in sql_text.split(";") if s.strip()]
            for stmt in statements:
                cur.execute(stmt)
                try: cur.fetchall()
                except: pass
            cur.execute(f"INSERT INTO {migration_fq} (SCRIPT_NAME, APPLIED_AT) VALUES (%s, CURRENT_TIMESTAMP)", (file_name_upper,))
            conn.commit()
            obj = discover_objects_in_sql(sql_text)
            existing_tables.update(obj["tables"])
            existing_stages.update(obj["stages"])
    finally:
        cur.close()

def run_python_scripts(py_glob="python/*.py", dry=False):
    py_files = sorted(glob.glob(py_glob))
    for p in py_files:
        if dry:
            logging.info("[DRY RUN] Would run %s", p)
            continue
        rc = subprocess.call([sys.executable, p], env=os.environ.copy())
        if rc != 0:
            raise RuntimeError(f"Python script failed: {p}")

# --- Main ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--backup-before", action="store_true")
    parser.add_argument("--commit-sha", default=os.environ.get("GITHUB_SHA", "local"))
    args = parser.parse_args()

    branch = os.environ.get("GITHUB_REF_NAME") or os.environ.get("BRANCH_NAME") or os.environ.get("GITHUB_REF", "local").split("/")[-1]
    target_schema = os.environ.get("SNOWFLAKE_SCHEMA") or (
        "DEV_SCHEMA" if branch=="dev" else "TEST_SCHEMA" if branch=="test" else "PROD_SCHEMA"
    )

    account = get_env("SNOWFLAKE_ACCOUNT")
    user = get_env("SNOWFLAKE_USER")
    password = get_env("SNOWFLAKE_PASSWORD")
    warehouse = get_env("SNOWFLAKE_WAREHOUSE")
    database = get_env("SNOWFLAKE_DATABASE")
    role = get_env("SNOWFLAKE_ROLE")
    deploy_id = f"{branch}-{args.commit_sha[:8]}-{int(time.time())}"
    start_ts = datetime.utcnow()
    conn = None

    try:
        private_key_der = _load_private_key_bytes()
        if password:
            try:
                conn = connect_with_password(account, user, password, warehouse, database, target_schema, role)
            except Exception as e:
                if is_mfa_error(e) and private_key_der:
                    conn = connect_with_keypair(account, user, private_key_der, warehouse, database, target_schema, role)
                else: raise
        else:
            if private_key_der:
                conn = connect_with_keypair(account, user, private_key_der, warehouse, database, target_schema, role)
            else:
                logging.error("No authentication available"); sys.exit(2)

        ensure_deploy_log(conn, database, target_schema)
        run_sql_files(conn, database, target_schema, dry=args.dry_run)
        run_python_scripts(dry=args.dry_run)
        end_ts = datetime.utcnow()
        log_deploy(conn, database, target_schema, deploy_id, branch, args.commit_sha, start_ts, end_ts, "SUCCESS", "Deployed OK" if not args.dry_run else "Dry-run")
        logging.info("Deployment SUCCESS")
    except Exception as e:
        end_ts = datetime.utcnow()
        if conn:
            try: log_deploy(conn, database, target_schema, deploy_id, branch, args.commit_sha, start_ts, end_ts, "FAILED", str(e)[:1000])
            except: logging.exception("Failed writing failure log")
        logging.exception("Deployment failed: %s", e)
        sys.exit(3)
    finally:
        if conn: conn.close()

if __name__=="__main__":
    main()
