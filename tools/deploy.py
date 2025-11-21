#!/usr/bin/env python3
"""
deploy.py - branch-aware, MFA/keypair ready Snowflake CD runner
"""

import os, sys, glob, logging, subprocess, time, argparse, re
from datetime import datetime
import snowflake.connector
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# ------------------------
# ENV
# ------------------------
def get_env(name, default=None):
    return os.environ.get(name, default)

# ------------------------
# Private key loader
# ------------------------
def _load_private_key_bytes():
    path = os.environ.get("SNOWFLAKE_PRIVATE_KEY_FILE")
    base64_env = os.environ.get("SNOWFLAKE_PRIVATE_KEY")

    pem_bytes = None
    if path and os.path.exists(path):
        with open(path, "rb") as fh:
            pem_bytes = fh.read()
    elif base64_env:
        pem_bytes = base64.b64decode(base64_env)

    if not pem_bytes:
        return None

    passphrase = os.environ.get("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE") or None
    if passphrase == "":
        passphrase = None
    if passphrase:
        passphrase = passphrase.encode()

    p_key = serialization.load_pem_private_key(
        pem_bytes, password=passphrase, backend=default_backend()
    )
    return p_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

# ------------------------
# Connections
# ------------------------
def connect_with_password(account, user, password, warehouse, database, schema, role=None):
    logging.info(f"Connecting with password to DB={database} SCHEMA={schema} ROLE={role}")
    return snowflake.connector.connect(
        user=user, password=password, account=account,
        warehouse=warehouse, database=database, schema=schema, role=role
    )

def connect_with_keypair(account, user, private_key_der, warehouse, database, schema, role=None):
    logging.info(f"Connecting with keypair to DB={database} SCHEMA={schema} ROLE={role}")
    return snowflake.connector.connect(
        user=user, private_key=private_key_der, account=account,
        warehouse=warehouse, database=database, schema=schema, role=role
    )

def is_mfa_error(exc):
    msg = str(exc).upper()
    return any(x in msg for x in ["MFA", "TOTP", "250001", "MULTI-FACTOR"])

def qualify(db, schema, name):
    return f"{db}.{schema}.{name}"

# ------------------------
# Deploy log tables
# ------------------------
def ensure_deploy_log(conn, database, schema):
    fq = qualify(database, schema, "PIPELINE_DEPLOYMENT_LOG")
    logging.info(f"Ensuring table {fq}")
    cur = conn.cursor()
    try:
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
    logging.info(f"Ensuring table {fq}")
    cur = conn.cursor()
    try:
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

# ------------------------
# Run SQL
# ------------------------
RE_USE_SCHEMA = re.compile(r'^\s*use\s+schema', re.IGNORECASE|re.MULTILINE)

def run_sql_files(conn, database, schema, sql_glob="sql/*.sql", dry=False):
    ensure_migration_log(conn, database, schema)
    cur = conn.cursor()
    migration_fq = qualify(database, schema, "MIGRATION_LOG")

    try:
        logging.info(f"Switching to DATABASE {database}")
        cur.execute(f"USE DATABASE {database}")
        logging.info(f"Switching to SCHEMA {schema}")
        cur.execute(f"USE SCHEMA {schema}")

        sql_files = sorted(glob.glob(sql_glob))
        logging.info(f"Found {len(sql_files)} SQL files")

        for path in sql_files:
            file_name = os.path.basename(path)
            file_name_upper = file_name.upper()

            cur.execute(f"SELECT 1 FROM {migration_fq} WHERE UPPER(SCRIPT_NAME)=%s", (file_name_upper,))
            if cur.fetchone():
                logging.info(f"SKIP {file_name}: already applied")
                continue

            with open(path, "r", encoding="utf-8") as fh:
                sql_text = fh.read()

            if RE_USE_SCHEMA.search(sql_text):
                raise RuntimeError(f"{file_name} contains 'USE SCHEMA' — remove it.")

            if dry:
                logging.info(f"[DRY RUN] Would APPLY {file_name}")
                continue

            logging.info(f"APPLYING {file_name}")
            statements = [s.strip() for s in sql_text.split(";") if s.strip()]
            for stmt in statements:
                cur.execute(stmt)
                try: cur.fetchall()
                except: pass

            cur.execute(
                f"INSERT INTO {migration_fq} (SCRIPT_NAME, APPLIED_AT) VALUES (%s, CURRENT_TIMESTAMP)",
                (file_name_upper,)
            )
            conn.commit()

    finally:
        cur.close()

# ------------------------
# Python scripts
# ------------------------
def run_python_scripts(py_glob="python/*.py", dry=False):
    py_files = sorted(glob.glob(py_glob))
    for p in py_files:
        if dry:
            logging.info(f"[DRY RUN] Would run {p}")
            continue
        logging.info(f"RUNNING python script {p}")
        rc = subprocess.call([sys.executable, p], env=os.environ.copy())
        if rc != 0:
            raise RuntimeError(f"Python script failed: {p}")

# ------------------------
# MAIN
# ------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--commit-sha", default=os.environ.get("GITHUB_SHA", "local"))
    args = parser.parse_args()

    branch = os.environ.get("GITHUB_REF_NAME", "local")
    target_schema = os.environ.get("SNOWFLAKE_SCHEMA")

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
                else:
                    raise
        else:
            conn = connect_with_keypair(account, user, private_key_der, warehouse, database, target_schema, role)

        ensure_deploy_log(conn, database, target_schema)
        run_sql_files(conn, database, target_schema, dry=args.dry_run)
        run_python_scripts(dry=args.dry_run)

        end_ts = datetime.utcnow()
        log_deploy(conn, database, target_schema, deploy_id, branch, args.commit_sha,
                   start_ts, end_ts, "SUCCESS",
                   "Deployed OK" if not args.dry_run else "Dry-run")

        logging.info("DEPLOYMENT SUCCESS")

    except Exception as e:
        end_ts = datetime.utcnow()
        if conn:
            try:
                log_deploy(conn, database, target_schema, deploy_id, branch, args.commit_sha,
                           start_ts, end_ts, "FAILED", str(e))
            except:
                logging.exception("Failed writing failure log")
        logging.exception("DEPLOY FAILED")
        sys.exit(3)

    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    main()
