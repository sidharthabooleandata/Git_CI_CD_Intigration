#!/usr/bin/env python3
"""
deploy.py - improved & hardened migration runner
Supports automatic auth fallback:
  1) Try password auth (if SNOWFLAKE_PASSWORD present)
  2) On MFA/TOTP error -> retry with key-pair (if private key available)
  3) If no password, use key-pair
"""

import os
import sys
import glob
import logging
import subprocess
import time
import argparse
import re
from datetime import datetime

import snowflake.connector

# cryptography for private key loading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# --- Helpers ---------------------------------------------------------
def get_env(name, default=None):
    val = os.environ.get(name, default)
    if val is None:
        logging.debug("Env %s not set", name)
    return val

def _load_private_key_bytes():
    """
    Load private key bytes (PEM) from either:
      - file path in SNOWFLAKE_PRIVATE_KEY_FILE
      - base64 string in SNOWFLAKE_PRIVATE_KEY (raw PEM base64)
    Returns DER-encoded PKCS8 bytes suitable for snowflake.connector.connect(private_key=...)
    """
    path = os.environ.get("SNOWFLAKE_PRIVATE_KEY_FILE")
    base64_env = os.environ.get("SNOWFLAKE_PRIVATE_KEY")

    pem_bytes = None
    if path and os.path.exists(path):
        logging.info("Loading private key from file: %s", path)
        with open(path, "rb") as fh:
            pem_bytes = fh.read()
    elif base64_env:
        logging.info("Loading private key from SNOWFLAKE_PRIVATE_KEY env (base64)")
        import base64
        pem_bytes = base64.b64decode(base64_env)

    if not pem_bytes:
        return None

    passphrase = os.environ.get("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE") or None
    if passphrase == "":
        passphrase = None
    if passphrase is not None:
        passphrase = passphrase.encode()

    # load PEM private key object (supports encrypted and unencrypted keys)
    p_key = serialization.load_pem_private_key(pem_bytes, password=passphrase, backend=default_backend())

    # return DER PKCS8 bytes (connector expects private_key in DER form)
    pk_der = p_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pk_der

def connect_with_password(account, user, password, warehouse, database, schema, role=None):
    logging.info("Attempting Snowflake connection using password auth (user=%s)", user)
    return snowflake.connector.connect(
        user=user,
        password=password,
        account=account,
        warehouse=warehouse,
        database=database,
        schema=schema,
        role=role
    )

def connect_with_keypair(account, user, private_key_der, warehouse, database, schema, role=None):
    logging.info("Attempting Snowflake connection using key-pair auth (user=%s)", user)
    return snowflake.connector.connect(
        user=user,
        account=account,
        private_key=private_key_der,
        warehouse=warehouse,
        database=database,
        schema=schema,
        role=role
    )

def is_mfa_error(exc):
    """
    Detects whether a Snowflake DatabaseError is an MFA/TOTP required error.
    Look for known error code or message fragments.
    """
    msg = str(exc).upper() if exc is not None else ""
    # check for common strings and error code 250001
    mfa_indicators = ["MFA", "TOTP", "250001", "MUST AUTHENTICATE", "MULTI-FACTOR", "MFA_REQUIRED"]
    return any(s in msg for s in mfa_indicators)

# keep the rest of your original helpers (qualify, logs, discovery, run_sql_files, etc.)
# --- Qualified name helpers -----------------------------------------
def qualify(db, schema, name):
    return f"{db}.{schema}.{name}"

# --- Audit / Logs ---------------------------------------------------
def ensure_deploy_log(conn, database, schema):
    cur = conn.cursor()
    fq = qualify(database, schema, "PIPELINE_DEPLOYMENT_LOG")
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
    cur = conn.cursor()
    fq = qualify(database, schema, "MIGRATION_LOG")
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
    cur = conn.cursor()
    fq = qualify(database, schema, "PIPELINE_DEPLOYMENT_LOG")
    try:
        cur.execute(f"""
            INSERT INTO {fq}
            (DEPLOY_ID, BRANCH, COMMIT_SHA, START_TS, END_TS, STATUS, LOG_MESSAGE)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (deploy_id, branch, commit_sha, start_ts, end_ts, status, msg))
        conn.commit()
    finally:
        cur.close()

# --- Object discovery & simple dependency parser --------------------
RE_CREATE_TABLE = re.compile(r'create\s+(?:or\s+replace\s+)?table\s+([^\s(;]+)', re.IGNORECASE)
RE_CREATE_STAGE = re.compile(r'create\s+(?:or\s+replace\s+)?stage\s+([^\s;]+)', re.IGNORECASE)
RE_COPY_FROM_STAGE = re.compile(r'copy\s+into\s+[^\s]+\s+from\s+@([^\s;]+)', re.IGNORECASE)
RE_CREATE_PIPE = re.compile(r'create\s+(?:or\s+replace\s+)?pipe\s+([^\s]+)\s+as', re.IGNORECASE)
RE_STREAM_ON_TABLE = re.compile(r'create\s+(?:or\s+replace\s+)?stream\s+[^\s]+\s+on\s+table\s+([^\s;]+)', re.IGNORECASE)
RE_USE_SCHEMA = re.compile(r'^\s*use\s+schema\s+([^\s;]+)', re.IGNORECASE | re.MULTILINE)

def discover_objects_in_sql(sql_text):
    tables = set(m.group(1).strip().upper() for m in RE_CREATE_TABLE.finditer(sql_text))
    stages = set(m.group(1).strip().upper() for m in RE_CREATE_STAGE.finditer(sql_text))
    pipes = set(m.group(1).strip().upper() for m in RE_CREATE_PIPE.finditer(sql_text))
    streams = set(m.group(1).strip().upper() for m in RE_STREAM_ON_TABLE.finditer(sql_text))
    copy_froms = set(m.group(1).strip().upper() for m in RE_COPY_FROM_STAGE.finditer(sql_text))
    return {"tables": tables, "stages": stages, "pipes": pipes, "streams": streams, "copy_froms": copy_froms}

def load_existing_objects(conn, database, schema):
    cur = conn.cursor()
    try:
        tables = set()
        stages = set()
        cur.execute("""
            SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_SCHEMA = %s
        """, (schema.upper(),))
        for r in cur:
            tables.add(r[0].upper())
        cur.execute("""
            SELECT STAGE_NAME FROM INFORMATION_SCHEMA.STAGES
            WHERE STAGE_SCHEMA = %s
        """, (schema.upper(),))
        for r in cur:
            stages.add(r[0].upper())
        return {"tables": tables, "stages": stages}
    finally:
        cur.close()

# --- Runner functions ------------------------------------------------
def run_sql_files(conn, database, schema, sql_glob="sql/*.sql", dry=False):
    ensure_migration_log(conn, database, schema)
    cur = conn.cursor()
    migration_fq = qualify(database, schema, "MIGRATION_LOG")
    try:
        db_name = conn.database
        if not db_name:
            db_name = database
        logging.info("Using database=%s schema=%s", db_name, schema)
        cur.execute(f"USE DATABASE {db_name}")
        cur.execute(f"USE SCHEMA {schema}")

        existing = load_existing_objects(conn, db_name, schema)
        existing_tables = set(x.upper() for x in existing["tables"])
        existing_stages = set(x.upper() for x in existing["stages"])

        sql_files = sorted(glob.glob(sql_glob))
        logging.info("Found %d SQL files", len(sql_files))

        declared_tables = set()
        declared_stages = set()
        declared_copy_froms = set()
        for path in sql_files:
            with open(path, "r", encoding="utf-8") as fh:
                sql_text = fh.read()
            if RE_USE_SCHEMA.search(sql_text):
                raise RuntimeError(f"Migration file {os.path.basename(path)} contains a 'USE SCHEMA' statement. Remove it; deploy script controls schema.")
            obj = discover_objects_in_sql(sql_text)
            declared_tables.update(obj["tables"])
            declared_stages.update(obj["stages"])
            declared_copy_froms.update(obj["copy_froms"])

        logging.info("Declared tables in files: %s", sorted(declared_tables))
        logging.info("Declared stages in files: %s", sorted(declared_stages))
        logging.info("Declared copy-from targets referenced: %s", sorted(declared_copy_froms))

        for path in sql_files:
            file_name = os.path.basename(path)
            file_name_upper = file_name.upper()
            cur.execute(f"SELECT 1 FROM {migration_fq} WHERE UPPER(SCRIPT_NAME) = %s", (file_name_upper,))
            if cur.fetchone():
                logging.info("Skipping already applied migration: %s", file_name)
                continue

            logging.info("Pre-checking SQL file: %s", file_name)
            with open(path, "r", encoding="utf-8") as fh:
                sql_text = fh.read()

            for m in RE_COPY_FROM_STAGE.finditer(sql_text):
                ref = m.group(1).strip()
                ref_up = ref.upper()
                if ref_up.startswith('%'):
                    tbl = ref_up.lstrip('%')
                    tbl_exists = (tbl in existing_tables) or (tbl in declared_tables)
                    if not tbl_exists:
                        raise RuntimeError(f"Preflight check failed: COPY/PIPE references table-stage @{ref} but table '{tbl}' not found in schema or migrations.")
                else:
                    stage_name = ref_up.split('.')[-1]
                    if (stage_name not in existing_stages) and (stage_name not in declared_stages):
                        raise RuntimeError(f"Preflight check failed: COPY/PIPE references stage @{ref} but stage not found in schema or migrations.")

            for m in RE_STREAM_ON_TABLE.finditer(sql_text):
                tbl = m.group(1).strip().upper()
                tbl_simple = tbl.split('.')[-1]
                if (tbl_simple not in existing_tables) and (tbl_simple not in declared_tables):
                    raise RuntimeError(f"Preflight check failed: STREAM references table '{tbl}' but table not found in schema or migrations.")

            if dry:
                logging.info("[DRY RUN] Would execute SQL statements from %s", file_name)
                continue

            logging.info("Running SQL file: %s", path)
            statements = [s.strip() for s in sql_text.split(";") if s.strip()]
            for stmt in statements:
                try:
                    logging.info("Executing statement: %.120s", stmt.replace("\n"," ")[:120])
                    cur.execute(stmt)
                    try:
                        cur.fetchall()
                    except Exception:
                        pass
                except Exception as e:
                    logging.exception("SQL failed in %s: %s", path, e)
                    raise

            cur.execute(f"INSERT INTO {migration_fq} (SCRIPT_NAME, APPLIED_AT) VALUES (%s, CURRENT_TIMESTAMP)", (file_name_upper,))
            conn.commit()

            obj = discover_objects_in_sql(sql_text)
            existing_tables.update(obj["tables"])
            existing_stages.update(obj["stages"])

    finally:
        cur.close()

def run_python_scripts(py_glob="python/*.py", dry=False):
    py_files = sorted(glob.glob(py_glob))
    logging.info("Found %d Python files", len(py_files))
    for p in py_files:
        logging.info("Running Python script: %s", p)
        if dry:
            logging.info("[DRY RUN] Would run Python script: %s", p)
            continue
        rc = subprocess.call([sys.executable, p], env=os.environ.copy())
        if rc != 0:
            raise RuntimeError(f"Python script failed: {p}")

def clone_schema(conn, source_db, source_schema, target_db, target_schema):
    cur = conn.cursor()
    try:
        logging.info("Cloning %s.%s to %s.%s", source_db, source_schema, target_db, target_schema)
        cur.execute(f"CREATE DATABASE IF NOT EXISTS {target_db}")
        cur.execute(f"CREATE SCHEMA IF NOT EXISTS {target_db}.{target_schema}")
        cur.execute(f"CREATE SCHEMA {target_db}.{target_schema} CLONE {source_db}.{source_schema}")
        conn.commit()
    finally:
        cur.close()

# --- Main ------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="validate SQL and dependencies but do not execute")
    parser.add_argument("--backup-before", action="store_true", help="clone target schema before deploy (prod safety)")
    parser.add_argument("--commit-sha", default=os.environ.get("GITHUB_SHA", "local"))
    args = parser.parse_args()

    branch = os.environ.get("GITHUB_REF_NAME") or os.environ.get("BRANCH_NAME") or os.environ.get("GITHUB_REF", "local").split('/')[-1]
    target_schema = os.environ.get("SNOWFLAKE_SCHEMA") or (
        "DEV_SCHEMA" if branch == "dev" else ("TEST_SCHEMA" if branch == "test" else "PROD_SCHEMA")
    )

    account = get_env("SNOWFLAKE_ACCOUNT")
    user = get_env("SNOWFLAKE_USER")
    password = get_env("SNOWFLAKE_PASSWORD")
    warehouse = get_env("SNOWFLAKE_WAREHOUSE")
    database = get_env("SNOWFLAKE_DATABASE")
    role = get_env("SNOWFLAKE_ROLE")

    if not (account and user and warehouse and database):
        logging.error("Missing Snowflake connection envs. Aborting. Required: SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER, SNOWFLAKE_WAREHOUSE, SNOWFLAKE_DATABASE")
        sys.exit(2)

    deploy_id = f"{branch}-{args.commit_sha[:8]}-{int(time.time())}"
    start_ts = datetime.utcnow()
    conn = None

    try:
        # First attempt: password auth if password provided
        last_exc = None
        private_key_der = _load_private_key_bytes()

        if password:
            try:
                conn = connect_with_password(account, user, password, warehouse, database, target_schema, role)
                logging.info("Connected to Snowflake using password auth")
            except Exception as e:
                last_exc = e
                logging.warning("Password auth failed: %s", e)
                # If the failure looks like MFA required and we have a key, try keypair
                if is_mfa_error(e) and private_key_der:
                    logging.info("Detected MFA requirement in error. Trying key-pair fallback...")
                    try:
                        conn = connect_with_keypair(account, user, private_key_der, warehouse, database, target_schema, role)
                        logging.info("Connected to Snowflake using key-pair auth (fallback)")
                    except Exception as e2:
                        logging.exception("Key-pair fallback also failed: %s", e2)
                        raise
                else:
                    # If not MFA or no key available, re-raise original
                    raise

        else:
            # No password provided -> try keypair if available
            if private_key_der:
                conn = connect_with_keypair(account, user, private_key_der, warehouse, database, target_schema, role)
                logging.info("Connected to Snowflake using key-pair auth")
            else:
                logging.error("No authentication method available: provide SNOWFLAKE_PASSWORD or SNOWFLAKE_PRIVATE_KEY")
                sys.exit(2)

        # Ensure deploy log exists
        ensure_deploy_log(conn, database, target_schema)

        # backup if requested and deploying to prod/main
        if args.backup_before and branch in ("main", "prod"):
            backup_db = f"{database}_backup_{int(time.time())}"
            clone_schema(conn, database, target_schema, backup_db, target_schema)

        # Deploy SQL first (idempotent) - supports dry-run preflight
        run_sql_files(conn, database, target_schema, dry=args.dry_run)

        # Deploy Python scripts (optional)
        run_python_scripts(dry=args.dry_run)

        end_ts = datetime.utcnow()
        log_deploy(conn, database, target_schema, deploy_id, branch, args.commit_sha, start_ts, end_ts, "SUCCESS", "Deployed OK (dry-run)" if args.dry_run else "Deployed OK")
        logging.info("Deployment SUCCESS")

    except Exception as e:
        end_ts = datetime.utcnow()
        try:
            if conn:
                log_deploy(conn, database, target_schema, deploy_id, branch, args.commit_sha, start_ts, end_ts, "FAILED", str(e)[:1000])
        except Exception:
            logging.exception("Failed to write failure into deploy log")
        logging.exception("Deployment failed: %s", e)
        sys.exit(3)
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    main()
