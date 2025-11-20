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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


# -----------------------------------
# Helper to load env
# -----------------------------------
def get_env(name, default=None):
    return os.environ.get(name, default)


# -----------------------------------
# Load private key (PEM → DER)
# -----------------------------------
def _load_private_key_bytes():
    path = os.environ.get("SNOWFLAKE_PRIVATE_KEY_FILE")
    b64 = os.environ.get("SNOWFLAKE_PRIVATE_KEY")

    pem = None
    if path and os.path.exists(path):
        with open(path, "rb") as f:
            pem = f.read()
    elif b64:
        import base64
        pem = base64.b64decode(b64)

    if not pem:
        return None

    passphrase = os.environ.get("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE")
    passphrase = passphrase.encode() if passphrase else None

    key = serialization.load_pem_private_key(pem, password=passphrase, backend=default_backend())

    return key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


# -----------------------------------
# Connection helpers
# -----------------------------------
def connect_with_password(account, user, password, warehouse, database, schema, role=None):
    logging.info("Trying password authentication…")
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
    logging.info("Trying key-pair authentication…")
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
    msg = str(exc).upper()
    return any(s in msg for s in ["MFA", "TOTP", "250001", "MULTI-FACTOR", "AUTHENTICATE"])


# -------------------------------------------------------
# (all your original logic stays exactly unchanged below)
# -------------------------------------------------------

# ---- helpers & regex ----
def qualify(db, schema, name):
    return f"{db}.{schema}.{name}"

# ---- logs ----
def ensure_deploy_log(conn, database, schema):
    cur = conn.cursor()
    fq = qualify(database, schema, "PIPELINE_DEPLOYMENT_LOG")
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
    cur = conn.cursor()
    fq = qualify(database, schema, "MIGRATION_LOG")
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


# ------------ regex discovery -----------------
RE_CREATE_TABLE = re.compile(r'create\s+(?:or\s+replace\s+)?table\s+([^\s(;]+)', re.IGNORECASE)
RE_CREATE_STAGE = re.compile(r'create\s+(?:or\s+replace\s+)?stage\s+([^\s;]+)', re.IGNORECASE)
RE_COPY_FROM_STAGE = re.compile(r'copy\s+into\s+[^\s]+\s+from\s+@([^\s;]+)', re.IGNORECASE)
RE_CREATE_PIPE = re.compile(r'create\s+(?:or\s+replace\s+)?pipe\s+([^\s]+)\s+as', re.IGNORECASE)
RE_STREAM_ON_TABLE = re.compile(r'create\s+(?:or\s+replace\s+)?stream\s+[^\s]+\s+on\s+table\s+([^\s;]+)', re.IGNORECASE)
RE_USE_SCHEMA = re.compile(r'^\s*use\s+schema\s+([^\s;]+)', re.IGNORECASE | re.MULTILINE)


# -------- object discovery ----------
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
        cur.execute("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = %s", (schema.upper(),))
        tables = {r[0].upper() for r in cur}
        cur.execute("SELECT STAGE_NAME FROM INFORMATION_SCHEMA.STAGES WHERE STAGE_SCHEMA = %s", (schema.upper(),))
        stages = {r[0].upper() for r in cur}
        return {"tables": tables, "stages": stages}
    finally:
        cur.close()


# ----------- MIGRATION RUNNER (unchanged) -----------
def run_sql_files(conn, database, schema, sql_glob="sql/*.sql", dry=False):
    ensure_migration_log(conn, database, schema)

    cur = conn.cursor()
    migration_fq = qualify(database, schema, "MIGRATION_LOG")

    try:
        cur.execute(f"USE DATABASE {database}")
        cur.execute(f"USE SCHEMA {schema}")

        existing = load_existing_objects(conn, database, schema)
        existing_tables = {x.upper() for x in existing["tables"]}
        existing_stages = {x.upper() for x in existing["stages"]}

        sql_files = sorted(glob.glob(sql_glob))
        logging.info("Found %d SQL files", len(sql_files))

        declared_tables = set()
        declared_stages = set()
        declared_copy_froms = set()

        for path in sql_files:
            with open(path) as f:
                txt = f.read()
            if RE_USE_SCHEMA.search(txt):
                raise RuntimeError(f"Remove 'USE SCHEMA' from: {path}")
            obj = discover_objects_in_sql(txt)
            declared_tables.update(obj["tables"])
            declared_stages.update(obj["stages"])
            declared_copy_froms.update(obj["copy_froms"])

        for path in sql_files:
            f_name = os.path.basename(path).upper()

            cur.execute(f"SELECT 1 FROM {migration_fq} WHERE SCRIPT_NAME=%s", (f_name,))
            if cur.fetchone():
                logging.info("Skipping already applied: %s", f_name)
                continue

            with open(path) as f:
                sql_text = f.read()

            # Preflight checks
            for m in RE_COPY_FROM_STAGE.finditer(sql_text):
                ref = m.group(1).upper()
                if ref.startswith('%'):
                    tbl = ref.lstrip('%')
                    if tbl not in existing_tables and tbl not in declared_tables:
                        raise RuntimeError(f"Missing table for stage @{ref}")
                else:
                    stg = ref.split('.')[-1]
                    if stg not in existing_stages and stg not in declared_stages:
                        raise RuntimeError(f"Missing stage @{ref}")

            if dry:
                logging.info("[DRY] Would run SQL from %s", path)
                continue

            # Execute SQL
            for stmt in filter(None, (s.strip() for s in sql_text.split(";"))):
                try:
                    logging.info("EXEC: %.100s", stmt)
                    cur.execute(stmt)
                    try: cur.fetchall()
                    except: pass
                except Exception as e:
                    logging.error("Failed in %s: %s", f_name, e)
                    raise

            cur.execute(f"INSERT INTO {migration_fq} VALUES (%s, CURRENT_TIMESTAMP)", (f_name,))
            conn.commit()

    finally:
        cur.close()


def run_python_scripts(py_glob="python/*.py", dry=False):
    py_files = sorted(glob.glob(py_glob))
    for p in py_files:
        if dry:
            logging.info("[DRY] Skip py script: %s", p)
            continue
        rc = subprocess.call([sys.executable, p])
        if rc != 0:
            raise RuntimeError(f"Python script failed: {p}")


def clone_schema(conn, source_db, source_schema, target_db, target_schema):
    cur = conn.cursor()
    try:
        cur.execute(f"CREATE DATABASE IF NOT EXISTS {target_db}")
        cur.execute(f"CREATE SCHEMA IF NOT EXISTS {target_db}.{target_schema}")
        cur.execute(f"CREATE SCHEMA {target_db}.{target_schema} CLONE {source_db}.{source_schema}")
        conn.commit()
    finally:
        cur.close()


# -----------------------------------------------------
# Main deploy logic
# -----------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--backup-before", action="store_true")
    parser.add_argument("--commit-sha", default=os.environ.get("GITHUB_SHA"))
    args = parser.parse_args()

    branch = os.environ.get("GITHUB_REF_NAME", "local")
    target_schema = os.environ.get("SNOWFLAKE_SCHEMA")

    account = get_env("SNOWFLAKE_ACCOUNT")
    user = get_env("SNOWFLAKE_USER")
    password = get_env("SNOWFLAKE_PASSWORD")
    warehouse = get_env("SNOWFLAKE_WAREHOUSE")
    database = get_env("SNOWFLAKE_DATABASE")
    role = get_env("SNOWFLAKE_ROLE")

    private_key_der = _load_private_key_bytes()

    deploy_id = f"{branch}-{args.commit_sha[:8]}-{int(time.time())}"
    start_ts = datetime.utcnow()
    conn = None

    try:
        # 1) Try password first
        if password:
            try:
                conn = connect_with_password(account, user, password, warehouse, database, target_schema, role)
                logging.info("Connected using password")
            except Exception as e:
                if is_mfa_error(e) and private_key_der:
                    logging.info("Password auth blocked by MFA → trying keypair")
                    conn = connect_with_keypair(account, user, private_key_der, warehouse, database, target_schema, role)
                else:
                    raise

        # 2) Otherwise try key-pair only
        else:
            if not private_key_der:
                raise RuntimeError("No password and no private key available")
            conn = connect_with_keypair(account, user, private_key_der, warehouse, database, target_schema, role)

        ensure_deploy_log(conn, database, target_schema)

        if args.backup_before and branch in ("main", "prod"):
            clone_schema(conn, database, target_schema, f"{database}_backup", target_schema)

        run_sql_files(conn, database, target_schema, dry=args.dry_run)
        run_python_scripts(dry=args.dry_run)

        end_ts = datetime.utcnow()
        log_deploy(conn, database, target_schema, deploy_id, branch, args.commit_sha, start_ts, end_ts,
                   "SUCCESS", "Dry OK" if args.dry_run else "OK")
        logging.info("Deployment SUCCESS")

    except Exception as e:
        end_ts = datetime.utcnow()
        if conn:
            log_deploy(conn, database, target_schema, deploy_id, branch, args.commit_sha, start_ts, end_ts,
                       "FAILED", str(e)[:500])
        logging.error("Deployment failed: %s", e)
        sys.exit(3)
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    main()
