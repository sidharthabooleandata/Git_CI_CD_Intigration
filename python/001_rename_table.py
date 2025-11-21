import os
import snowflake.connector

# --- READ FROM ENV VARIABLES (from GitHub Secrets) ---
ACCOUNT   = os.getenv("SNOWFLAKE_ACCOUNT")
USER      = os.getenv("SNOWFLAKE_USER")
PASSWORD  = os.getenv("SNOWFLAKE_PASSWORD")
ROLE      = os.getenv("SNOWFLAKE_ROLE")          # you said this is stored
WAREHOUSE = os.getenv("SNOWFLAKE_WAREHOUSE")
DATABASE  = os.getenv("SNOWFLAKE_DATABASE")
SCHEMA    = os.getenv("SNOWFLAKE_SCHEMA")

OLD_TABLE = "APP_TABLE"
NEW_TABLE = "MY_APP_TABLE"

try:
    conn = snowflake.connector.connect(
        user=USER,
        password=PASSWORD,
        account=ACCOUNT,
        role=ROLE,
        warehouse=WAREHOUSE,
        database=DATABASE,
        schema=SCHEMA
    )

    cur = conn.cursor()
    sql = f"ALTER TABLE {OLD_TABLE} RENAME TO {NEW_TABLE};"
    cur.execute(sql)

    print(f"SUCCESS: Renamed {OLD_TABLE} → {NEW_TABLE}")

except Exception as e:
    print(f"ERROR: {e}")

finally:
    try:
        cur.close()
        conn.close()
    except:
        pass
