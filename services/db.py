"""Thin database layer. SQLite for the offline demo, Aurora MySQL in AWS mode.

All queries use '?' placeholders; they are translated to '%s' for MySQL.
Dates are stored as ISO-8601 strings so the same schema works on both engines.
"""
import sqlite3

import config

PK = {"sqlite": "INTEGER PRIMARY KEY AUTOINCREMENT", "mysql": "INT AUTO_INCREMENT PRIMARY KEY"}

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS users (
        id {PK}, username VARCHAR(64) NOT NULL UNIQUE, full_name VARCHAR(128) NOT NULL,
        role VARCHAR(32) NOT NULL, pw_hash VARCHAR(255) NOT NULL,
        mfa_enabled INT NOT NULL DEFAULT 0, last_login VARCHAR(32))""",
    """CREATE TABLE IF NOT EXISTS patients (
        id {PK}, mrn VARCHAR(32) NOT NULL UNIQUE, phi_enc TEXT NOT NULL,
        age INT NOT NULL, gender VARCHAR(16) NOT NULL, blood_group VARCHAR(8),
        city VARCHAR(64), created_at VARCHAR(32) NOT NULL, created_by VARCHAR(64))""",
    """CREATE TABLE IF NOT EXISTS admissions (
        id {PK}, patient_id INT NOT NULL, department VARCHAR(64) NOT NULL,
        diagnosis VARCHAR(128) NOT NULL, admit_date VARCHAR(16) NOT NULL,
        discharge_date VARCHAR(16), outcome VARCHAR(32) NOT NULL, readmission INT NOT NULL DEFAULT 0)""",
    """CREATE TABLE IF NOT EXISTS documents (
        id {PK}, mrn VARCHAR(32) NOT NULL, filename VARCHAR(255) NOT NULL,
        s3_key VARCHAR(255) NOT NULL, size_bytes INT NOT NULL, content_type VARCHAR(128),
        key_id VARCHAR(64) NOT NULL, sha256 VARCHAR(64) NOT NULL,
        uploaded_by VARCHAR(64) NOT NULL, uploaded_at VARCHAR(32) NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS audit_log (
        id {PK}, event_time VARCHAR(32) NOT NULL, event_name VARCHAR(64) NOT NULL,
        event_source VARCHAR(64) NOT NULL, username VARCHAR(64) NOT NULL,
        role VARCHAR(32) NOT NULL, source_ip VARCHAR(64), resource VARCHAR(255),
        outcome VARCHAR(16) NOT NULL, detail TEXT)""",
    """CREATE TABLE IF NOT EXISTS config_state (
        k VARCHAR(64) PRIMARY KEY, v VARCHAR(255) NOT NULL)""",
]


class Database:
    def __init__(self):
        self.engine = config.DB_ENGINE
        self._mysql_creds = None
        if self.engine == "mysql":
            import pymysql  # noqa: F401  (fail early with a clear error)
            self._mysql_creds = self._load_mysql_creds()

    def _load_mysql_creds(self):
        user, password = config.DB_USER, config.DB_PASSWORD
        if config.DB_SECRET_ARN:
            import json
            import boto3
            sm = boto3.client("secretsmanager", region_name=config.AWS_REGION)
            secret = json.loads(sm.get_secret_value(SecretId=config.DB_SECRET_ARN)["SecretString"])
            user, password = secret["username"], secret["password"]
        return user, password

    def _connect(self):
        if self.engine == "sqlite":
            conn = sqlite3.connect(config.SQLITE_PATH, timeout=15)
            conn.row_factory = sqlite3.Row
            return conn
        import pymysql
        user, password = self._mysql_creds
        return pymysql.connect(
            host=config.DB_HOST, port=config.DB_PORT, user=user, password=password,
            database=config.DB_NAME, cursorclass=pymysql.cursors.DictCursor,
            autocommit=True, connect_timeout=10,
        )

    def _sql(self, sql):
        return sql.replace("?", "%s") if self.engine == "mysql" else sql

    def execute(self, sql, params=()):
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(self._sql(sql), tuple(params))
            if self.engine == "sqlite":
                conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def executemany(self, sql, rows):
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.executemany(self._sql(sql), [tuple(r) for r in rows])
            if self.engine == "sqlite":
                conn.commit()
        finally:
            conn.close()

    def query(self, sql, params=()):
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(self._sql(sql), tuple(params))
            return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def one(self, sql, params=()):
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def init_schema(self):
        for stmt in SCHEMA:
            self.execute(stmt.format(PK=PK[self.engine]))

    def get_state(self, key, default="0"):
        row = self.one("SELECT v FROM config_state WHERE k = ?", (key,))
        return row["v"] if row else default

    def set_state(self, key, value):
        if self.one("SELECT k FROM config_state WHERE k = ?", (key,)):
            self.execute("UPDATE config_state SET v = ? WHERE k = ?", (str(value), key))
        else:
            self.execute("INSERT INTO config_state (k, v) VALUES (?, ?)", (key, str(value)))
