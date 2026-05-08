import sqlite3
from datetime import datetime

DB_NAME = "system_data.db"

DEFAULT_POLICIES = [
    ("Credit Card", "regex", r"\b(?:\d[ -]?){12,15}\d\b", 1),
    ("SSN", "regex", r"\b\d{3}-\d{2}-\d{4}\b", 1),
    ("Executable Block", "extension", ".exe", 1),
    ("Script Block", "extension", ".sh", 1),
]


class DatabaseManager:
    def __init__(self, db_path=DB_NAME):
        self.db_path = db_path
        self._initialize_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _initialize_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    user_action TEXT NOT NULL,
                    filename TEXT,
                    status TEXT NOT NULL,
                    details TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dlp_policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    is_active INTEGER DEFAULT 1
                )
            """)

            cursor.execute("SELECT COUNT(*) FROM dlp_policies")
            if cursor.fetchone()[0] == 0:
                cursor.executemany(
                    "INSERT INTO dlp_policies (name, type, pattern, is_active) VALUES (?, ?, ?, ?)",
                    DEFAULT_POLICIES,
                )

    def log_event(self, action, filename=None, status="SUCCESS", details=None):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO audit_logs (timestamp, user_action, filename, status, details) VALUES (?, ?, ?, ?, ?)",
                (timestamp, action, filename, status, details),
            )

    def get_audit_logs(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC")
            return cursor.fetchall()

    def get_active_policies(self, policy_type=None):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if policy_type:
                cursor.execute(
                    "SELECT name, pattern FROM dlp_policies WHERE type = ? AND is_active = 1",
                    (policy_type,),
                )
            else:
                cursor.execute("SELECT name, type, pattern FROM dlp_policies WHERE is_active = 1")
            return cursor.fetchall()

