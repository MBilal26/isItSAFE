import sqlite3
import os
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_name="wifi_security.db"):
        self.db_path = os.path.join(os.path.dirname(__file__), db_name)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Threats table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ssid TEXT,
                    bssid TEXT,
                    timestamp DATETIME
                )
            ''')
            # Blocked SSIDs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked (
                    ssid TEXT PRIMARY KEY,
                    timestamp DATETIME
                )
            ''')
            conn.commit()

    def log_threat(self, ssid, bssid):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO threats (ssid, bssid, timestamp) VALUES (?, ?, ?)",
                (ssid, bssid, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
            conn.commit()

    def get_all_threats(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ssid, bssid, timestamp FROM threats ORDER BY timestamp DESC")
            return [f"[{row[2]}] THREAT: {row[0]} ({row[1]})" for row in cursor.fetchall()]

    def add_block(self, ssid):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT OR IGNORE INTO blocked (ssid, timestamp) VALUES (?, ?)",
                    (ssid, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                )
                conn.commit()
            return True
        except:
            return False

    def remove_block(self, ssid):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM blocked WHERE ssid = ?", (ssid,))
                conn.commit()
            return True
        except:
            return False

    def get_all_blocks(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ssid FROM blocked")
            return [row[0] for row in cursor.fetchall()]
