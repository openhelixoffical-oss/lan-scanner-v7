import sqlite3
import os
from datetime import datetime
from typing import List
from .scanner import Device


DB_PATH = os.path.join(os.path.expanduser("~"), ".lan_scanner.db")


class DeviceHistory:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    mac TEXT PRIMARY KEY,
                    ip TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    label TEXT DEFAULT '',
                    device_type TEXT DEFAULT 'unknown',
                    first_seen TEXT,
                    last_seen TEXT,
                    seen_count INTEGER DEFAULT 1
                )
            """)
            for col, default in [("label","''"), ("device_type","'unknown'")]:
                try:
                    conn.execute(f"ALTER TABLE devices ADD COLUMN {col} TEXT DEFAULT {default}")
                except Exception:
                    pass

    def _conn(self):
        return sqlite3.connect(self.db_path)

    def update(self, devices: List[Device]) -> List[Device]:
        new_devices = []
        with self._conn() as conn:
            for device in devices:
                if device.mac == "N/A":
                    continue
                existing = conn.execute(
                    "SELECT mac, first_seen, seen_count, label FROM devices WHERE mac = ?",
                    (device.mac,)
                ).fetchone()

                if existing:
                    device.first_seen = datetime.fromisoformat(existing[1])
                    device.seen_count = existing[2] + 1
                    device.label = existing[3] or ""
                    conn.execute("""
                        UPDATE devices SET ip=?, hostname=?, vendor=?, device_type=?,
                        last_seen=?, seen_count=seen_count+1 WHERE mac=?
                    """, (device.ip, device.hostname, device.vendor, device.device_type,
                          device.last_seen.isoformat(), device.mac))
                else:
                    conn.execute("""
                        INSERT INTO devices
                        (mac, ip, hostname, vendor, label, device_type, first_seen, last_seen, seen_count)
                        VALUES (?, ?, ?, ?, '', ?, ?, ?, 1)
                    """, (device.mac, device.ip, device.hostname, device.vendor,
                          device.device_type, device.first_seen.isoformat(),
                          device.last_seen.isoformat()))
                    new_devices.append(device)
        return new_devices

    def set_label(self, mac: str, label: str):
        with self._conn() as conn:
            conn.execute("UPDATE devices SET label=? WHERE mac=?", (label, mac))

    def get_all(self) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT mac, ip, hostname, vendor, label, device_type, first_seen, last_seen, seen_count
                FROM devices ORDER BY last_seen DESC
            """).fetchall()
        return [
            {"mac": r[0], "ip": r[1], "hostname": r[2], "vendor": r[3],
             "label": r[4], "device_type": r[5],
             "first_seen": r[6], "last_seen": r[7], "seen_count": r[8]}
            for r in rows
        ]

    def clear(self):
        with self._conn() as conn:
            conn.execute("DELETE FROM devices")
