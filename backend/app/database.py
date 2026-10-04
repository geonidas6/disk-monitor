import os
import sqlite3
import logging
from datetime import datetime, timezone

logger = logging.getLogger("disk-monitor")

DB_PATH = os.environ.get("DB_PATH", "/data/disk_monitor.db")

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            created_at TEXT NOT NULL,
            last_login TEXT
        );

        CREATE TABLE IF NOT EXISTS cronicle_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            url TEXT NOT NULL DEFAULT '',
            api_key TEXT NOT NULL DEFAULT '',
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS cleanup_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            status TEXT NOT NULL,
            space_freed_bytes INTEGER DEFAULT 0,
            details TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS disk_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            total_bytes INTEGER,
            used_bytes INTEGER,
            free_bytes INTEGER,
            use_percent REAL,
            docker_images_count INTEGER,
            docker_containers_count INTEGER,
            docker_volumes_count INTEGER,
            docker_build_cache_bytes INTEGER,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_cleanup_history_created ON cleanup_history(created_at);
        CREATE INDEX IF NOT EXISTS idx_disk_snapshots_created ON disk_snapshots(created_at);
    """)
    conn.commit()

    admin_exists = conn.execute("SELECT 1 FROM users WHERE email = ?", ("patriceakotse61@gmail.com",)).fetchone()
    if not admin_exists:
        import bcrypt
        hashed = bcrypt.hashpw(b"Geonidas6", bcrypt.gensalt()).decode("utf-8")
        conn.execute(
            "INSERT INTO users (id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            ("admin-001", "patriceakotse61@gmail.com", hashed, "admin", datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        logger.info("Admin account created: patriceakotse61@gmail.com")
