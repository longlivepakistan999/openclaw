import sqlite3
import threading
from contextlib import contextmanager

import config

_lock = threading.Lock()


def init_db():
    with connect() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS tasks (
            id              TEXT PRIMARY KEY,
            host            TEXT,
            note            TEXT,
            level           INTEGER,
            risk            INTEGER,
            timeout_min     INTEGER,
            status          TEXT,
            queue_pos       INTEGER,
            inject_ok       INTEGER,
            update_ok       INTEGER,
            is_dba          INTEGER,
            inject_param    TEXT,
            inject_type     TEXT,
            inject_payload  TEXT,
            dbms            TEXT,
            current_user    TEXT,
            request_text    TEXT,
            cmd_inject      TEXT,
            cmd_update      TEXT,
            cmd_dba         TEXT,
            log             TEXT,
            error           TEXT,
            created_at      TEXT,
            started_at      TEXT,
            finished_at     TEXT,
            duration_sec    INTEGER
        );

        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
        """)
        conn.execute(
            "INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)",
            ("sqlmap_path", config.DEFAULT_SQLMAP_PATH),
        )
        # Recover from a crash: any task left in 'running' state has no
        # owner process. Mark it as killed so the user can clean it up.
        conn.execute(
            "UPDATE tasks SET status='killed', "
            "error=COALESCE(error,'') || ' [orphaned by restart]' "
            "WHERE status='running'"
        )


@contextmanager
def connect():
    conn = sqlite3.connect(config.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        with _lock:
            yield conn
            conn.commit()
    finally:
        conn.close()


def get_setting(key, default=None):
    with connect() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key, value):
    with connect() as conn:
        conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def insert_task(task):
    """Insert a task. If queue_pos is missing and status='pending', assign
    next position atomically inside the same locked transaction."""
    with connect() as conn:
        if "queue_pos" not in task and task.get("status") == "pending":
            row = conn.execute(
                "SELECT COALESCE(MAX(queue_pos), -1) + 1 AS n "
                "FROM tasks WHERE status='pending'"
            ).fetchone()
            task["queue_pos"] = row["n"]
        cols = ",".join(task.keys())
        ph = ",".join("?" for _ in task)
        conn.execute(f"INSERT INTO tasks({cols}) VALUES ({ph})", tuple(task.values()))


def update_task(task_id, **fields):
    if not fields:
        return
    with connect() as conn:
        sets = ",".join(f"{k}=?" for k in fields)
        conn.execute(f"UPDATE tasks SET {sets} WHERE id=?", (*fields.values(), task_id))


def get_task(task_id):
    with connect() as conn:
        row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    return dict(row) if row else None


def list_tasks():
    """Return all tasks ordered: running first, then pending by queue_pos, then others by created_at desc."""
    with connect() as conn:
        rows = conn.execute("""
            SELECT * FROM tasks
            ORDER BY
              CASE status
                WHEN 'running' THEN 0
                WHEN 'pending' THEN 1
                ELSE 2
              END,
              queue_pos ASC,
              created_at DESC
        """).fetchall()
    return [dict(r) for r in rows]


def list_pending_ordered():
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, queue_pos FROM tasks WHERE status='pending' ORDER BY queue_pos ASC"
        ).fetchall()
    return [dict(r) for r in rows]


def delete_task(task_id):
    with connect() as conn:
        conn.execute("DELETE FROM tasks WHERE id=?", (task_id,))


def reorder_pending(ids_in_order):
    with connect() as conn:
        for i, tid in enumerate(ids_in_order):
            conn.execute(
                "UPDATE tasks SET queue_pos=? WHERE id=? AND status='pending'",
                (i, tid),
            )


def next_queue_pos():
    with connect() as conn:
        row = conn.execute(
            "SELECT COALESCE(MAX(queue_pos), -1) + 1 AS n FROM tasks WHERE status='pending'"
        ).fetchone()
    return row["n"]
