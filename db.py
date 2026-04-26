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
            duration_sec    INTEGER,
            server_id       TEXT DEFAULT 'local'
        );

        CREATE TABLE IF NOT EXISTS servers (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            is_local    INTEGER NOT NULL DEFAULT 0,
            host        TEXT,
            port        INTEGER DEFAULT 22,
            user        TEXT,
            key_path    TEXT,
            sqlmap_path TEXT NOT NULL DEFAULT '/usr/bin/sqlmap',
            created_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
        """)

        # Migration: add server_id to tasks if the column doesn't exist yet
        try:
            conn.execute("ALTER TABLE tasks ADD COLUMN server_id TEXT DEFAULT 'local'")
        except Exception:
            pass

        # Ensure the built-in local server always exists
        conn.execute(
            "INSERT OR IGNORE INTO servers(id, name, is_local, sqlmap_path, created_at) "
            "VALUES ('local', '本地执行', 1, ?, datetime('now'))",
            (config.DEFAULT_SQLMAP_PATH,),
        )

        # Migrate old sqlmap_path setting → local server's sqlmap_path
        conn.execute(
            "UPDATE servers SET sqlmap_path = COALESCE("
            "  (SELECT value FROM settings WHERE key='sqlmap_path'), sqlmap_path"
            ") WHERE id = 'local'"
        )

        # Migrate old single remote_host setting → a server row (one-time)
        conn.execute("""
            INSERT OR IGNORE INTO servers
                (id, name, is_local, host, port, user, key_path, sqlmap_path, created_at)
            SELECT
                'migrated-remote',
                COALESCE((SELECT value FROM settings WHERE key='remote_host'), ''),
                0,
                (SELECT value FROM settings WHERE key='remote_host'),
                CAST(COALESCE(
                    NULLIF((SELECT value FROM settings WHERE key='remote_port'), ''), '22'
                ) AS INTEGER),
                COALESCE((SELECT value FROM settings WHERE key='remote_user'), 'root'),
                COALESCE((SELECT value FROM settings WHERE key='remote_key_path'), ''),
                COALESCE(
                    NULLIF((SELECT value FROM settings WHERE key='remote_sqlmap_path'), ''),
                    '/usr/bin/sqlmap'
                ),
                datetime('now')
            WHERE EXISTS (
                SELECT 1 FROM settings WHERE key='remote_host' AND value != ''
            )
        """)

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


# ---------------------------------------------------------------------------
# Server CRUD
# ---------------------------------------------------------------------------

def list_servers():
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM servers ORDER BY is_local DESC, created_at ASC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_server(server_id):
    with connect() as conn:
        row = conn.execute("SELECT * FROM servers WHERE id=?", (server_id,)).fetchone()
    return dict(row) if row else None


def insert_server(server):
    with connect() as conn:
        cols = ",".join(server.keys())
        ph = ",".join("?" for _ in server)
        conn.execute(f"INSERT INTO servers({cols}) VALUES ({ph})", tuple(server.values()))


def update_server(server_id, **fields):
    if not fields:
        return
    with connect() as conn:
        sets = ",".join(f"{k}=?" for k in fields)
        conn.execute(f"UPDATE servers SET {sets} WHERE id=?", (*fields.values(), server_id))


def delete_server(server_id):
    with connect() as conn:
        conn.execute("DELETE FROM servers WHERE id=? AND is_local=0", (server_id,))


# ---------------------------------------------------------------------------
# Task CRUD
# ---------------------------------------------------------------------------

def insert_task(task):
    """Insert a task. Assigns queue_pos atomically for pending tasks."""
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


_LIST_COLS = (
    "t.id, t.host, t.note, t.level, t.risk, t.timeout_min, t.status, t.queue_pos, "
    "t.inject_ok, t.update_ok, t.is_dba, t.inject_param, t.inject_type, t.inject_payload, "
    "t.dbms, t.error, t.created_at, t.started_at, t.finished_at, t.duration_sec, "
    "t.server_id, COALESCE(s.name, t.server_id, '本地') AS server_name"
)


def list_tasks():
    """Return lightweight task summaries (no log/request_text/cmd_* columns)."""
    with connect() as conn:
        rows = conn.execute(f"""
            SELECT {_LIST_COLS}
            FROM tasks t
            LEFT JOIN servers s ON t.server_id = s.id
            ORDER BY
              CASE t.status
                WHEN 'running' THEN 0
                WHEN 'pending' THEN 1
                ELSE 2
              END,
              t.queue_pos ASC,
              t.created_at DESC
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
