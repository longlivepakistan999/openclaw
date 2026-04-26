import os
import re
import shlex
import signal
import subprocess
import threading
import time
import uuid
from datetime import datetime

import config
import db


_runtime_lock = threading.Lock()
_current_process = None
_current_task_id = None
_wakeup = threading.Event()


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def parse_host(request_text):
    for line in request_text.splitlines():
        m = re.match(r"^Host:\s*(\S+)", line, re.I)
        if m:
            return m.group(1)
    first = request_text.splitlines()[0] if request_text else ""
    m = re.search(r"https?://([^/\s]+)", first)
    return m.group(1) if m else "unknown"


def create_task(request_text, level, risk, timeout_min, note=""):
    task_id = uuid.uuid4().hex[:8]
    host = parse_host(request_text)
    task_dir = os.path.join(config.SCANS_DIR, task_id)
    os.makedirs(task_dir, exist_ok=True)
    with open(os.path.join(task_dir, "request.txt"), "w") as f:
        f.write(request_text)

    db.insert_task({
        "id": task_id,
        "host": host,
        "note": note,
        "level": level,
        "risk": risk,
        "timeout_min": timeout_min,
        "status": "pending",
        "queue_pos": db.next_queue_pos(),
        "request_text": request_text,
        "log": "",
        "created_at": now_iso(),
    })
    _wakeup.set()
    return task_id


def jump_queue(task_id):
    pending = db.list_pending_ordered()
    ids = [t["id"] for t in pending if t["id"] != task_id]
    if any(t["id"] == task_id for t in pending):
        ids = [task_id] + ids
        db.reorder_pending(ids)
        return True
    return False


def kill_current(task_id):
    global _current_process, _current_task_id
    with _runtime_lock:
        if _current_task_id != task_id or _current_process is None:
            return False
        try:
            os.killpg(os.getpgid(_current_process.pid), signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass
        return True


def rerun_task(task_id):
    old = db.get_task(task_id)
    if not old:
        return None
    return create_task(
        old["request_text"],
        old["level"],
        old["risk"],
        old["timeout_min"],
        note=old.get("note") or "",
    )


def delete_task(task_id):
    """Returns: 'ok', 'not_found', or 'running'."""
    task = db.get_task(task_id)
    if not task:
        return "not_found"
    if task["status"] == "running":
        return "running"
    db.delete_task(task_id)
    task_dir = os.path.join(config.SCANS_DIR, task_id)
    if os.path.isdir(task_dir):
        import shutil
        shutil.rmtree(task_dir, ignore_errors=True)
    return "ok"


def _build_cmd(sqlmap_path, request_file, output_dir, level, risk, extra=None):
    cmd = sqlmap_path.split() if " " in sqlmap_path else [sqlmap_path]
    cmd += [
        "-r", request_file,
        "--batch",
        "--dbms=mysql",
        f"--level={level}",
        f"--risk={risk}",
        f"--output-dir={output_dir}",
    ]
    if extra:
        cmd += extra
    return cmd


def _run_sqlmap(cmd, timeout_sec):
    """Run sqlmap, capture output. Returns (returncode, output, timed_out).
    Uses a reader thread so timeout works even when sqlmap stalls on output."""
    global _current_process
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        preexec_fn=os.setsid,
    )
    with _runtime_lock:
        _current_process = proc

    output_lines = []

    def _reader():
        try:
            for line in iter(proc.stdout.readline, ''):
                output_lines.append(line)
        except Exception:
            pass

    reader = threading.Thread(target=_reader, daemon=True)
    reader.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    finally:
        try:
            proc.stdout.close()
        except Exception:
            pass
        reader.join(timeout=2)
        with _runtime_lock:
            _current_process = None

    return proc.returncode, "".join(output_lines), timed_out


def _parse_injection(output):
    """Returns dict with inject_ok, inject_param, inject_type, inject_payload, dbms, current_user."""
    result = {
        "inject_ok": 0,
        "inject_param": None,
        "inject_type": None,
        "inject_payload": None,
        "dbms": None,
        "current_user": None,
    }
    if "sqlmap identified the following injection point" in output:
        result["inject_ok"] = 1

    m = re.search(r"Parameter:\s*(\S+)\s*\(([^)]+)\)", output)
    if m:
        result["inject_param"] = f"{m.group(1)} ({m.group(2)})"

    m = re.search(r"Type:\s*(.+)", output)
    if m:
        result["inject_type"] = m.group(1).strip()

    m = re.search(r"Payload:\s*(.+)", output)
    if m:
        result["inject_payload"] = m.group(1).strip()

    m = re.search(r"back-end DBMS(?: operating system)?:\s*(.+)", output)
    if m:
        result["dbms"] = m.group(1).strip()
    else:
        m = re.search(r"the back-end DBMS is\s*(\S+)", output)
        if m:
            result["dbms"] = m.group(1).strip()

    return result


_UPDATE_FAIL_PATTERNS = [
    r"command denied",
    r"access denied",
    r"permission denied",
    r"not allowed",
    r"no privilege",
    r"insufficient privilege",
    r"read[- ]only",
    r"all tested parameters do not appear to be injectable",
    r"unable to retrieve",
]


def _parse_update(output):
    """Blacklist: if any failure pattern matched, return 0; else 1."""
    for pat in _UPDATE_FAIL_PATTERNS:
        if re.search(pat, output, re.I):
            return 0
    return 1


def _parse_dba(output):
    m = re.search(r"current user is DBA:\s*(\w+)", output)
    if m:
        return 1 if m.group(1).strip().lower() == "true" else 0
    return 0


def _parse_current_user(output):
    m = re.search(r"current user:\s*'?([^'\n]+)'?", output)
    return m.group(1).strip() if m else None


def _execute_task(task_id):
    global _current_task_id
    task = db.get_task(task_id)
    if not task:
        return
    sqlmap_path = db.get_setting("sqlmap_path", config.DEFAULT_SQLMAP_PATH)
    task_dir = os.path.join(config.SCANS_DIR, task_id)
    request_file = os.path.join(task_dir, "request.txt")
    output_dir = os.path.join(task_dir, "output")
    os.makedirs(output_dir, exist_ok=True)

    timeout_sec = task["timeout_min"] * 60 if task["timeout_min"] else None
    started = time.time()

    cmd_inject = _build_cmd(sqlmap_path, request_file, output_dir, task["level"], task["risk"])
    cmd_update = _build_cmd(
        sqlmap_path, request_file, output_dir, task["level"], task["risk"],
        extra=[
            "--sql-query=UPDATE information_schema.TABLES "
            "SET TABLE_COMMENT=TABLE_COMMENT WHERE 1=0"
        ],
    )
    cmd_dba = _build_cmd(
        sqlmap_path, request_file, output_dir, task["level"], task["risk"],
        extra=["--is-dba"],
    )

    db.update_task(
        task_id,
        status="running",
        started_at=now_iso(),
        cmd_inject=" ".join(shlex.quote(p) for p in cmd_inject),
        cmd_update=" ".join(shlex.quote(p) for p in cmd_update),
        cmd_dba=" ".join(shlex.quote(p) for p in cmd_dba),
    )

    with _runtime_lock:
        _current_task_id = task_id

    full_log = ""
    error = None
    inject_data = {"inject_ok": 0}
    update_ok = None  # None = not tested; 0/1 = tested
    is_dba = None

    try:
        rc, out, timed_out = _run_sqlmap(cmd_inject, timeout_sec)
        full_log += "=== INJECTION DETECTION ===\n" + out + "\n"

        latest = db.get_task(task_id)
        if latest and latest["status"] == "killed":
            return

        if timed_out:
            error = "timeout"
            full_log += "\n[!] timeout reached, process killed\n"
        else:
            inject_data = _parse_injection(out)
            inject_data["current_user"] = _parse_current_user(out)

            if inject_data["inject_ok"]:
                remain = timeout_sec - (time.time() - started) if timeout_sec else None
                if remain is None or remain > 0:
                    rc2, out2, t2 = _run_sqlmap(cmd_update, remain)
                    full_log += "\n=== UPDATE TEST ===\n" + out2 + "\n"
                    if not t2:
                        update_ok = _parse_update(out2)
                    if (db.get_task(task_id) or {}).get("status") != "killed":
                        remain2 = timeout_sec - (time.time() - started) if timeout_sec else None
                        if remain2 is None or remain2 > 0:
                            rc3, out3, t3 = _run_sqlmap(cmd_dba, remain2)
                            full_log += "\n=== IS-DBA CHECK ===\n" + out3 + "\n"
                            if not t3:
                                is_dba = _parse_dba(out3)
                                if not inject_data.get("current_user"):
                                    inject_data["current_user"] = _parse_current_user(out3)
    except FileNotFoundError as e:
        error = f"sqlmap not found: {e}"
        full_log += f"\n[!] {error}\n"
    except Exception as e:
        error = f"{type(e).__name__}: {e}"
        full_log += f"\n[!] {error}\n"
    finally:
        with _runtime_lock:
            _current_task_id = None

        # Don't overwrite a 'killed' status
        latest = db.get_task(task_id)
        final_status = "done" if (latest and latest["status"] != "killed") else "killed"

        db.update_task(
            task_id,
            status=final_status,
            finished_at=now_iso(),
            duration_sec=int(time.time() - started),
            log=full_log,
            error=error,
            inject_ok=inject_data.get("inject_ok"),
            inject_param=inject_data.get("inject_param"),
            inject_type=inject_data.get("inject_type"),
            inject_payload=inject_data.get("inject_payload"),
            dbms=inject_data.get("dbms"),
            current_user=inject_data.get("current_user"),
            update_ok=update_ok if inject_data.get("inject_ok") else None,
            is_dba=is_dba if inject_data.get("inject_ok") else None,
        )


def mark_killed(task_id):
    """Mark status=killed only if currently running or pending (avoids overwriting done)."""
    with db.connect() as conn:
        conn.execute(
            "UPDATE tasks SET status='killed', finished_at=? "
            "WHERE id=? AND status IN ('running','pending')",
            (now_iso(), task_id),
        )


def _worker_loop():
    while True:
        try:
            pending = db.list_pending_ordered()
            if not pending:
                _wakeup.wait(timeout=2.0)
                _wakeup.clear()
                continue
            next_id = pending[0]["id"]
            try:
                _execute_task(next_id)
            except Exception as e:
                try:
                    db.update_task(next_id, status="done", error=str(e), finished_at=now_iso())
                except Exception:
                    pass
        except Exception as e:
            # never let the worker thread die
            print(f"[worker] unexpected error: {type(e).__name__}: {e}", flush=True)
            time.sleep(1)


def start_worker():
    db.init_db()
    t = threading.Thread(target=_worker_loop, daemon=True)
    t.start()
    return t
