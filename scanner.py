import io
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
_current_process = None       # local mode: Popen
_current_task_id = None
_current_ssh_client = None    # remote mode: paramiko SSHClient
_current_remote_dir = None    # remote mode: temp dir path on remote host
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

    try:
        os.makedirs(task_dir, exist_ok=True)
        with open(os.path.join(task_dir, "request.txt"), "w", encoding="utf-8") as f:
            f.write(request_text)

        db.insert_task({
            "id": task_id,
            "host": host,
            "note": note,
            "level": level,
            "risk": risk,
            "timeout_min": timeout_min,
            "status": "pending",
            "request_text": request_text,
            "log": "",
            "created_at": now_iso(),
        })
    except Exception:
        # Roll back: don't leave an orphan directory if anything failed
        if os.path.isdir(task_dir):
            import shutil
            shutil.rmtree(task_dir, ignore_errors=True)
        raise

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
    global _current_process, _current_task_id, _current_ssh_client, _current_remote_dir
    with _runtime_lock:
        if _current_task_id != task_id:
            return False
        if _current_process is not None:
            # Local mode
            try:
                os.killpg(os.getpgid(_current_process.pid), signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
            return True
        if _current_ssh_client is not None:
            # Remote mode: kill sqlmap process on the remote host
            remote_dir = _current_remote_dir
            client = _current_ssh_client
            try:
                _, stdout, _ = client.exec_command(
                    f"pkill -9 -f {shlex.quote(remote_dir)}"
                )
                stdout.channel.recv_exit_status()
            except Exception:
                pass
            return True
        return False


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
    # shlex.split honors quoted segments, so "/path with space/sqlmap" still
    # works when the user wraps it in quotes ("\"/path with space/sqlmap\"").
    cmd = shlex.split(sqlmap_path) if " " in sqlmap_path else [sqlmap_path]
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
    """Run sqlmap locally, capture output. Returns (returncode, output, timed_out)."""
    global _current_process
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        start_new_session=True,
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


def _get_ssh_settings():
    """Return SSH settings dict if remote_host is configured, else None."""
    host = (db.get_setting("remote_host") or "").strip()
    if not host:
        return None
    return {
        "host": host,
        "port": int((db.get_setting("remote_port") or "22").strip() or 22),
        "user": (db.get_setting("remote_user") or "root").strip(),
        "key_path": (db.get_setting("remote_key_path") or "").strip(),
        "password": (db.get_setting("remote_password") or "").strip(),
        # Fall back to the local sqlmap_path setting if no remote path configured
        "sqlmap_path": (db.get_setting("remote_sqlmap_path") or "").strip()
                       or db.get_setting("sqlmap_path", config.DEFAULT_SQLMAP_PATH),
    }


def _run_sqlmap_remote(ssh, request_text, task_id, level, risk, timeout_sec, extra=None):
    """Run sqlmap on a remote host via SSH. Returns (returncode, output, timed_out)."""
    global _current_ssh_client, _current_remote_dir
    try:
        import paramiko
    except ImportError:
        return -1, "[!] paramiko not installed. Run: pip install paramiko\n", False

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kw = dict(
        hostname=ssh["host"],
        port=ssh["port"],
        username=ssh["user"],
        timeout=15,
    )
    if ssh.get("key_path"):
        connect_kw["key_filename"] = ssh["key_path"]
    if ssh.get("password"):
        connect_kw["password"] = ssh["password"]

    try:
        client.connect(**connect_kw)
    except Exception as e:
        return -1, f"[!] SSH connect failed: {e}\n", False

    remote_dir = f"/tmp/openclaw_{task_id}"
    remote_request = f"{remote_dir}/request.txt"
    remote_output = f"{remote_dir}/output"

    output_lines = []
    timed_out = False
    returncode = -1

    try:
        # Create remote working dirs
        _, stdout, _ = client.exec_command(f"mkdir -p {shlex.quote(remote_output)}")
        stdout.channel.recv_exit_status()

        # Upload request.txt via SFTP
        sftp = client.open_sftp()
        try:
            sftp.putfo(io.BytesIO(request_text.encode("utf-8")), remote_request)
        finally:
            sftp.close()

        # Build command with remote paths
        cmd = _build_cmd(ssh["sqlmap_path"], remote_request, remote_output, level, risk, extra)
        cmd_str = " ".join(shlex.quote(p) for p in cmd)

        with _runtime_lock:
            _current_ssh_client = client
            _current_remote_dir = remote_dir

        transport = client.get_transport()
        channel = transport.open_session()
        channel.set_combine_stderr(True)
        channel.exec_command(cmd_str)

        start = time.time()
        try:
            while True:
                if channel.recv_ready():
                    data = channel.recv(65536).decode("utf-8", errors="replace")
                    output_lines.append(data)
                    continue
                if channel.exit_status_ready() and not channel.recv_ready():
                    break
                if timeout_sec and (time.time() - start) > timeout_sec:
                    timed_out = True
                    try:
                        kill_ch = transport.open_session()
                        kill_ch.exec_command(f"pkill -9 -f {shlex.quote(remote_dir)}")
                        kill_ch.recv_exit_status()
                        kill_ch.close()
                    except Exception:
                        pass
                    break
                time.sleep(0.05)

            if not timed_out:
                returncode = channel.recv_exit_status()
        finally:
            channel.close()

    finally:
        with _runtime_lock:
            _current_ssh_client = None
            _current_remote_dir = None
        # Clean up remote temp dir
        try:
            client.exec_command(f"rm -rf {shlex.quote(remote_dir)}")
        except Exception:
            pass
        client.close()

    return returncode, "".join(output_lines), timed_out


def _parse_injection(output):
    """Returns dict with inject_ok, inject_param, inject_type, inject_payload, dbms."""
    result = {
        "inject_ok": 0,
        "inject_param": None,
        "inject_type": None,
        "inject_payload": None,
        "dbms": None,
    }
    if "sqlmap identified the following injection point" in output:
        result["inject_ok"] = 1

    m = re.search(r"Parameter:\s*(\S+)\s*\(([^)]+)\)", output)
    if m:
        result["inject_param"] = f"{m.group(1)} ({m.group(2)})"

    # Match the indented "Type:" line in sqlmap's injection block (avoids
    # matching HTTP "Content-Type:" headers echoed earlier in output).
    m = re.search(r"^[ \t]+Type:\s*(.+)$", output, re.MULTILINE)
    if m:
        result["inject_type"] = m.group(1).strip()

    m = re.search(r"^[ \t]+Payload:\s*(.+)$", output, re.MULTILINE)
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


_UPDATE_FAIL_PATTERN = re.compile(
    r"execution of non-query SQL statements is only available when stacked queries are supported",
    re.I,
)


def _parse_update(output):
    """If sqlmap printed the 'stacked queries required' warning, UPDATE is not
    supported (return 0). Otherwise UPDATE went through (return 1)."""
    return 0 if _UPDATE_FAIL_PATTERN.search(output) else 1


_DBA_TRUE_PATTERN = re.compile(r"current user is DBA:\s*True", re.I)


def _parse_dba(output):
    """sqlmap --is-dba prints 'current user is DBA: True' or 'False'.
    Match True → 1; anything else → 0."""
    return 1 if _DBA_TRUE_PATTERN.search(output) else 0


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
    level, risk = task["level"], task["risk"]

    ssh = _get_ssh_settings()

    if ssh:
        # Remote mode: build display strings using remote paths
        remote_sqlmap = ssh["sqlmap_path"]
        remote_dir = f"/tmp/openclaw_{task_id}"
        remote_req = f"{remote_dir}/request.txt"
        remote_out = f"{remote_dir}/output"

        cmd_inject_str = " ".join(shlex.quote(p) for p in
            _build_cmd(remote_sqlmap, remote_req, remote_out, level, risk))
        cmd_update_str = " ".join(shlex.quote(p) for p in
            _build_cmd(remote_sqlmap, remote_req, remote_out, level, risk,
                extra=["--sql-query=UPDATE information_schema.TABLES "
                       "SET TABLE_COMMENT=TABLE_COMMENT WHERE 1=0"]))
        cmd_dba_str = " ".join(shlex.quote(p) for p in
            _build_cmd(remote_sqlmap, remote_req, remote_out, level, risk,
                extra=["--is-dba"]))

        def run_phase(timeout, extra=None):
            return _run_sqlmap_remote(
                ssh, task["request_text"], task_id, level, risk, timeout, extra
            )
    else:
        # Local mode
        cmd_inject_str = " ".join(shlex.quote(p) for p in
            _build_cmd(sqlmap_path, request_file, output_dir, level, risk))
        cmd_update_str = " ".join(shlex.quote(p) for p in
            _build_cmd(sqlmap_path, request_file, output_dir, level, risk,
                extra=["--sql-query=UPDATE information_schema.TABLES "
                       "SET TABLE_COMMENT=TABLE_COMMENT WHERE 1=0"]))
        cmd_dba_str = " ".join(shlex.quote(p) for p in
            _build_cmd(sqlmap_path, request_file, output_dir, level, risk,
                extra=["--is-dba"]))

        def run_phase(timeout, extra=None):
            cmd = _build_cmd(sqlmap_path, request_file, output_dir, level, risk, extra)
            return _run_sqlmap(cmd, timeout)

    db.update_task(
        task_id,
        status="running",
        started_at=now_iso(),
        cmd_inject=cmd_inject_str,
        cmd_update=cmd_update_str,
        cmd_dba=cmd_dba_str,
    )

    with _runtime_lock:
        _current_task_id = task_id

    full_log = ""
    if ssh:
        full_log += f"[remote] {ssh['user']}@{ssh['host']}:{ssh['port']}\n\n"

    error = None
    inject_data = {"inject_ok": 0}
    update_ok = None  # None = not tested; 0/1 = tested
    is_dba = None

    try:
        rc, out, timed_out = run_phase(timeout_sec)
        full_log += "=== INJECTION DETECTION ===\n" + out + "\n"

        latest = db.get_task(task_id)
        if latest and latest["status"] == "killed":
            return

        if timed_out:
            error = "timeout"
            full_log += "\n[!] timeout reached, process killed\n"
        else:
            inject_data = _parse_injection(out)

            if inject_data["inject_ok"]:
                remain = timeout_sec - (time.time() - started) if timeout_sec else None
                if (remain is None or remain > 0) and \
                   (db.get_task(task_id) or {}).get("status") != "killed":
                    rc2, out2, t2 = run_phase(
                        remain,
                        extra=["--sql-query=UPDATE information_schema.TABLES "
                               "SET TABLE_COMMENT=TABLE_COMMENT WHERE 1=0"],
                    )
                    full_log += "\n=== UPDATE TEST ===\n" + out2 + "\n"
                    if not t2:
                        update_ok = _parse_update(out2)
                    remain2 = timeout_sec - (time.time() - started) if timeout_sec else None
                    if (remain2 is None or remain2 > 0) and \
                       (db.get_task(task_id) or {}).get("status") != "killed":
                        rc3, out3, t3 = run_phase(remain2, extra=["--is-dba"])
                        full_log += "\n=== IS-DBA CHECK ===\n" + out3 + "\n"
                        if not t3:
                            is_dba = _parse_dba(out3)
    except FileNotFoundError as e:
        error = f"sqlmap not found: {e}"
        full_log += f"\n[!] {error}\n"
    except Exception as e:
        error = f"{type(e).__name__}: {e}"
        full_log += f"\n[!] {error}\n"
    finally:
        with _runtime_lock:
            _current_task_id = None

        # Save all results regardless of how we got here (done or killed
        # externally), then update status atomically — only mark 'done'
        # if no one has set 'killed' on us in the meantime.
        # Wrap in try/except so a DB error here never leaves the task
        # permanently stuck in 'running'.
        try:
            with db.connect() as conn:
                conn.execute(
                    "UPDATE tasks SET "
                    "  finished_at=?,"
                    "  duration_sec=?,"
                    "  log=?,"
                    "  error=?,"
                    "  inject_ok=?,"
                    "  inject_param=?,"
                    "  inject_type=?,"
                    "  inject_payload=?,"
                    "  dbms=?,"
                    "  update_ok=?,"
                    "  is_dba=?,"
                    "  status=CASE WHEN status='killed' THEN 'killed' ELSE 'done' END "
                    "WHERE id=?",
                    (
                        now_iso(),
                        int(time.time() - started),
                        full_log,
                        error,
                        inject_data.get("inject_ok"),
                        inject_data.get("inject_param"),
                        inject_data.get("inject_type"),
                        inject_data.get("inject_payload"),
                        inject_data.get("dbms"),
                        update_ok if inject_data.get("inject_ok") else None,
                        is_dba if inject_data.get("inject_ok") else None,
                        task_id,
                    ),
                )
        except Exception as db_err:
            print(f"[worker] failed to finalize task {task_id}: {db_err}", flush=True)
            # Last-ditch attempt: at minimum flip status out of 'running'
            # so the task doesn't stay stuck on the next restart.
            try:
                with db.connect() as conn:
                    conn.execute(
                        "UPDATE tasks SET status='done', finished_at=?, "
                        "error='DB write failed during finalization' "
                        "WHERE id=? AND status='running'",
                        (now_iso(), task_id),
                    )
            except Exception:
                pass


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
