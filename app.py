from flask import Flask, jsonify, render_template, request

import config
import db
import scanner

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.get("/api/settings")
def get_settings():
    return jsonify({
        "sqlmap_path": db.get_setting("sqlmap_path", config.DEFAULT_SQLMAP_PATH),
    })


@app.post("/api/settings")
def update_settings():
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "invalid JSON object"}), 400
    if "sqlmap_path" in data:
        path = data["sqlmap_path"]
        if not isinstance(path, str):
            return jsonify({"error": "sqlmap_path must be a string"}), 400
        db.set_setting("sqlmap_path", path.strip())
    return jsonify({"ok": True})


_HEAVY_FIELDS = ("log", "request_text", "cmd_inject", "cmd_update", "cmd_dba")


@app.get("/api/tasks")
def list_tasks():
    tasks = db.list_tasks()
    pending = [t for t in tasks if t["status"] == "pending"]
    pending_index = {t["id"]: i + 1 for i, t in enumerate(pending)}
    summaries = []
    for t in tasks:
        t["queue_position"] = pending_index.get(t["id"])
        for f in _HEAVY_FIELDS:
            t.pop(f, None)
        summaries.append(t)
    return jsonify(summaries)


@app.get("/api/tasks/<task_id>")
def get_task(task_id):
    task = db.get_task(task_id)
    if not task:
        return jsonify({"error": "not found"}), 404
    return jsonify(task)


def _coerce_int(v, default, lo, hi):
    """Return clamped int, or None on failure (caller decides what to do)."""
    if v in (None, ""):
        return default
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return max(lo, min(hi, n))


@app.post("/api/tasks")
def create_task():
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "invalid JSON object"}), 400

    request_text = data.get("request_text")
    if not isinstance(request_text, str) or not request_text.strip():
        return jsonify({"error": "request_text required"}), 400
    request_text = request_text.strip()

    level = _coerce_int(data.get("level"), config.DEFAULT_LEVEL, 1, 5)
    risk = _coerce_int(data.get("risk"), config.DEFAULT_RISK, 1, 3)
    if level is None or risk is None:
        return jsonify({"error": "level/risk must be integers"}), 400

    raw_timeout = data.get("timeout_min")
    if raw_timeout in (None, "", 0, "0"):
        timeout_min = None
    else:
        try:
            timeout_min = int(raw_timeout)
            if timeout_min < 0:
                timeout_min = None
        except (TypeError, ValueError):
            return jsonify({"error": "timeout_min must be an integer"}), 400

    note = data.get("note") or ""
    if not isinstance(note, str):
        return jsonify({"error": "note must be a string"}), 400
    note = note.strip()[:500]

    task_id = scanner.create_task(request_text, level, risk, timeout_min, note=note)
    return jsonify({"id": task_id})


@app.post("/api/tasks/<task_id>/jump")
def jump(task_id):
    ok = scanner.jump_queue(task_id)
    return jsonify({"ok": ok})


@app.post("/api/tasks/<task_id>/kill")
def kill(task_id):
    task = db.get_task(task_id)
    if not task:
        return jsonify({"error": "not found"}), 404
    if task["status"] != "running":
        return jsonify({"error": "task is not running"}), 400
    scanner.mark_killed(task_id)
    scanner.kill_current(task_id)
    return jsonify({"ok": True})


@app.post("/api/tasks/<task_id>/rerun")
def rerun(task_id):
    new_id = scanner.rerun_task(task_id)
    if not new_id:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": new_id})


@app.delete("/api/tasks/<task_id>")
def delete(task_id):
    result = scanner.delete_task(task_id)
    if result == "not_found":
        return jsonify({"error": "task not found"}), 404
    if result == "running":
        return jsonify({"error": "cannot delete running task"}), 400
    return jsonify({"ok": True})


@app.post("/api/tasks/batch")
def batch():
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "invalid JSON object"}), 400
    action = data.get("action")
    if action not in ("delete", "kill", "jump"):
        return jsonify({"error": "action must be delete/kill/jump"}), 400
    ids = data.get("ids")
    if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
        return jsonify({"error": "ids must be a list of strings"}), 400

    results = {}
    for tid in ids:
        if action == "delete":
            results[tid] = scanner.delete_task(tid) == "ok"
        elif action == "kill":
            t = db.get_task(tid)
            if t and t["status"] == "running":
                scanner.mark_killed(tid)
                scanner.kill_current(tid)
                results[tid] = True
            else:
                results[tid] = False
        else:  # jump
            results[tid] = scanner.jump_queue(tid)
    return jsonify({"results": results})


if __name__ == "__main__":
    scanner.start_worker()
    app.run(host="0.0.0.0", port=5000, debug=False)
