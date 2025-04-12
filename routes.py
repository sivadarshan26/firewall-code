# routes.py
from flask import request, jsonify, render_template
import flask_limiter.errors
import threading
from datetime import datetime
import os 
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter
import json

from app_factory import app, limiter  # ✅ Get app from new file
from mail import send_alert_email
from firewall import (
    block_port,
    unblock_port,
    start_sniffer,
    add_sniffer_port,
    remove_sniffer_port,
    restore_sniffers,
    active_sniffers,
    log_access,
    get_blocked_ports,
    port_rate_limits
)
from rateLimiter import set_limit_for_port, get_limit_for_port, remove_limit_for_port, save_rate_limits, load_rate_limits


# app = Flask(__name__)
# limiter = Limiter(get_remote_address, app=app)

load_rate_limits()
restore_sniffers()

# ------------------- Error -------------------

@app.errorhandler(flask_limiter.errors.RateLimitExceeded)
def ratelimit_handler(e):
    ip = request.remote_addr
    send_alert_email(ip)
    return "⚠️ Rate limit exceeded. Admin notified.", 429

# ------------------- UI -------------------

@app.route("/")
def home():
    log_access(request.remote_addr)
    return render_template("index.html", blocked_ports=get_blocked_ports(), limits=port_rate_limits)

# ------------------- APIs -------------------

@app.route("/api/block", methods=["POST"])
def api_block():
    data = request.get_json()
    port = data.get("port")
    result = block_port(port)
    with open("firewall.log", "a") as f:
        f.write(f"[BLOCK] {datetime.now()} - Port {port} blocked\n")
    return jsonify({"result": result})


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    data = request.get_json()
    port = data.get("port")
    result = unblock_port(port)
    with open("firewall.log", "a") as f:
        f.write(f"[UNBLOCK] {datetime.now()} - Port {port} unblocked\n")
    return jsonify({"result": result})

@app.route("/api/start_sniffer", methods=["POST"])
def api_start_sniffer():
    data = request.get_json()
    port = int(data.get("port"))
    if port in active_sniffers:
        return jsonify({"error": "Already running"}), 400

    stop_event = threading.Event()
    thread = threading.Thread(target=start_sniffer, kwargs={"port": port, "stop_event": stop_event})
    thread.daemon = True
    thread.start()
    active_sniffers[port] = (thread, stop_event)
    add_sniffer_port(port)

    with open("firewall.log", "a") as f:
        f.write(f"[SNIFFER STARTED] {datetime.now()} - Port {port}\n")

    return jsonify({"status": "started"})


@app.route("/api/stop_sniffer", methods=["POST"])
def api_stop_sniffer():
    data = request.get_json()
    port = int(data.get("port"))
    if port in active_sniffers:
        thread, stop_event = active_sniffers[port]
        stop_event.set()
        del active_sniffers[port]
        remove_sniffer_port(port)

        with open("firewall.log", "a") as f:
            f.write(f"[SNIFFER STOPPED] {datetime.now()} - Port {port}\n")

        return jsonify({"status": "stopped"})
    return jsonify({"error": "Not running"}), 400


@app.route("/api/sniffed_ports")
def sniffed_ports():
    return jsonify(list(active_sniffers.keys()))

@app.route("/api/set_limit", methods=["POST"])
def api_set_limit():
    print("🛠️ set_limit route hit")
    data = request.json
    port = data.get("port")
    rate = data.get("rate")
    unit = data.get("unit")
    scheme = data.get("scheme")
    mode = data.get("mode")

    if mode == "scheme":
        success = set_limit_for_port(port, scheme=scheme)
    else:
        success = set_limit_for_port(port, rate=rate, unit=unit)

    if success:
        save_rate_limits()  # ✅ persist it here
        return jsonify({"success": True}), 200
    return jsonify({"success": False}), 400

@app.route("/api/remove_limit", methods=["POST"])
def remove_limit():
    data = request.get_json()
    port = str(data["port"])  # or int, depending on your key style

    with open("rate_limits.json", "r") as f:
        limits = json.load(f)

    if port in limits:
        del limits[port]

    with open("rate_limits.json", "w") as f:
        json.dump(limits, f, indent=2)

    return jsonify(success=True)


@limiter.exempt
@app.route("/api/access_logs")
def api_logs():
    log_entries = []
    if os.path.exists("firewall.log"):
        with open("firewall.log", "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    log_entries.append(line)
    return jsonify(log_entries[-20:][::-1])

@app.route("/port/<int:port_number>", methods=["GET", "POST"])
@limiter.limit(lambda: get_limit_for_port(request.view_args["port_number"]) or "1000 per minute")
def simulate_port_hit(port_number):
    ip = request.remote_addr
    log_access(ip)
    with open("firewall.log", "a") as f:
        f.write(f"[ACCESS] Port {port_number} hit from {ip}\n")
    return jsonify({"message": f"Access to port {port_number} logged."})

@app.route("/api/rate_limits")
def get_rate_limits():
    with open("rate_limits.json") as f:
        data = json.load(f)
    return jsonify(data)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
