import os
import platform
import threading
import requests
import subprocess
from flask import Flask, request, render_template ,jsonify, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import flask_limiter.errors
from sniffer import start_sniffer
from datetime import datetime
from mail import send_alert_email


app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["15 per minute"])
access_logs = []

active_sniffers = {}

# Function to detect OS
def get_os():
    return platform.system()
def get_external_ip():
    """Get the external IP of the machine"""
    try:
        response = requests.get("https://api64.ipify.org?format=json")
        return response.json()["ip"]
    except:
        return "Unknown"
def get_geo_ip(ip):
    """Fetch location info of an IP address"""
    try:
        response = requests.get(f"http://ipinfo.io/{ip}/json")
        data = response.json()
        return {
            "ip": ip,
            "city": data.get("city", "Unknown"),
            "region": data.get("region", "Unknown"),
            "country": data.get("country", "Unknown"),
            "isp": data.get("org", "Unknown"),
        }
    except:
        return {"ip": ip, "city": "Unknown", "region": "Unknown", "country": "Unknown", "isp": "Unknown"}

def log_access(ip):
    """Log incoming access attempts with Geo-IP details"""
    is_admin = ip == "127.0.0.1"

    geo_info = {
        "ip": "admin" if is_admin else ip,
        "city": "Local" if is_admin else "Unknown",
        "region": "Local" if is_admin else "Unknown",
        "country": "Local" if is_admin else "Unknown",
        "isp": "Localhost" if is_admin else "Unknown",
    }

    if not is_admin:
        try:
            geo_info = get_geo_ip(ip)
        except:
            pass

    access_logs.append(geo_info)

    # Log line with timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[ACCESS] {timestamp} {geo_info['ip']} - {geo_info['city']}, {geo_info['region']}, {geo_info['country']} ({geo_info['isp']})\n"

    with open("firewall.log", "a") as f:
        f.write(log_line)

def block_port(port):
    os_type = get_os()
    if os_type == "Windows":
        command = f'netsh advfirewall firewall add rule name="BlockPort{port}" dir=in action=block protocol=TCP localport={port}'
    elif os_type == "Linux":
        command = f"sudo iptables -A INPUT -p tcp --dport {port} -j DROP"
    else:
        return "❌ Unsupported OS"

    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else result.stderr


# Function to unblock a port
def unblock_port(port):
    os_type = get_os()
    if os_type == "Windows":
        command = f'netsh advfirewall firewall delete rule name="BlockPort{port}"'
    elif os_type == "Linux":
        command = f"sudo iptables -D INPUT -p tcp --dport {port} -j DROP"
    else:
        return "❌ Unsupported OS"

    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else result.stderr

# Function to list blocked ports
def get_blocked_ports():
    os_type = get_os()
    blocked_ports = []

    if os_type == "Windows":
        command = 'netsh advfirewall firewall show rule name=all'
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        lines = result.stdout.splitlines()
        for i in range(len(lines)):
            if "Rule Name" in lines[i] and "BlockPort" in lines[i]:  
                for j in range(i, min(i + 10, len(lines))):
                    if "LocalPort" in lines[j]:  
                        port = lines[j].split(":")[-1].strip()
                        blocked_ports.append(port)

    elif os_type == "Linux":
        command = "sudo iptables -L INPUT -n --line-numbers"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        for line in result.stdout.splitlines():
            if "DROP" in line and "dpt:" in line:
                parts = line.split()
                port = next((p.split(":")[-1] for p in parts if "dpt:" in p), None)
                if port:
                    blocked_ports.append(port)

    return blocked_ports

@app.errorhandler(flask_limiter.errors.RateLimitExceeded)
def ratelimit_handler(e):
    ip = request.remote_addr
    send_alert_email(ip)
    return "⚠️ Rate limit exceeded. Admin has been notified.", 429

# Start the packet sniffer in a separate thread
# sniffer_thread = threading.Thread(target=start_sniffer, kwargs={"port": 8080})
# sniffer_thread.daemon = True
# sniffer_thread.start()

# Flask Routes
@app.route("/log_attempt", methods=["GET", "POST"])

@app.route("/")
def home():
    log_access(request.remote_addr)  # Add this
    blocked_ports = get_blocked_ports()
    return render_template("index.html", blocked_ports=blocked_ports)

@app.route('/block', methods=['POST'])
def block_port_route():
    port = request.form.get("port")
    result = block_port(port)

    with open("firewall.log", "a") as f:
        f.write(f"[BLOCK] Port {port} blocked from {request.remote_addr}\n")

    return redirect(url_for('home'))


@app.route("/unblock", methods=["POST"])
def unblock():
    port = request.form.get("port")
    result = unblock_port(port)

    # Log the action
    with open("firewall.log", "a") as f:
        f.write(f"[UNBLOCK] Port {port} unblocked from {request.remote_addr}\n")

    return home()

@app.route("/log_attempt", methods=["POST"])
def log_attempt():
    ip = request.remote_addr
    log_access(ip)
    return jsonify({"message": "Logged", "ip": ip})

@app.route("/access_logs")
def access_logs_view():
    log_entries = []

    if os.path.exists("firewall.log"):
        with open("firewall.log", "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    log_entries.append(line)

    return jsonify(log_entries[-20:][::-1])  # Last 20 entries, newest first

@app.route("/start_sniffer", methods=["POST"])
def start_sniffer_route():
    port = int(request.form.get("sniff_port"))

    # If already running, don't start again
    if port in active_sniffers:
        return f"❌ Sniffer already running on port {port}", 400

    stop_event = threading.Event()
    thread = threading.Thread(target=start_sniffer, kwargs={"port": port, "stop_event": stop_event})
    thread.daemon = True
    thread.start()

    active_sniffers[port] = (thread, stop_event)

    with open("firewall.log", "a") as f:
        f.write(f"[INFO] Sniffer started on port {port} by {request.remote_addr}\n")

    return home()

@app.route("/stop_sniffer", methods=["POST"])
def stop_sniffer_route():
    port = int(request.form.get("sniff_port"))

    if port in active_sniffers:
        thread, stop_event = active_sniffers[port]
        stop_event.set()  # Signal the thread to stop
        del active_sniffers[port]

        with open("firewall.log", "a") as f:
            f.write(f"[INFO] Sniffer stopped on port {port} by {request.remote_addr}\n")

        return redirect(url_for('home'))
    else:
        return f"❌ No sniffer running on port {port}", 400


@app.route("/sniffed_ports")
def sniffed_ports():
    return jsonify(list(active_sniffers.keys()))



@app.route("/port/<int:port_number>", methods=["GET", "POST"])
def simulate_port_hit(port_number):
    ip = request.remote_addr
    log_access(ip)

    with open("firewall.log", "a") as f:
        f.write(f"[ACCESS] Port {port_number} hit from {ip}\n")

    return jsonify({"message": f"Access to port {port_number} logged."})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
