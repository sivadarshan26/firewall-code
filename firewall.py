import os
import platform
import subprocess
from flask import Flask, request, render_template ,jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["5 per hour", "1 per minute"])
access_logs = []

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
    geo_info = get_geo_ip(ip)
    access_logs.append(geo_info)

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

# Flask Routes
@app.route("/")
def home():
    blocked_ports = get_blocked_ports()
    return render_template("index.html", blocked_ports=blocked_ports)

@app.route("/block", methods=["POST"])
def block():
    port = request.form.get("port")
    block_port(port)
    return home()

@app.route("/unblock", methods=["POST"])
def unblock():
    port = request.form.get("port")
    unblock_port(port)
    return home()
@app.route("/log_attempt", methods=["POST"])
def log_attempt():
    ip = request.remote_addr
    log_access(ip)
    return jsonify({"message": "Logged", "ip": ip})

@app.route("/access_logs")
def access_logs_view():
    return jsonify(access_logs)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
