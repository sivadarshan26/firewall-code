# firewall.py
import os
import platform
import threading
import subprocess
import json
import requests
from datetime import datetime

from app_factory import app  # ✅ Get app from clean source
from sniffer import start_sniffer, load_sniffer_ports, add_sniffer_port, remove_sniffer_port
from rateLimiter import port_rate_limits, save_rate_limits, set_limit_for_port


access_logs = []
active_sniffers = {}
RATE_LIMITS_FILE = "rate_limits.json"

# ------------------- OS & Geo Info -------------------

def get_os():
    return platform.system()

def get_external_ip():
    try:
        response = requests.get("https://api64.ipify.org?format=json")
        return response.json()["ip"]
    except:
        return "Unknown"

def get_geo_ip(ip):
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
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[ACCESS] {timestamp} {geo_info['ip']} - {geo_info['city']}, {geo_info['region']}, {geo_info['country']} ({geo_info['isp']})\n"

    with open("firewall.log", "a") as f:
        f.write(log_line)


# ------------------- Port Block/Unblock -------------------

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

# ------------------- Rate Limit -------------------


def save_rate_limits():
    try:
        with open(RATE_LIMITS_FILE, "w") as f:
            json.dump(port_rate_limits, f)
    except Exception as e:
        print(f"[ERROR] Failed to save rate limits: {e}")

def get_limit_for_port(port):
    return port_rate_limits.get(str(port))

def remove_limit_for_port(port):
    port = str(port)
    if port in port_rate_limits:
        del port_rate_limits[port]
        save_rate_limits()
        return True
    return False


# ------------------- Sniffer Bootstrap -------------------

def restore_sniffers():
    for port in load_sniffer_ports():
        if port not in active_sniffers:
            stop_event = threading.Event()
            thread = threading.Thread(target=start_sniffer, kwargs={"port": port, "stop_event": stop_event})
            thread.daemon = True
            thread.start()
            active_sniffers[port] = (thread, stop_event)
            with open("firewall.log", "a") as f:
                f.write(f"[INFO] Sniffer auto-restarted on port {port}\n")


