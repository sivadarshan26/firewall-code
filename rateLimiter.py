# limiter.py
import json
import os

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

RATE_LIMITS_FILE = "rate_limits.json"
port_rate_limits = {}

limiter = Limiter(get_remote_address, default_limits=[])

# Predefined schemes
PREDEFINED_LIMITS = {
    "minimal": "5 per minute",
    "hardcore": "20 per second",
    "burst": "100 per minute",
    "standard": "1000 per hour"
}

def set_limit_for_port(port, rate=None, unit=None, scheme=None):
    if scheme and scheme in PREDEFINED_LIMITS:
        port_rate_limits[str(port)] = PREDEFINED_LIMITS[scheme]
    elif rate and unit:
        port_rate_limits[str(port)] = f"{rate} per {unit}"
    else:
        return False
    save_rate_limits()  # ✅ Persist changes
    return True


def get_limit_for_port(port):
    return port_rate_limits.get(str(port))

def remove_limit_for_port(port):
    if str(port) in port_rate_limits:
        del port_rate_limits[str(port)]
        save_rate_limits()  # ✅ Persist changes
        return True
    return False
def save_rate_limits():
    with open(RATE_LIMITS_FILE, "w") as f:
        json.dump(port_rate_limits, f, indent=2)


def load_rate_limits():
    global port_rate_limits
    if os.path.exists(RATE_LIMITS_FILE):
        try:
            with open(RATE_LIMITS_FILE, "r") as f:
                port_rate_limits = json.load(f)
        except Exception as e:
            print(f"[ERROR] Failed to load rate limits: {e}")
            port_rate_limits = {}
