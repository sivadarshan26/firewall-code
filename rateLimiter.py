from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Global rate limiter instance (to be used in main app)
limiter = Limiter(get_remote_address, default_limits=[])

# Dictionary to track per-port limits
port_rate_limits = {}

def set_limit_for_port(port, rate):
    """Store a custom rate limit for a specific port"""
    if port and rate:
        port_rate_limits[port] = rate
        return True
    return False

def get_limit_for_port(port):
    return port_rate_limits.get(port)
