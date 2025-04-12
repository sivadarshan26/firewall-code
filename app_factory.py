# app_factory.py
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from rateLimiter import load_rate_limits

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app)

load_rate_limits()