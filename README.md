# SentriX

**SentriX** is a lightweight, open-source firewall and monitoring tool built with Python and Flask.  
It provides port rate limiting, blocking/unblocking, logging, and email alerts for enhanced security of local services.

---

## Features
- Port rate limiting
- Port blocking/unblocking via API
- Email alerts for rate limit breaches
- Request/response logging in `.log` files
- Track blocked and rate-limited ports in `.json` files

---

## Installation

1. Clone the repository
   ```bash
   git clone https://github.com/yourname/SentriX.git
   cd SentriX

2. Set up a virtual environment (optional but recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On :env\Scripts\activate

3. Install dependencies:
   ```bash
   pip install -r requirements.txt

4. For Windows users:
    Scapy requires Npcap or WinPcap to work on Windows.
    Download and install [Npcap](https://npcap.com/)   (recommended over WinPcap). Make sure to select the option to install Npcap in "WinPcap API-compatible mode" during installation.

4. Run the application:
   python app.py
