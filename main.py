from firewall import restore_sniffers
from app_factory import app
from routes import *  # register routes here

if __name__ == "__main__":
    print("🚀 Starting Firewall Flask App...")
    restore_sniffers()
    print("🟢 Sniffers restored. Running app now.")
    app.run(host="0.0.0.0", port=5000, debug=True)
