from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "Abishek's test application 001!"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001, debug=True)  # Runs on port 8080
