from flask import Flask, request
import os
import subprocess

app = Flask(__name__)

@app.route("/")
def index():
    return "Welcome to the vulnerable app!"

@app.route("/ping")
def ping():
    """
    VULNERABLE PING ENDPOINT
    Works in fat image (classic shell RCE), fails in distroless.
    """
    ip = request.args.get("ip")
    if not ip:
        return "Missing IP", 400

    try:
        # shell=True allows ;, |, && injection
        output = subprocess.check_output(f"/bin/ping -c 1 {ip}", shell=True, text=True)
        return f"<pre>{output}</pre>"

    except FileNotFoundError:
        return "Ping or shell not found (distroless fails)", 500
    except subprocess.CalledProcessError as e:
        return f"Command failed: {e}", 500
    except Exception as e:
        return f"Unexpected error: {e}", 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

