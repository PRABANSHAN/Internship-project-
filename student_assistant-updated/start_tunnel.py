"""
Start the Flask app and open a public ngrok HTTP tunnel to it.
Requires: pyngrok, python-dotenv (optional .env file)

Usage:
  python start_tunnel.py

If you have an ngrok authtoken, set it in env as NGROK_AUTHTOKEN or use `pyngrok authtoken <token>`.
"""
import os
import threading
import time
from pyngrok import ngrok, conf
from dotenv import load_dotenv

# load .env if present
load_dotenv()

# Import the Flask app from app.py
# Note: app.py should expose a Flask instance named `app` at top-level
try:
    from app import app as flask_app
except Exception as e:
    print("Error: could not import Flask app from app.py:", e)
    raise

PORT = int(os.environ.get('PORT', 5000))
HOST = '0.0.0.0'

# Optionally set ngrok auth token from env var NGROK_AUTHTOKEN
ngrok_token = os.environ.get('NGROK_AUTHTOKEN') or os.environ.get('NGROK_AUTH_TOKEN')
if ngrok_token:
    conf.get_default().auth_token = ngrok_token


def run_flask():
    # Run Flask without the reloader so we can run it in a thread
    flask_app.run(host=HOST, port=PORT, debug=False, use_reloader=False)


def main():
    print("Starting Flask app on http://{}:{}".format(HOST, PORT))

    t = threading.Thread(target=run_flask, daemon=True)
    t.start()

    # Wait a moment for the server to start
    time.sleep(1.5)

    print("Opening ngrok tunnel...")
    try:
        public_url = ngrok.connect(addr=PORT, bind_tls=True)
        print("ngrok tunnel established:", public_url)
        print("Share this URL to access the app from the web. Press Ctrl+C to stop.")
    except Exception as e:
        print("Failed to start ngrok tunnel:", e)
        print("Make sure ngrok is installed or your NGROK_AUTHTOKEN is correct.")
        return

    try:
        # Keep the main thread alive while the app and tunnel run
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down tunnel and server...")
        ngrok.kill()


if __name__ == '__main__':
    main()
