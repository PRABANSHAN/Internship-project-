Student Assistant (local)

This project is a small Flask app with an optional AI chat feature.

Quick start (Windows PowerShell):

1. Create and activate a virtualenv:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Put your Hugging Face API key in a `.env` file (already created locally) or set `HUGGINGFACE_API_KEY` env var:

```powershell
# temporary for this shell
$env:HUGGINGFACE_API_KEY = "hf_xxxREPLACE_WITH_YOUR_KEYxxx"
# or set permanently
setx HUGGINGFACE_API_KEY "hf_xxxREPLACE_WITH_YOUR_KEYxxx"
```

4. Run the app:

```powershell
python .\app.py
```

5. Open http://127.0.0.1:5000/chat

Notes:
- A `.env` file is used to load environment variables in development. `.env` is listed in `.gitignore` to avoid committing secrets.
- If no `HUGGINGFACE_API_KEY` is set, the app uses a small local rule-based chatbot.
- The default HF model is `mistralai/Mistral-7B-Instruct-v0.3`. Some large models require special access on Hugging Face.
 
Running publicly (expose the app to the web)
-----------------------------------------

You can expose your locally-running app to the public internet using ngrok. This repository includes `start_tunnel.py` which uses `pyngrok` to create a public HTTPS URL.

Requirements:
- Install ngrok (optional — `pyngrok` can download/operate without it, but an ngrok authtoken is recommended).
- Optionally set `NGROK_AUTHTOKEN` to your ngrok authtoken for higher rate limits.

Quick steps (PowerShell):

```powershell
# activate venv
.\.venv\Scripts\Activate.ps1
# install requirements
pip install -r requirements.txt
# set ngrok authtoken (optional)
$env:NGROK_AUTHTOKEN = "your_ngrok_token_here"
# start app + tunnel
python .\start_tunnel.py
```

When `start_tunnel.py` runs it will print a public HTTPS URL (ngrok) that you can open from any device. IMPORTANT: exposing a development server publicly can pose security risks — do not share sensitive keys or data, and consider using a production-ready deployment for real users.

Security note: The repository no longer contains your real API key. A template `.env` file has been added instead (without any secret). Create a real `.env` locally with your `HUGGINGFACE_API_KEY` and do not commit it.

Chat history page
-----------------

Signed-in users can view their stored chat history at `/history`.

Logging and debugging
---------------------

When Hugging Face is enabled, the server logs HF request/response info to help debug failures. If the HF call fails you'll see the error details in the server console and receive an error back in the chat UI.

Admin setup (recommended before making public)
---------------------------------------------

1. Set an admin token in your environment so only people who know this token can access the admin dashboard:

```powershell
setx ADMIN_TOKEN "some-strong-secret"
# restart your shell/IDE so the env var is available
```

2. Admin dashboard is available at `/admin`. Sign in with the token you set.

3. Admin features:
- View users and recent messages
- Export all messages as CSV (`/admin/export`)
- Prune messages older than N days (`/admin/prune`)

Always set `ADMIN_TOKEN` before exposing the site publicly (ngrok or other). The admin dashboard is protected by this token stored in the server environment and never sent to clients.
