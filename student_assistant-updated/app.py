from flask import Flask, request, redirect, session, render_template, flash, jsonify
import sqlite3
import os
import requests
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import logging
import traceback
import ast
import operator as op

# Load .env for local development if present
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'your_secret_key'
# Database path configurable for tests/dev
DB_PATH = os.environ.get('DB_PATH', 'users.db')

# India Standard Time (UTC+5:30) helper
IST = timezone(timedelta(hours=5, minutes=30), name='IST')

def now_ist():
    return datetime.now(IST)

def get_conn():
    return sqlite3.connect(DB_PATH)

# ---------------------- DATABASE INIT ----------------------
def init_db():
    # Always ensure the database file and required tables exist.
    conn = get_conn()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    # ensure an admin user exists (configurable via env)
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@gmail.com')
    admin_name = os.environ.get('ADMIN_NAME', 'admin')
    admin_pass = os.environ.get('ADMIN_PASS', 'admin123')
    try:
        c.execute('SELECT id FROM users WHERE email=?', (admin_email,))
        if not c.fetchone():
            hashed = generate_password_hash(admin_pass)
            c.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', (admin_name, admin_email, hashed))
            conn.commit()
            logger.info('Created default admin user: %s', admin_email)
    except Exception as e:
        logger.error('Error ensuring admin user exists: %s', e)
    conn.close()

init_db()

# ---------------------- ROUTES ----------------------
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        print(f"Message from {name} ({email}): {message}")
        flash('Thanks for contacting us! We\'ll get back to you soon.', 'success')
        return redirect('/contact')
    return render_template('contact.html')

@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/settings')
def settings():
    # Allow user to set a per-session Hugging Face API key from the settings page
    return render_template('settings.html')


@app.route('/settings', methods=['POST'])
def settings_save():
    # Save or clear the Hugging Face API key in the user's session
    key = request.form.get('hf_api_key', '').strip()
    if key:
        session['hf_api_key'] = key
        flash('Hugging Face API key saved to your session. Advanced AI enabled for your session.', 'success')
    else:
        session.pop('hf_api_key', None)
        flash('Hugging Face API key removed from your session.', 'success')
    return redirect('/settings')

@app.route('/under-construction')
def under_construction():
    return render_template('under-construction.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if 'user' in session:
        return redirect('/features')
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = get_conn()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=?", (email,))
        user = c.fetchone()
        conn.close()
        if user:
            stored = user[3]
            # First try hashed password check
            if check_password_hash(stored, password):
                session['user'] = user[1]
                session['user_id'] = user[0]
                # mark admin session if this is the admin email
                admin_email = os.environ.get('ADMIN_EMAIL', 'admin@gmail.com')
                if user[2] == admin_email:
                    session['is_admin'] = True
                return redirect('/features')
            # If hashed check fails, support legacy plaintext passwords by migrating them
            if stored == password:
                # migrate: store hashed password
                new_hash = generate_password_hash(password)
                conn = get_conn()
                c = conn.cursor()
                c.execute("UPDATE users SET password=? WHERE id=?", (new_hash, user[0]))
                conn.commit()
                conn.close()
                session['user'] = user[1]
                session['user_id'] = user[0]
                admin_email = os.environ.get('ADMIN_EMAIL', 'admin@gmail.com')
                if user[2] == admin_email:
                    session['is_admin'] = True
                return redirect('/features')

        flash('Invalid email or password. Please try again.', 'error')
        return redirect('/signin')
    return render_template('signin.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user' in session:
        return redirect('/features')
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        # store hashed password
        hashed = generate_password_hash(password)
        try:
            conn = get_conn()
            c = conn.cursor()
            c.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", (name, email, hashed))
            conn.commit()
            conn.close()
            flash('Account created successfully! Please sign in.', 'success')
            return redirect('/signin')
        except sqlite3.IntegrityError:
            flash('Email already registered. Please sign in.', 'error')
            return redirect('/signin')
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('user_id', None)
    flash('You have been logged out successfully.', 'success')
    return redirect('/signin')


@app.route('/chat')
def chat():
    # hf_key may be provided per-session (via settings) or via environment variable
    hf_key = session.get('hf_api_key') or os.environ.get('HUGGINGFACE_API_KEY')
    hf_enabled = bool(hf_key)
    model = os.environ.get('HUGGINGFACE_MODEL', 'mistralai/Mistral-7B-Instruct-v0.3')
    return render_template('chat.html', hf_enabled=hf_enabled, hf_model=model)


@app.route('/history')
def history():
    # show chat history to signed-in user
    user_id = session.get('user_id')
    if not user_id:
        flash('Please sign in to view your chat history.', 'error')
        return redirect('/signin')
    msgs = []
    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute("SELECT role, content, created_at FROM messages WHERE user_id=? ORDER BY id DESC", (user_id,))
        rows = c.fetchall()
        msgs = [{'role': r[0], 'content': r[1], 'created_at': r[2]} for r in rows]
        conn.close()
    except Exception as e:
        logger.error('Failed to load history for user %s: %s', user_id, e)
    return render_template('history.html', messages=msgs)


# ---------------------- ADMIN ----------------------
def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Admin access required.', 'error')
            return redirect('/admin/login')
        return fn(*args, **kwargs)
    return wrapper


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    # simple token-based admin login (token stored in ADMIN_TOKEN env var)
    if request.method == 'POST':
        token = request.form.get('token', '')
        admin_token = os.environ.get('ADMIN_TOKEN')
        if admin_token and token == admin_token:
            session['is_admin'] = True
            flash('Admin signed in.', 'success')
            return redirect('/admin')
        else:
            flash('Invalid admin token.', 'error')
            return redirect('/admin/login')
    return render_template('admin_login.html')


@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    flash('Admin logged out.', 'success')
    return redirect('/')


@app.route('/admin')
@admin_required
def admin():
    # show simple admin dashboard: users and recent messages
    users = []
    msgs = []
    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute('SELECT id, name, email FROM users ORDER BY id DESC')
        users = [{'id': r[0], 'name': r[1], 'email': r[2]} for r in c.fetchall()]
        c.execute('SELECT id, user_id, role, content, created_at FROM messages ORDER BY id DESC LIMIT 200')
        msgs = [{'id': r[0], 'user_id': r[1], 'role': r[2], 'content': r[3], 'created_at': r[4]} for r in c.fetchall()]
        conn.close()
    except Exception as e:
        logger.error('Admin dashboard load failed: %s', e)
    return render_template('admin.html', users=users, messages=msgs)


@app.route('/admin/export')
@admin_required
def admin_export():
    # export all messages as CSV
    import csv
    from io import StringIO
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['id', 'user_id', 'role', 'content', 'created_at'])
    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute('SELECT id, user_id, role, content, created_at FROM messages ORDER BY id')
        for r in c.fetchall():
            writer.writerow(r)
        conn.close()
    except Exception as e:
        logger.error('Export failed: %s', e)
        flash('Export failed', 'error')
        return redirect('/admin')
    output = si.getvalue()
    return (output, 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename="messages.csv"'
    })


@app.route('/admin/prune', methods=['POST'])
@admin_required
def admin_prune():
    # prune messages older than X days (POST form: days)
    try:
        days = int(request.form.get('days', '30'))
    except Exception:
        days = 30
    cutoff = now_ist() - timedelta(days=days)
    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute('DELETE FROM messages WHERE created_at < ?', (cutoff.isoformat(),))
        deleted = c.rowcount
        conn.commit()
        conn.close()
        flash(f'Pruned {deleted} messages older than {days} days.', 'success')
    except Exception as e:
        logger.error('Prune failed: %s', e)
        flash('Prune failed', 'error')
    return redirect('/admin')


@app.route('/api/chat', methods=['POST'])
def api_chat():
    data = request.get_json() or {}
    message = data.get('message', '')
    if not message:
        return jsonify({'error': 'No message provided'}), 400

    # Check per-session key first, then environment
    hf_key = session.get('hf_api_key') or os.environ.get('HUGGINGFACE_API_KEY')
    model = os.environ.get('HUGGINGFACE_MODEL', 'gpt2')
    # persist incoming message to DB
    user_id = session.get('user_id')
    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute("INSERT INTO messages (user_id, role, content, created_at) VALUES (?, ?, ?, ?)",
                  (user_id, 'user', message, now_ist().isoformat()))
        conn.commit()
    except Exception:
        # ignore DB errors for now but continue
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass
    if hf_key:
        url = f'https://api-inference.huggingface.co/models/{model}'
        headers = {"Authorization": f"Bearer {hf_key}"}
        payload = {"inputs": message, "parameters": {"max_new_tokens": 150}}
        logger.info("HF request: model=%s user_id=%s message_len=%d", model, user_id, len(message))
        try:
            r = requests.post(url, headers=headers, json=payload, timeout=30)
            logger.info("HF response status: %s", r.status_code)
            r.raise_for_status()
            resp = r.json()
            logger.info("HF response (truncated): %s", str(resp)[:1000])
            if isinstance(resp, list) and isinstance(resp[0], dict) and 'generated_text' in resp[0]:
                text = resp[0]['generated_text']
            elif isinstance(resp, dict) and 'generated_text' in resp:
                text = resp['generated_text']
            elif isinstance(resp, dict) and 'error' in resp:
                text = f"API error: {resp['error']}"
            else:
                text = str(resp)
            # store bot reply
            try:
                conn = get_conn()
                c = conn.cursor()
                c.execute("INSERT INTO messages (user_id, role, content, created_at) VALUES (?, ?, ?, ?)",
                          (user_id, 'bot', text, now_ist().isoformat()))
                conn.commit()
                conn.close()
            except Exception:
                pass
            return jsonify({'reply': text})
        except Exception as e:
            # Log full traceback to server logs for debugging
            logger.error("HF API call failed: %s", e)
            logger.error(traceback.format_exc())
            # Return a helpful error to the client
            return jsonify({'error': 'External AI service error', 'details': str(e)}), 500
    else:
        # Local rule-based chatbot (no API key required)
        # Safe math evaluation using ast (only arithmetic)
        def safe_eval(expr: str):
            # supported operators
            allowed_ops = {
                ast.Add: op.add,
                ast.Sub: op.sub,
                ast.Mult: op.mul,
                ast.Div: op.truediv,
                ast.Pow: op.pow,
                ast.BitXor: op.xor,
                ast.USub: op.neg,
                ast.Mod: op.mod,
            }

            def _eval(node):
                if isinstance(node, ast.Num):  # <number>
                    return node.n
                if isinstance(node, ast.BinOp):
                    left = _eval(node.left)
                    right = _eval(node.right)
                    op_type = type(node.op)
                    if op_type in allowed_ops:
                        return allowed_ops[op_type](left, right)
                if isinstance(node, ast.UnaryOp):
                    operand = _eval(node.operand)
                    op_type = type(node.op)
                    if op_type in allowed_ops:
                        return allowed_ops[op_type](operand)
                raise ValueError('Unsupported expression')

            node = ast.parse(expr, mode='eval')
            return _eval(node.body)

        # small knowledge base
        KB = {
            'recursion': 'Recursion is a method of solving a problem where the solution depends on solutions to smaller instances of the same problem.',
            'algorithm': 'An algorithm is a step-by-step procedure for calculations. It is a set of rules to be followed in problem-solving operations.'
        }

        def generate_local_reply(text: str) -> str:
            t = text.strip()
            tl = t.lower()
            # greetings
            if any(g in tl for g in ("hi", "hello", "hey")):
                return "Hi there! I'm your local assistant — how can I help you today?"
            if "how are you" in tl or "how r you" in tl:
                return "I'm a simple assistant running on this server — ready to help!"
            if "time" in tl or "date" in tl:
                return f"Current server time is {now_ist().strftime('%Y-%m-%d %H:%M:%S %Z')}"
            if "name" in tl and "your" in tl:
                return "I'm Student Assistant's built-in chatbot. You can call me Assistant."
            if "help" in tl or "features" in tl:
                return "I can answer simple questions, solve basic math, store chat history while you are signed in, and use an advanced AI if you provide a Hugging Face API key."
            if "joke" in tl:
                return "Why did the programmer quit his job? Because he didn't get arrays. 😄"

            # knowledge base lookup
            if tl.startswith('what is') or tl.startswith('define') or tl.startswith('explain'):
                # remove question words
                q = tl.replace('what is', '').replace('define', '').replace('explain', '').strip(' ?')
                if q in KB:
                    return KB[q]
                # try math evaluation
                try:
                    # allow simple math expressions like '7+9' or '2 ** 10'
                    val = safe_eval(q)
                    return str(val)
                except Exception:
                    pass

            # pure arithmetic detection (e.g., '7+9', '12 / 4')
            import re
            if re.fullmatch(r"[0-9\s\.\+\-\*\/\%\^\(\)]+", t):
                try:
                    # replace ^ with ** for power
                    expr = t.replace('^', '**')
                    val = safe_eval(expr)
                    return str(val)
                except Exception:
                    pass

            # fallback: ask for more detail
            if len(tl) < 4:
                return "Could you give a bit more detail?"
            return f"You said: '{text}'. I can give a better reply if you provide more context or set up an advanced AI key."

        reply = generate_local_reply(message)
        # persist bot reply
        try:
            conn = get_conn()
            c = conn.cursor()
            c.execute("INSERT INTO messages (user_id, role, content, created_at) VALUES (?, ?, ?, ?)",
                      (user_id, 'bot', reply, now_ist().isoformat()))
            conn.commit()
            conn.close()
        except Exception:
            pass
        return jsonify({'reply': reply})

# ---------------------- RUN APP ----------------------
if __name__ == '__main__':
    app.run(debug=True)
