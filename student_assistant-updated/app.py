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
app.secret_key = os.environ.get('FLASK_SECRET', 'your_secret_key')
# Database path configurable for tests/dev
DB_PATH = os.environ.get('DB_PATH', 'users.db')
IST = timezone(timedelta(hours=5, minutes=30), name='IST')

# Session and cookie security defaults (adjust via env in production)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax'),
)
# allow turning on secure cookie flag via env (useful in HTTPS deployments)
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() in ('1', 'true', 'yes')


@app.after_request
def set_security_headers(response):
    # Basic security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    return response

def now_utc():
    return datetime.now(timezone.utc)

def now_ist():
    return datetime.now(IST)

def utc_to_ist(iso_str: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        ist = dt.astimezone(IST)
        return ist.strftime('%Y-%m-%d %H:%M:%S %Z')
    except Exception:
        return iso_str

def get_conn():
    return sqlite3.connect(DB_PATH)


# Simple login_required decorator used for page routes (redirects to signin)
def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please sign in to access that feature.', 'error')
            return redirect('/signin')
        return fn(*args, **kwargs)
    return wrapper

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
    c.execute('''
        CREATE TABLE IF NOT EXISTS assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            due_date TEXT NOT NULL,
            status TEXT DEFAULT 'pending' NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    # Add status column to existing assignments table if it doesn't exist
    c.execute("PRAGMA table_info(assignments)")
    columns = [col[1] for col in c.fetchall()]
    if 'status' not in columns:
        c.execute("ALTER TABLE assignments ADD COLUMN status TEXT DEFAULT 'pending' NOT NULL")
        logger.info("Added 'status' column to 'assignments' table.")
    c.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS schedule_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            time TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS goals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            target_date TEXT NOT NULL,
            status TEXT DEFAULT 'pending' NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    # Add status column to existing goals table if it doesn't exist
    c.execute("PRAGMA table_info(goals)")
    columns = [col[1] for col in c.fetchall()]
    if 'status' not in columns:
        c.execute("ALTER TABLE goals ADD COLUMN status TEXT DEFAULT 'pending' NOT NULL")
        logger.info("Added 'status' column to 'goals' table.")
    c.execute('''
        CREATE TABLE IF NOT EXISTS reminders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            time TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS group_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER,
            user_id INTEGER,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(group_id) REFERENCES groups(id),
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
        logger.info("Contact form received from %s (%s): %s", name, email, message)
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

@app.route('/assignment-tracker', methods=['GET', 'POST'])
@login_required
def assignment_tracker():
    if 'user_id' not in session:
        flash('Please sign in to use this feature.', 'error')
        return redirect('/signin')
    user_id = session['user_id']
    conn = get_conn()
    c = conn.cursor()
    if request.method == 'POST':
        # form submission creates an assignment (used by browser forms/tests)
        name = request.form.get('assignment_name') or request.form.get('name')
        due_date = request.form.get('due_date')
        if name and due_date:
            c.execute("INSERT INTO assignments (user_id, name, due_date) VALUES (?, ?, ?)", (user_id, name, due_date))
            conn.commit()
            flash('Assignment added.', 'success')
            # fall through to render page (tests use follow_redirects)
    c.execute("SELECT * FROM assignments WHERE user_id=?", (user_id,))
    assignments = c.fetchall()
    conn.close()
    return render_template('assignment-tracker.html', assignments=[{'id': a[0], 'name': a[2], 'due_date': a[3]} for a in assignments])

@app.route('/api/assignments', methods=['POST'])
def add_assignment():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user_id = session['user_id']
    data = request.get_json()
    name = data.get('name')
    due_date = data.get('due_date')

    if not name or not due_date:
        return jsonify({'error': 'Missing name or due_date'}), 400

    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO assignments (user_id, name, due_date) VALUES (?, ?, ?)", (user_id, name, due_date))
    new_assignment_id = c.lastrowid
    conn.commit()
    conn.close()

    return jsonify({'id': new_assignment_id, 'name': name, 'due_date': due_date}), 201

@app.route('/api/assignments/<int:assignment_id>', methods=['DELETE'])
def delete_assignment(assignment_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user_id = session['user_id']
    conn = get_conn()
    c = conn.cursor()
    c.execute("DELETE FROM assignments WHERE id=? AND user_id=?", (assignment_id, user_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Assignment deleted successfully'}), 200


@app.route('/delete-assignment/<int:assignment_id>', methods=['POST'])
def delete_assignment_form(assignment_id):
    if 'user_id' not in session:
        flash('Please sign in to use this feature.', 'error')
        return redirect('/signin')
    user_id = session['user_id']
    conn = get_conn()
    c = conn.cursor()
    c.execute("DELETE FROM assignments WHERE id=? AND user_id=?", (assignment_id, user_id))
    conn.commit()
    conn.close()
    flash('Assignment deleted.', 'success')
    return redirect('/assignment-tracker')

# New API endpoint for updating assignment status
@app.route('/api/assignments/<int:assignment_id>/status', methods=['POST'])
def update_assignment_status(assignment_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user_id = session['user_id']
    data = request.get_json()
    status = data.get('status')
    
    if status not in ['pending', 'completed']:
        return jsonify({'error': 'Invalid status'}), 400

    conn = get_conn()
    c = conn.cursor()
    c.execute("UPDATE assignments SET status=? WHERE id=? AND user_id=?", (status, assignment_id, user_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Assignment status updated successfully'}), 200


@app.route('/group-collaboration', methods=['GET', 'POST'])
@login_required
def group_collaboration():
    conn = get_conn()
    c = conn.cursor()
    if request.method == 'POST':
        name = request.form['group_name']
        c.execute("INSERT INTO groups (name) VALUES (?)", (name,))
        conn.commit()
        flash('Group created successfully!', 'success')
        return redirect('/group-collaboration')
    c.execute("SELECT * FROM groups")
    groups = c.fetchall()
    conn.close()
    return render_template('group-collaboration.html', groups=[{'id': g[0], 'name': g[1]} for g in groups])

@app.route('/group/<int:group_id>', methods=['GET', 'POST'])
@login_required
def group(group_id):
    if 'user_id' not in session:
        flash('Please sign in to use this feature.', 'error')
        return redirect('/signin')
    user_id = session['user_id']
    conn = get_conn()
    c = conn.cursor()
    if request.method == 'POST':
        message = request.form['message']
        c.execute("INSERT INTO group_messages (group_id, user_id, role, content, created_at) VALUES (?, ?, ?, ?, ?)",
              (group_id, user_id, 'user', message, now_utc().isoformat()))
        conn.commit()
        flash('Message sent successfully!', 'success')
        return redirect(f'/group/{group_id}')
    c.execute("SELECT * FROM groups WHERE id=?", (group_id,))
    group = c.fetchone()
    c.execute("SELECT gm.id, gm.group_id, gm.user_id, gm.role, gm.content, gm.created_at, u.name FROM group_messages gm JOIN users u ON gm.user_id = u.id WHERE gm.group_id=? ORDER BY gm.created_at", (group_id,))
    rows = c.fetchall()
    messages = []
    for m in rows:
        created = m[5]
        created_display = utc_to_ist(created) if created else ''
        messages.append({'role': m[3], 'content': m[4], 'created_at': created_display, 'username': m[6]})
    conn.close()
    return render_template('group.html', group={'id': group[0], 'name': group[1]}, messages=messages)

@app.route('/schedule-planner', methods=['GET', 'POST'])
@login_required
def schedule_planner():
    if 'user_id' not in session:
        flash('Please sign in to use this feature.', 'error')
        return redirect('/signin')
    user_id = session['user_id']
    conn = get_conn()
    c = conn.cursor()
    if request.method == 'POST':
        name = request.form.get('event_name') or request.form.get('name')
        time = request.form.get('event_time') or request.form.get('time')
        if name and time:
            c.execute("INSERT INTO schedule_events (user_id, name, time) VALUES (?, ?, ?)", (user_id, name, time))
            conn.commit()
            flash('Event added.', 'success')
    c.execute("SELECT * FROM schedule_events WHERE user_id=?", (user_id,))
    events = c.fetchall()
    conn.close()

    def _format_time(t):
        if not t:
            return ''
        try:
            # ISO format like '2025-11-23T05:00' or '2025-11-23 05:00:00'
            if 'T' in t:
                dt = datetime.fromisoformat(t)
            else:
                dt = datetime.fromisoformat(t)
            return dt.strftime('%d-%m-%Y %H:%M')
        except Exception:
            try:
                # fallback common format
                dt = datetime.strptime(t, '%Y-%m-%d %H:%M:%S')
                return dt.strftime('%d-%m-%Y %H:%M')
            except Exception:
                return t

    rendered_events = []
    for e in events:
        time_raw = e[3]
        rendered_events.append({'id': e[0], 'name': e[2], 'time': time_raw, 'formatted_time': _format_time(time_raw)})

    return render_template('schedule-planner.html', events=rendered_events)

@app.route('/api/schedule-events', methods=['POST'])
def add_event():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user_id = session['user_id']
    data = request.get_json()
    name = data.get('name')
    time = data.get('time')

    if not name or not time:
        return jsonify({'error': 'Missing name or time'}), 400

    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO schedule_events (user_id, name, time) VALUES (?, ?, ?)", (user_id, name, time))
    new_event_id = c.lastrowid
    conn.commit()
    conn.close()

    # prepare formatted time for client
    formatted = None
    try:
        if 'T' in time:
            dt = datetime.fromisoformat(time)
        else:
            dt = datetime.fromisoformat(time)
        formatted = dt.strftime('%d-%m-%Y %H:%M')
    except Exception:
        try:
            dt = datetime.strptime(time, '%Y-%m-%d %H:%M:%S')
            formatted = dt.strftime('%d-%m-%Y %H:%M')
        except Exception:
            formatted = time

    return jsonify({'id': new_event_id, 'name': name, 'time': time, 'formatted_time': formatted}), 201

@app.route('/api/schedule-events/<int:event_id>', methods=['DELETE'])
def delete_event(event_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user_id = session['user_id']
    conn = get_conn()
    c = conn.cursor()
    c.execute("DELETE FROM schedule_events WHERE id=? AND user_id=?", (event_id, user_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Event deleted successfully'}), 200


@app.route('/delete-event/<int:event_id>', methods=['POST'])
def delete_event_form(event_id):
    if 'user_id' not in session:
        flash('Please sign in to use this feature.', 'error')
        return redirect('/signin')
    user_id = session['user_id']
    conn = get_conn()
    c = conn.cursor()
    c.execute("DELETE FROM schedule_events WHERE id=? AND user_id=?", (event_id, user_id))
    conn.commit()
    conn.close()
    flash('Event deleted.', 'success')
    return redirect('/schedule-planner')

@app.route('/goal-tracker', methods=['GET', 'POST'])
@login_required
def goal_tracker():
    if 'user_id' not in session:
        flash('Please sign in to use this feature.', 'error')
        return redirect('/signin')
    user_id = session['user_id']
    conn = get_conn()
    c = conn.cursor()
    if request.method == 'POST':
        name = request.form.get('goal_name') or request.form.get('name')
        target_date = request.form.get('target_date')
        if name and target_date:
            c.execute("INSERT INTO goals (user_id, name, target_date) VALUES (?, ?, ?)", (user_id, name, target_date))
            conn.commit()
            flash('Goal added.', 'success')
    c.execute("SELECT * FROM goals WHERE user_id=?", (user_id,))
    goals = c.fetchall()
    conn.close()
    return render_template('goal-tracker.html', goals=[{'id': g[0], 'name': g[2], 'target_date': g[3]} for g in goals])

@app.route('/api/goals', methods=['POST'])
def add_goal():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user_id = session['user_id']
    data = request.get_json()
    name = data.get('name')
    target_date = data.get('target_date')

    if not name or not target_date:
        return jsonify({'error': 'Missing name or target_date'}), 400

    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO goals (user_id, name, target_date) VALUES (?, ?, ?)", (user_id, name, target_date))
    new_goal_id = c.lastrowid
    conn.commit()
    conn.close()

    return jsonify({'id': new_goal_id, 'name': name, 'target_date': target_date}), 201

@app.route('/api/goals/<int:goal_id>', methods=['DELETE'])
def delete_goal(goal_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user_id = session['user_id']
    conn = get_conn()
    c = conn.cursor()
    c.execute("DELETE FROM goals WHERE id=? AND user_id=?", (goal_id, user_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Goal deleted successfully'}), 200


@app.route('/delete-goal/<int:goal_id>', methods=['POST'])
def delete_goal_form(goal_id):
    if 'user_id' not in session:
        flash('Please sign in to use this feature.', 'error')
        return redirect('/signin')
    user_id = session['user_id']
    conn = get_conn()
    c = conn.cursor()
    c.execute("DELETE FROM goals WHERE id=? AND user_id=?", (goal_id, user_id))
    conn.commit()
    conn.close()
    flash('Goal deleted.', 'success')
    return redirect('/goal-tracker')

# New API endpoint for updating goal status
@app.route('/api/goals/<int:goal_id>/status', methods=['POST'])
def update_goal_status(goal_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user_id = session['user_id']
    data = request.get_json()
    status = data.get('status')
    
    if status not in ['pending', 'completed']:
        return jsonify({'error': 'Invalid status'}), 400

    conn = get_conn()
    c = conn.cursor()
    c.execute("UPDATE goals SET status=? WHERE id=? AND user_id=?", (status, goal_id, user_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Goal status updated successfully'}), 200

@app.route('/smart-reminders', methods=['GET', 'POST'])
@login_required
def smart_reminders():
    if 'user_id' not in session:
        flash('Please sign in to use this feature.', 'error')
        return redirect('/signin')
    user_id = session['user_id']
    conn = get_conn()
    c = conn.cursor()
    if request.method == 'POST':
        name = request.form.get('reminder_name') or request.form.get('name')
        time = request.form.get('reminder_time') or request.form.get('time')
        if name and time:
            c.execute("INSERT INTO reminders (user_id, name, time) VALUES (?, ?, ?)", (user_id, name, time))
            conn.commit()
            flash('Reminder added.', 'success')
    c.execute("SELECT * FROM reminders WHERE user_id=?", (user_id,))
    reminders = c.fetchall()
    conn.close()
    return render_template('smart-reminders.html', reminders=[{'id': r[0], 'name': r[2], 'time': r[3]} for r in reminders])

@app.route('/api/reminders', methods=['POST'])
def add_reminder():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user_id = session['user_id']
    data = request.get_json()
    name = data.get('name')
    time = data.get('time')

    if not name or not time:
        return jsonify({'error': 'Missing name or time'}), 400

    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO reminders (user_id, name, time) VALUES (?, ?, ?)", (user_id, name, time))
    new_reminder_id = c.lastrowid
    conn.commit()
    conn.close()

    return jsonify({'id': new_reminder_id, 'name': name, 'time': time}), 201

@app.route('/api/reminders/<int:reminder_id>', methods=['DELETE'])
def delete_reminder(reminder_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user_id = session['user_id']
    conn = get_conn()
    c = conn.cursor()
    c.execute("DELETE FROM reminders WHERE id=? AND user_id=?", (reminder_id, user_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Reminder deleted successfully'}), 200


@app.route('/delete-reminder/<int:reminder_id>', methods=['POST'])
def delete_reminder_form(reminder_id):
    if 'user_id' not in session:
        flash('Please sign in to use this feature.', 'error')
        return redirect('/signin')
    user_id = session['user_id']
    conn = get_conn()
    c = conn.cursor()
    c.execute("DELETE FROM reminders WHERE id=? AND user_id=?", (reminder_id, user_id))
    conn.commit()
    conn.close()
    flash('Reminder deleted.', 'success')
    return redirect('/smart-reminders')

@app.route('/api/performance-data')
def get_performance_data():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user_id = session['user_id']
    conn = get_conn()
    c = conn.cursor()

    # Get assignment data
    c.execute("SELECT status, COUNT(*) FROM assignments WHERE user_id=? GROUP BY status", (user_id,))
    assignment_stats = {row[0]: row[1] for row in c.fetchall()}
    total_assignments = sum(assignment_stats.values())
    completed_assignments = assignment_stats.get('completed', 0)
    pending_assignments = assignment_stats.get('pending', 0)

    # Get goal data
    c.execute("SELECT status, COUNT(*) FROM goals WHERE user_id=? GROUP BY status", (user_id,))
    goal_stats = {row[0]: row[1] for row in c.fetchall()}
    total_goals = sum(goal_stats.values())
    completed_goals = goal_stats.get('completed', 0)
    pending_goals = goal_stats.get('pending', 0)

    conn.close()

    return jsonify({
        'assignments': {
            'total': total_assignments,
            'completed': completed_assignments,
            'pending': pending_assignments
        },
        'goals': {
            'total': total_goals,
            'completed': completed_goals,
            'pending': pending_goals
        }
    }), 200

@app.route('/performance-analytics')
@login_required
def performance_analytics():
    return render_template('performance-analytics.html')

def _set_session(user):
    session['user'] = user[1]
    session['user_id'] = user[0]
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@gmail.com')
    if user[2] == admin_email:
        session['is_admin'] = True

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
                _set_session(user)
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
                _set_session(user)
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
@login_required
def chat():
    # hf_key may be provided per-session (via settings) or via environment variable
    hf_key = session.get('hf_api_key') or os.environ.get('HUGGINGFACE_API_KEY')
    hf_enabled = bool(hf_key)
    model = os.environ.get('HUGGINGFACE_MODEL', 'mistralai/Mistral-7B-Instruct-v0.3')
    return render_template('chat.html', hf_enabled=hf_enabled, hf_model=model)


@app.route('/history')
@login_required
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
        msgs = []
        for r in rows:
            created = r[2]
            created_display = utc_to_ist(created) if created else ''
            msgs.append({'role': r[0], 'content': r[1], 'created_at': created_display})
        conn.close()
    except Exception as e:
        logger.error('Failed to load history for user %s: %s', user_id, e)
    return render_template('history.html', messages=msgs)


@app.route('/api/history')
def api_history():
    # return recent chat messages for signed-in user as JSON (newest first)
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute("SELECT role, content, created_at FROM messages WHERE user_id=? ORDER BY id DESC LIMIT 200", (user_id,))
        rows = c.fetchall()
        msgs = []
        for r in rows:
            created = r[2]
            created_display = utc_to_ist(created) if created else ''
            msgs.append({'role': r[0], 'content': r[1], 'created_at': created_display})
        conn.close()
        return jsonify({'messages': msgs})
    except Exception as e:
        logger.error('Failed to load history for API: %s', e)
        return jsonify({'error': 'Failed to load history'}), 500


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


def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please sign in to access that feature.', 'error')
            return redirect('/signin')
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
        msgs = []
        for r in c.fetchall():
            created = r[4]
            created_display = utc_to_ist(created) if created else ''
            msgs.append({'id': r[0], 'user_id': r[1], 'role': r[2], 'content': r[3], 'created_at': created_display})
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
    return (
        output,
        200,
        {
            'Content-Type': 'text/csv',
            'Content-Disposition': 'attachment; filename="messages.csv"'
        }
    )


@app.route('/admin/prune', methods=['POST'])
@admin_required
def admin_prune():
    # prune messages older than X days (POST form: days)
    try:
        days = int(request.form.get('days', '30'))
    except Exception:
        days = 30
    cutoff = now_utc() - timedelta(days=days)
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
                  (user_id, 'user', message, now_utc().isoformat()))
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
            # store bot reply with timestamp and return it to client
            try:
                ts = now_utc().isoformat()
                conn = get_conn()
                c = conn.cursor()
                c.execute("INSERT INTO messages (user_id, role, content, created_at) VALUES (?, ?, ?, ?)",
                          (user_id, 'bot', text, ts))
                conn.commit()
                conn.close()
            except Exception:
                ts = now_utc().isoformat()
            return jsonify({'reply': text, 'timestamp': utc_to_ist(ts)})
        except requests.exceptions.RequestException as e:
            logger.error("HF API call failed: %s", e)
            return jsonify({'error': 'External AI service is currently unavailable. Please try again later.', 'details': str(e)}), 503
        except Exception as e:
            # Log full traceback to server logs for debugging
            logger.error("HF API call failed: %s", e)
            logger.error(traceback.format_exc())
            # Return a helpful error to the client
            return jsonify({'error': 'An unexpected error occurred with the external AI service.', 'details': str(e)}), 500
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
                if isinstance(node, ast.Constant):  # <number>
                    if isinstance(node.value, (int, float)):
                        return node.value
                    raise ValueError('Unsupported constant')
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
            t = text.strip().lower()

            rules = {
                "greetings": (["hi", "hello", "hey"], "Hi there! I'm your local assistant — how can I help you today?"),
                "how_are_you": (["how are you", "how r you"], "I'm a simple assistant running on this server — ready to help!"),
                "time": (["time", "date"], f"Current server time is {now_ist().strftime('%Y-%m-%d %H:%M:%S %Z')}"),
                "name": (["name", "your"], "I'm Student Assistant's built-in chatbot. You can call me Assistant."),
                "help": (["help", "features"], "I can answer simple questions, solve basic math, store chat history while you are signed in, and use an advanced AI if you provide a Hugging Face API key."),
                "joke": (["joke"], "Why did the programmer quit his job? Because he didn't get arrays. 😄"),
            }

            for key, (keywords, response) in rules.items():
                if any(keyword in t for keyword in keywords):
                    return response

            # knowledge base lookup
            if t.startswith(('what is', 'define', 'explain')):
                q = t.replace('what is', '').replace('define', '').replace('explain', '').strip(' ?')
                if q in KB:
                    return KB[q]
                try:
                    val = safe_eval(q)
                    return str(val)
                except Exception:
                    pass

            # pure arithmetic detection
            import re
            if re.fullmatch(r"[0-9\s\.\+\-\*\/\%\^\(\)]+", t):
                try:
                    expr = t.replace('^', '**')
                    val = safe_eval(expr)
                    return str(val)
                except Exception:
                    pass

            if len(t) < 4:
                return "Could you give a bit more detail?"
            return f"You said: '{text}'. I can give a better reply if you provide more context or set up an advanced AI key."

        reply = generate_local_reply(message)
        # persist bot reply and return timestamp
        try:
            ts = now_utc().isoformat()
            conn = get_conn()
            c = conn.cursor()
            c.execute("INSERT INTO messages (user_id, role, content, created_at) VALUES (?, ?, ?, ?)",
                      (user_id, 'bot', reply, ts))
            conn.commit()
            conn.close()
        except Exception:
            ts = now_utc().isoformat()
        return jsonify({'reply': reply, 'timestamp': utc_to_ist(ts)})

# ---------------------- RUN APP ----------------------
if __name__ == '__main__':
    app.run(debug=True)