from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure key in production

# Initialize SQLite database
def init_db():
    if not os.path.exists('users.db'):
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

init_db()

# Home page
@app.route('/')
def home():
    return render_template('index.html')

# Features page (requires login)
@app.route('/features')
def features():
    if 'user' in session:
        return render_template('features.html', user=session['user'])
    return redirect('/signin')

# About page
@app.route('/about')
def about():
    return render_template('about.html')

# Contact page
@app.route('/contact')
def contact():
    return render_template('contact.html')

# Profile page
@app.route('/profile')
def profile():
    return render_template('profile.html')

# Settings page
@app.route('/settings')
def settings():
    return render_template('settings.html')

# Under Construction page
@app.route('/under-construction')
def under_construction():
    return render_template('under-construction.html')

# Sign In
@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=? AND password=?", (email, password))
        user = c.fetchone()
        conn.close()
        if user:
            session['user'] = user[1]  # Store name in session
            return redirect('/features')
        else:
            return "Invalid email or password"
    return render_template('signin.html')

# Sign Up
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", (name, email, password))
            conn.commit()
            conn.close()
            return redirect('/signin')
        except sqlite3.IntegrityError:
            return "Email already registered"
    return render_template('signup.html')

# Logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/signin')

if __name__ == '__main__':
    app.run(debug=True)
