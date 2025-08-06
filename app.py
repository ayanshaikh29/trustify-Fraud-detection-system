from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, flash, session
)
import sqlite3
import datetime
import re
from functools import wraps

from werkzeug.security import check_password_hash, generate_password_hash
from model_train import detect_fraud  # your prediction function here

app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.secret_key = 'your_secret_key_here'  # Change to a strong secret!

def get_db():
    conn = sqlite3.connect('fraud.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                amount REAL NOT NULL,
                time REAL NOT NULL,
                result TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()

init_db()

# Optional: Decorator for login required routes (if you want to add restrictions later)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ================= Home
@app.route('/')
@app.route('/home')
def home():
    logged_in = 'username' in session
    return render_template('home.html', logged_in=logged_in)

# ================= Login@app.route('/login', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        flash('Already logged in.', 'info')
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash('Please fill in all fields.', 'warning')
            return redirect(url_for('login'))

        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT password FROM users WHERE username=?", (username,))
            row = c.fetchone()

        if row is not None and check_password_hash(row['password'], password):
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))

    # Show login form if GET or failed POST
    return render_template('login.html')


# ================= Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not email or not password:
            flash('Please fill out all fields.', 'danger')
            return redirect(url_for('register'))

        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address.', 'danger')
            return redirect(url_for('register'))

        if not re.match(r'^[A-Za-z0-9]+$', username):
            flash('Username must contain only letters and numbers.', 'danger')
            return redirect(url_for('register'))

        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username=? OR email=?", (username, email))
            if c.fetchone():
                flash('Account with that username or email already exists.', 'danger')
                return redirect(url_for('register'))

            hashed_password = generate_password_hash(password)
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                      (username, email, hashed_password))
            conn.commit()

            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

# ================= Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


@app.route('/predict', methods=['GET', 'POST'])
def predict():
    result = None
    if request.method == 'POST':
        try:
            amount = float(request.form['amount'])
            time_val = float(request.form['time'])  # 0-24
            if amount <= 0:
                result = "❌ Amount must be positive."
            elif not (0 <= time_val <= 24):
                result = "❌ Time must be between 0 and 24 hours."
            else:
                raw_result = detect_fraud(amount, time_val)
                result = raw_result

                simple_result = "🚨 Fraud Detected!" if "Fraud" in raw_result else "✅ Transaction is Legitimate"

                with get_db() as conn:
                    c = conn.cursor()
                    c.execute('''
                        INSERT INTO predictions (amount, time, result, timestamp)
                        VALUES (?, ?, ?, ?)
                    ''', (amount, time_val, simple_result, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                    conn.commit()
        except Exception as e:
            result = f"❌ Error: {str(e)}"
    return render_template('predict.html', result=result)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@app.route('/history')
def history():
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT amount, time, result, timestamp FROM predictions ORDER BY timestamp DESC")
            records = c.fetchall()
    except Exception as e:
        print("DB Error:", e)
        records = []
    return render_template('history.html', records=records)


@app.route('/api/pie')
def pie():
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM predictions WHERE result='🚨 Fraud Detected!'")
        frauds = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM predictions WHERE result='✅ Transaction is Legitimate'")
        legits = c.fetchone()[0]
    return jsonify({"labels": ["Legitimate", "Fraud"], "values": [legits, frauds]})


@app.route('/api/bar')
def bar():
    hourly = [0]*24
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT time FROM predictions WHERE result='🚨 Fraud Detected!'")
        for (h,) in c.fetchall():
            idx = int(float(h)) if 0 <= h < 24 else 0
            hourly[idx] += 1
    return jsonify({"hours": list(range(24)), "fraud_counts": hourly})


@app.route('/api/table')
def table():
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT amount, time, result, timestamp FROM predictions ORDER BY timestamp DESC LIMIT 10")
        records = c.fetchall()
    return jsonify({"records": [tuple(row) for row in records]})


@app.route('/api/line')
def line_chart_data():
    # Dummy example data; adapt for your dataset
    data = {
        "labels": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        "values": [5, 8, 6, 9, 12, 7, 4]
    }
    return jsonify(data)


@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store"
    return response


if __name__ == '__main__':
    app.run(debug=True)
