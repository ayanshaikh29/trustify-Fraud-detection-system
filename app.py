# app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
import sqlite3
import datetime
import re
import os
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
from model_train import detect_fraud, ensure_model_ready  # your ML helpers

# ================= Flask App Config =================
app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.secret_key = os.environ.get('TRUSTIFY_SECRET', 'trust@trust')

# ================= Absolute Paths =================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'fraud.db')

print(f"📂 Using Database: {DB_PATH}")

# ================= SQLite Utilities =================
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# ================= DB Init & Helpers =================
def add_trusted_upis():
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS trusted_upis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                upi_id TEXT UNIQUE NOT NULL
            )
        ''')
        trusted_upis = [
            "paytm@upi", "phonepe@upi", "gpay@okicici", "gpay@okhdfcbank",
            "icici@upi", "sbi@upi", "axisbank@upi", "hdfcbank@upi",
            "amazonpay@apl", "ybl@upi", "okaxis@upi", "okicici@upi",
            "okhdfcbank@upi", "okbizaxis@upi", "airtel@upi"
        ]
        for upi in trusted_upis:
            c.execute("INSERT OR IGNORE INTO trusted_upis (upi_id) VALUES (?)", (upi,))
        conn.commit()
    finally:
        conn.close()
    print("✅ Trusted UPIs ensured in DB.")

def init_db():
    if not os.path.exists(DB_PATH):
        print("⚠️ Database not found — creating new DB…")
        conn = get_db()
        try:
            c = conn.cursor()
            c.execute('''
                CREATE TABLE predictions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    upi_id TEXT,
                    utr TEXT,
                    amount REAL NOT NULL DEFAULT 0,
                    hour INTEGER NOT NULL DEFAULT 0,
                    known_upi INTEGER,
                    location_match INTEGER,
                    purpose TEXT,
                    frequency INTEGER,
                    result TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
            ''')
            c.execute('''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )
            ''')
            c.execute('''
                CREATE TABLE trusted_upis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    upi_id TEXT UNIQUE NOT NULL
                )
            ''')
            conn.commit()
        finally:
            conn.close()
        print("✅ New DB created.")
    else:
        print("✅ Existing DB found.")

# ================= Auth Decorator =================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ================= Utilities =================
def parse_amount(value):
    try:
        return round(float(value), 2)
    except Exception:
        return 0.0

def parse_hour(value):
    try:
        h = int(value)
        return h if 0 <= h <= 23 else datetime.datetime.now().hour
    except Exception:
        return datetime.datetime.now().hour

# ================= Routes =================
@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html', logged_in=('username' in session))

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

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['email'] = user['email']
            session['user_id'] = user['id']
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

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

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? OR email=?", (username, email))
        if c.fetchone():
            conn.close()
            flash('Account with that username or email already exists.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", 
                  (username, email, hashed_password))
        conn.commit()
        conn.close()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session_keys = ['username', 'email', 'user_id']
    for k in session_keys:
        session.pop(k, None)
    flash("Logged out successfully!", "info")
    return redirect(url_for("home"))

@app.route('/predict', methods=['GET', 'POST'])
@login_required
def predict():
    result = None
    form_data = {
        'upi_id': '',
        'utr': '',
        'amount': '',
        'hour': datetime.datetime.now().hour,
        'location_match': '',
        'purpose': '',
        'frequency': ''
    }
    if request.method == 'POST':
        for k in form_data:
            form_data[k] = request.form.get(k, '')

        amount = parse_amount(form_data['amount'])
        hour = parse_hour(form_data['hour'])
        location_match = int(form_data.get('location_match') or 0)
        frequency = int(form_data.get('frequency') or 0)

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT upi_id FROM trusted_upis")
        trusted_list = {row['upi_id'].lower() for row in c.fetchall()}
        conn.close()
        known_upi = 1 if form_data['upi_id'].lower() in trusted_list else 0

        utr_valid = True
        utr_reason = ""
        if form_data['utr']:
            if not (6 <= len(form_data['utr']) <= 50):
                utr_valid = False
                utr_reason = "⚠️ Invalid UTR length."
            elif not re.match(r'^[A-Za-z0-9\-]+$', form_data['utr']):
                utr_valid = False
                utr_reason = "⚠️ UTR contains invalid characters."

        if amount <= 0:
            result = "❌ Amount must be positive."
        elif not (0 <= int(hour) <= 23):
            result = "❌ Time must be between 0 and 23 hours."
        elif frequency < 0:
            result = "❌ Frequency cannot be negative."
        elif not utr_valid:
            result = utr_reason
        else:
            raw_result = detect_fraud(amount, hour, known_upi, location_match, form_data['purpose'], frequency)
            simple_result = "Fraud" if "Fraud" in raw_result else "Legitimate"
            result = raw_result

            try:
                conn = get_db()
                c = conn.cursor()
                c.execute('''
                    INSERT INTO predictions 
                    (upi_id, utr, amount, hour, known_upi, location_match, purpose, frequency, result, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    form_data['upi_id'] or None,
                    form_data['utr'] or None,
                    amount,
                    int(hour),
                    known_upi,
                    location_match,
                    form_data['purpose'] or None,
                    frequency,
                    simple_result,
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ))
                conn.commit()
            except Exception as e:
                print("❌ DB Insert Error:", e)
            finally:
                conn.close()

    # Stats
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM predictions")
    total_predictions = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM predictions WHERE result='Fraud'")
    total_frauds = c.fetchone()[0] or 0  # FIX: Correctly access the count value
    total_legit = total_predictions - total_frauds

    c.execute("""
        SELECT date(timestamp) AS day, COUNT(*) AS count
        FROM predictions
        GROUP BY day
        ORDER BY day DESC
        LIMIT 30
    """)
    daily_usage = c.fetchall()

    c.execute("""
        SELECT upi_id, utr, amount, hour, result, timestamp
        FROM predictions
        ORDER BY timestamp DESC
        LIMIT 50
    """)
    all_predictions = c.fetchall()
    conn.close()

    return render_template('predict.html',
                           result=result,
                           total_predictions=total_predictions,
                           total_frauds=total_frauds,
                           total_legit=total_legit,
                           daily_usage=daily_usage,
                           form_data=form_data,
                           all_predictions=all_predictions)

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT date(timestamp) AS day, COUNT(*) AS usage_count
        FROM predictions
        GROUP BY day
        ORDER BY day DESC
        LIMIT 30
    """)
    daily_usage = c.fetchall()
    conn.close()
    return render_template('dashboard.html', daily_usage=daily_usage)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/history')
@login_required
def history():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT upi_id, utr, COALESCE(amount,0), hour, result, timestamp 
        FROM predictions ORDER BY timestamp DESC
    """)
    records = c.fetchall()
    conn.close()
    return render_template('history.html', records=records)

# ================= API Endpoints =================
@app.route('/api/table')
def table():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT upi_id, utr, COALESCE(amount,0), hour, result, timestamp 
        FROM predictions ORDER BY timestamp DESC LIMIT 10
    """)
    records = c.fetchall()
    conn.close()
    return jsonify({"records": [tuple(row) for row in records]})

@app.route('/api/pie')
def pie():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM predictions WHERE result='Fraud'")
    frauds = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM predictions WHERE result='Legitimate'")
    legits = c.fetchone()[0] or 0 # FIX: Correctly access the count value
    conn.close()
    return jsonify({"labels": ["Legitimate", "Fraud"], "values": [legits, frauds]})

@app.route('/api/line')
def line():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT date(timestamp) as day, COUNT(*) as count
        FROM predictions
        GROUP BY day
        ORDER BY day ASC
        LIMIT 30
    """)
    rows = c.fetchall()
    conn.close()
    labels = [row['day'] for row in rows]
    values = [row['count'] for row in rows]
    return jsonify({"labels": labels, "values": values})

@app.route('/api/bar')
def bar():
    hourly = [0] * 24
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT hour FROM predictions WHERE result='Fraud'")
    for (h,) in c.fetchall():
        try:
            idx = int(h)
            if 0 <= idx < 24:
                hourly[idx] += 1
            else:
                hourly[0] += 1
        except:
            hourly[0] += 1 # FIX: Change 'hourly += 1' to 'hourly[0] += 1' to avoid TypeError
    conn.close()
    return jsonify({"hours": list(range(24)), "fraud_counts": hourly})

@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store"
    return response

# ================= Main Entry =================
if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        init_db()
        add_trusted_upis()
    else:
        add_trusted_upis()

    ensure_model_ready()
    app.run(debug=True, use_reloader=False)
    
