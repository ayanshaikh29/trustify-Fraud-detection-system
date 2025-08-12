# app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
import sqlite3
import datetime
import re
import os
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
import requests
from model_train import detect_fraud, ensure_model_ready  # your ML helpers


# ================= Flask App Config =================
app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.secret_key = os.environ.get('TRUSTIFY_SECRET', 'trust@trust')  # set a strong secret in prod


# ================= Brevo API Config (use env vars) =================
# IMPORTANT: set these environment variables on your machine/server
# BREVO_API_KEY  - your Brevo / Sendinblue API key
# BREVO_SENDER_EMAIL - verified sender email in Brevo (e.g. no-reply@yourdomain.com)
# Optionally: TEST_TO_EMAIL for test route receiver
BREVO_API_KEY = os.environ.get('BREVO_API_KEY', None)
BREVO_SENDER_EMAIL = os.environ.get('BREVO_SENDER_EMAIL', '948faf001@smtp-brevo.com')
BREVO_SENDER_NAME = os.environ.get('BREVO_SENDER_NAME', 'Trustify Alerts')


# ================= Absolute Paths =================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'fraud.db')
MODEL_PATH = os.path.join(BASE_DIR, 'fraud_model.pkl')


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


# ================= Email (Brevo API) =================
def send_email_via_brevo(to_email: str, subject: str, html_content: str) -> bool:
    """
    Send email using Brevo (Sendinblue) transactional API.
    Returns True on success, False on failure. Prints debug info to console.
    """
    if not BREVO_API_KEY:
        print("❌ BREVO_API_KEY not set. Please set BREVO_API_KEY environment variable.")
        return False

    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
    }
    payload = {
        "sender": {"name": BREVO_SENDER_NAME, "email": BREVO_SENDER_EMAIL},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html_content
    }

    try:
        print(f"📡 Sending email to {to_email} via Brevo API...")
        r = requests.post(url, headers=headers, json=payload, timeout=15)
        if r.status_code in (200, 201, 202):
            print("✅ Email sent successfully (Brevo).")
            return True
        else:
            print(f"❌ EMAIL ERROR: {r.status_code} - {r.text}")
            return False
    except Exception as e:
        print("❌ EMAIL EXCEPTION:", e)
        return False


def send_fraud_alert(email, transaction_id, amount):
    try:
        subject = "🚨 Fraud Alert - Trustify"
        body = f"""<p>Hello,</p>
<p>A suspicious transaction has been detected.</p>
<ul>
<li><strong>Transaction ID:</strong> {transaction_id}</li>
<li><strong>Amount:</strong> ₹{amount}</li>
</ul>
<p>Please verify immediately.</p>
<p>- Trustify Security Team</p>
"""
        ok = send_email_via_brevo(email, subject, body)
        if not ok:
            app.logger.warning("Failed to send fraud alert to %s", email)
    except Exception as e:
        app.logger.warning("send_fraud_alert exception: %s", e)


def send_login_email(email, username):
    try:
        subject = "🔐 Login Notification - Trustify"
        body = f"""<p>Hello {username},</p>
<p>You have successfully logged in to your Trustify account.</p>
<p>If this was not you, please change your password immediately.</p>
<p>- Trustify Security Team</p>
"""
        ok = send_email_via_brevo(email, subject, body)
        if not ok:
            app.logger.warning("Failed to send login email to %s", email)
    except Exception as e:
        app.logger.warning("send_login_email exception: %s", e)


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

            # best-effort email (non-blocking)
            try:
                send_login_email(user['email'], user['username'])
            except Exception as e:
                app.logger.warning("Login email failed: %s", e)

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
        c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, hashed_password))
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

            if simple_result == "Fraud":
                user_email = session.get('email') or "receiver_email@gmail.com"
                try:
                    send_fraud_alert(user_email, form_data['utr'] or "N/A", amount)
                except Exception as e:
                    app.logger.warning("Fraud alert email failed: %s", e)

    # Stats
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM predictions")
    total_predictions = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM predictions WHERE result='Fraud'")
    total_frauds = c.fetchone()[0] or 0
    total_legit = total_predictions - total_frauds

    c.execute("""
        SELECT upi_id, utr, amount, hour, result, timestamp
        FROM predictions
        ORDER BY timestamp DESC
    """)
    all_predictions = c.fetchall()
    conn.close()

    return render_template('predict.html',
                           result=result,
                           total_predictions=total_predictions,
                           total_frauds=total_frauds,
                           total_legit=total_legit,
                           form_data=form_data,
                           all_predictions=all_predictions)


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/history')
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
        FROM predictions
        ORDER BY timestamp DESC
        LIMIT 10
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
    legits = c.fetchone()[0] or 0
    conn.close()
    return jsonify({"labels": ["Legitimate", "Fraud"], "values": [legits, frauds]})


@app.route('/api/bar')
def bar():
    hourly = [0] * 24
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT hour FROM predictions WHERE result='Fraud'")
    for (h,) in c.fetchall():
        try:
            idx = int(h) if 0 <= int(h) < 24 else 0
        except:
            idx = 0
        hourly[idx] += 1
    conn.close()
    return jsonify({"hours": list(range(24)), "fraud_counts": hourly})


@app.route('/test_email')
def test_email():
    # quick test route to verify Brevo API works
    test_to = os.environ.get('TEST_TO_EMAIL', 'receiver@example.com')
    ok = send_email_via_brevo(test_to, "Trustify Test Email", "This is a test from Trustify (Brevo API).")
    return ("✅ Test email sent!" if ok else "❌ Test email failed. Check console/logs.")


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
