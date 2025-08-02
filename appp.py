from flask import Flask, render_template, request
import sqlite3
import datetime
from model_train import detect_fraud  # Make sure this file is in the same folder

app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# Initialize SQLite DB
def init_db():
    with sqlite3.connect('fraud.db') as conn:
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
        conn.commit()

init_db()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    result = None
    if request.method == 'POST':
        try:
            amount = float(request.form['amount'])
            time_val = float(request.form['time'])  # Time expected in 0–24 format

            if amount <= 0:
                result = "❌ Amount must be positive."
            elif not (0 <= time_val <= 24):
                result = "❌ Time must be between 0 and 24 hours."
            else:
                # Predict using model
                result = detect_fraud(amount, time_val)

                # Save prediction to DB
                with sqlite3.connect('fraud.db') as conn:
                    c = conn.cursor()
                    c.execute('''
                        INSERT INTO predictions (amount, time, result, timestamp)
                        VALUES (?, ?, ?, ?)
                    ''', (amount, time_val, result, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                    conn.commit()

        except Exception as e:
            result = f"❌ Error: {str(e)}"

    return render_template('predict.html', result=result)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/history')
def history():
    try:
        with sqlite3.connect('fraud.db') as conn:
            c = conn.cursor()
            c.execute("SELECT amount, time, result, timestamp FROM predictions ORDER BY timestamp DESC")
            records = c.fetchall()
    except:
        records = []
    return render_template('history.html', records=records)

@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store"
    return response

if __name__ == '__main__':
    app.run(debug=True)
