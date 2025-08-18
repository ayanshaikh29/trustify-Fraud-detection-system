import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os
import sqlite3
from datetime import datetime
import numpy as np

# ===== Paths =====
DB_PATH = "fraud.db"
DATA_PATH = "creditcard_250.csv"
MODEL_PATH = "fraud_model.pkl"
ENCODER_PATH = "purpose_encoder.pkl"

# ===== 0. DB Setup (Fix table schema only) =====
with sqlite3.connect(DB_PATH) as conn:
    c = conn.cursor()
    # Drop and recreate predictions table with matching app.py schema
    c.execute("DROP TABLE IF EXISTS predictions")
    c.execute('''
        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            upi_id TEXT,
            utr TEXT,
            amount REAL NOT NULL,
            hour REAL NOT NULL,
            known_upi INTEGER,
            location_match INTEGER,
            purpose TEXT,
            frequency INTEGER,
            result TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    # Trusted UPI table
    c.execute('''
        CREATE TABLE IF NOT EXISTS trusted_upis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            upi_id TEXT UNIQUE
        )
    ''')
    conn.commit()

print("✅ Database setup complete.")

# ===== Ensure Model Ready =====
def ensure_model_ready():
    """
    Loads or trains the model with consistent features/encoder.
    """
    global model, le_purpose

    # Check CSV
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Dataset not found: {DATA_PATH}. Please place the CSV file.")

    # Load dataset
    df = pd.read_csv(DATA_PATH)

    # Ensure columns present
    required_cols = ['Amount', 'Hour', 'Known_UPI', 'Location_Match', 'Purpose', 'Frequency', 'Fraud']
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing columns in CSV: {missing_cols}")

    # Class balance check
    fraud_counts = df['Fraud'].value_counts()
    print(f"📊 Dataset balance: {dict(fraud_counts)}")
    if len(fraud_counts) < 2:
        raise ValueError("Dataset must contain both fraud and legitimate transactions.")

    # Encode Purpose
    le_purpose = LabelEncoder()
    df['Purpose'] = le_purpose.fit_transform(df['Purpose'])
    joblib.dump(le_purpose, ENCODER_PATH)

    FEATURES = ['Amount', 'Hour', 'Known_UPI', 'Location_Match', 'Purpose', 'Frequency']
    TARGET = 'Fraud'

    X = df[FEATURES]
    y = df[TARGET]

    # Fix: Check if stratified split is possible (class count >1 for both fraud and legit)
    counts = y.value_counts()
    min_count = counts.min()
    if min_count < 2:
        print("⚠️ Not enough samples per class for stratified split. Performing normal split.")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42
        )
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )

    retrain = True
    if os.path.exists(MODEL_PATH) and os.path.exists(ENCODER_PATH):
        try:
            print("📂 Loading existing model...")
            loaded_model = joblib.load(MODEL_PATH)
            if hasattr(loaded_model, "feature_names_in_") and list(loaded_model.feature_names_in_) == FEATURES:
                model = loaded_model
                retrain = False
                print("✅ Existing model loaded successfully.")
            else:
                print("⚠️ Feature mismatch in saved model. Retraining...")
        except Exception as e:
            print(f"⚠️ Error loading model: {e}. Retraining...")

    if retrain:
        print("🛠 Training new model...")
        model = RandomForestClassifier(n_estimators=200, random_state=42, class_weight='balanced')
        model.fit(X_train, y_train)
        joblib.dump(model, MODEL_PATH)
        print(f"✅ Model trained and saved: {MODEL_PATH}")
        # Evaluate
        y_pred = model.predict(X_test)
        print(f"🧠 Accuracy: {accuracy_score(y_test, y_pred):.4f}")
        print("\n📊 Classification Report:")
        print(classification_report(y_test, y_pred))
        print("\n📌 Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred))

# ===== Fraud Detection =====
def detect_fraud(amount, hour, known_upi, location_match, purpose, frequency):
    """
    Predicts fraud and gives reasons.
    """
    if 'model' not in globals() or 'le_purpose' not in globals():
        ensure_model_ready()

    # Validation
    if amount <= 0 or not (0 <= hour <= 23) or frequency < 0:
        return "❌ Invalid input values."

    # Encode Purpose
    try:
        purpose_encoded = le_purpose.transform([purpose])[0]
    except ValueError:
        return f"❌ Purpose '{purpose}' not recognized. Available: {list(le_purpose.classes_)}"

    FEATURES = ['Amount', 'Hour', 'Known_UPI', 'Location_Match', 'Purpose', 'Frequency']
    input_df = pd.DataFrame([[amount, hour, known_upi, location_match, purpose_encoded, frequency]],
                            columns=FEATURES)

    try:
        prediction = model.predict(input_df)
        prob_array = model.predict_proba(input_df)
        # Here: prediction == 1 means fraud, 0 means legitimate. Make sure your mapping in CSV is 0/1.
        fraud_class_idx = list(model.classes_).index(1) if 1 in model.classes_ else 0
        probability = prob_array[fraud_class_idx] * 100 if len(prob_array) > 1 else 50.0
    except Exception as e:
        print(f"Prediction error: {e}")
        return "❌ Error during prediction."

    # Reason logic
    reasons = []
    # Night time logic
    if hour >= 23 or hour <= 5:
        reasons.append("Unusual transaction time (Night)")
    elif 6 <= hour <= 22:
        if amount > 20000 or known_upi == 0 or str(purpose).lower() in ["lottery", "reward", "donation"]:
            reasons.append("Suspicious daytime transaction")
    if amount > 30000:
        reasons.append("Large amount")
    if known_upi == 0:
        reasons.append("Unknown UPI ID")
    if location_match == 0:
        reasons.append("Unusual location")
    if str(purpose).lower() in ["lottery", "reward", "donation"]:
        reasons.append("Suspicious purpose")
    if frequency > 2:
        reasons.append("Multiple rapid transactions")

    if prediction == 1:
        return f"🚨 Fraud Detected! ({probability:.2f}% probability)\nReason: {', '.join(set(reasons)) if reasons else 'Model indicates risk'}"
    else:
        return f"✅ Transaction is Legitimate ({100 - probability:.2f}% probability)\nReason: {', '.join(set(reasons)) if reasons else 'No suspicious patterns detected'}"

# ===== Example Run =====
if __name__ == "__main__":
    ensure_model_ready()
    print("\n--- Example Predictions ---")
    print(detect_fraud(25000, 1, 0, 0, "Lottery", 3))      # Night + high risk
    print(detect_fraud(5000, 14, 1, 1, "Shopping", 1))     # Daytime safe
    print(detect_fraud(30000, 14, 0, 1, "Donation", 1))    # Daytime suspicious
