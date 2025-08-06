import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE
import joblib
import os

# ===== Model Training and Saving =====

# 1. Load dataset
df = pd.read_csv('creditcard_250.csv')

# 2. Feature Engineering: extract hour of day
df['Hour'] = (df['Time'] % 86400) / 3600

# 3. Feature selection & target
X = df[['Amount', 'Hour']]
y = df['Class']  # 1 = Fraud, 0 = Legitimate

# 4. Split to train/test
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

# 5. Fixing Class Imbalance using SMOTE
sm = SMOTE(random_state=42)
X_train_res, y_train_res = sm.fit_resample(X_train, y_train)

# 6. Train model or load if exists
MODEL_PATH = 'fraud_model.pkl'
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
else:
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train_res, y_train_res)
    joblib.dump(model, MODEL_PATH)
    model = joblib.load(MODEL_PATH)

# ===== Prediction Function for App =====

def detect_fraud(transaction_amount, transaction_hour):
    """
    Predict fraud from transaction amount and hour.
    Returns: "Fraud", "Legitimate", or "Invalid"
    """
    # Input validation
    if transaction_amount <= 0 or not (0 <= transaction_hour <= 24):
        return "Invalid"
    input_df = pd.DataFrame([[transaction_amount, transaction_hour]], columns=['Amount', 'Hour'])
    pred = model.predict(input_df)[0]
    return "🚨 Fraud Detected!" if pred == 1 else "✅ Transaction is Legitimate"

# ===== Evaluation and Examples =====

if __name__ == '__main__':
    print("✅ Model loaded. Evaluating on test set...")
    y_test_pred = model.predict(X_test)

    print(f"\n🧠 Accuracy: {accuracy_score(y_test, y_test_pred):.4f}")
    print("\n📊 Classification Report:\n", classification_report(y_test, y_test_pred))
    print("📌 Confusion Matrix:\n", confusion_matrix(y_test, y_test_pred))

    # 🔎 Example Predictions
    print("\nExample 1: ₹100 at 2 PM ->", detect_fraud(100, 14))     # Likely Legitimate
    print("Example 2: ₹600 at 3 AM ->", detect_fraud(600, 3))       # Likely Fraud
    print("Example 3: ₹1000 at 11 PM ->", detect_fraud(1000, 23))   # Likely Fraud
