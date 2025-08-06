import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE
import joblib
import os

# ===== 1. Load Dataset =====
df = pd.read_csv('creditcard_250.csv')

# ===== 2. Feature Engineering =====
df['Hour'] = (df['Time'] % 86400) / 3600

# ===== 3. Select Features & Target =====
X = df[['Amount', 'Hour']]
y = df['Class']  # 1 = Fraud, 0 = Legitimate

# ===== 4. Train-Test Split =====
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

# ===== 5. Handle Class Imbalance =====
sm = SMOTE(random_state=42)
X_train_res, y_train_res = sm.fit_resample(X_train, y_train)

# ===== 6. Train or Load Model =====
MODEL_PATH = 'fraud_model.pkl'

if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
else:
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train_res, y_train_res)
    joblib.dump(model, MODEL_PATH)

# ===== 7. Prediction Function =====
def detect_fraud(transaction_amount, transaction_hour):
    """
    Predict fraud from transaction amount and hour.
    Returns: Fraud status.
    """
    if transaction_amount <= 0 or not (0 <= transaction_hour <= 24):
        return "❌ Invalid input. Please enter valid values."
    
    input_df = pd.DataFrame([[transaction_amount, transaction_hour]], columns=['Amount', 'Hour'])
    prediction = model.predict(input_df)[0]
    
    return "🚨 Fraud Detected!" if prediction == 1 else "✅ Transaction is Legitimate"

# ===== 8. Evaluation & Examples =====
if __name__ == '__main__':
    print("✅ Model ready. Evaluating...\n")
    
    y_pred = model.predict(X_test)

    print(f"🧠 Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\n📊 Classification Report:\n", classification_report(y_test, y_pred))
    print("📌 Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

    # ==== 🔍 Example Transactions ====
    print("\n--- Example Predictions ---")
    print("Example 1: ₹100 at 2 PM     =>", detect_fraud(100, 14))   # Legit
    print("Example 2: ₹600 at 3 AM     =>", detect_fraud(600, 3))    # Fraud
    print("Example 3: ₹1000 at 11 PM   =>", detect_fraud(1000, 23))  # Fraud
    print("Example 4: ₹10 at 10 AM     =>", detect_fraud(10, 10))    # Legit
