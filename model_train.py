import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

# 1. Load dataset
df = pd.read_csv('creditcard_250.csv')

# 2. Preprocess: Add 'Hour' feature by converting 'Time' (seconds) to hour of day
df['Hour'] = (df['Time'] % 86400) / 3600

# 3. Define features and target
X = df[['Amount', 'Hour']]
y = df['Class']

# 4. Split into train/test with stratified class balance
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

# 5. Train model with class balancing
model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
model.fit(X_train, y_train)

# 6. Evaluate
y_pred = model.predict(X_test)
print("\n✅ Accuracy:", accuracy_score(y_test, y_pred))
print("\n📊 Classification Report:\n", classification_report(y_test, y_pred))
print("📌 Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

# 7. Save model
joblib.dump(model, 'fraud_model.pkl')
print("\n✅ Model saved as fraud_model.pkl")

# 8. Load model once for app use
model = joblib.load('fraud_model.pkl')

# 9. Predict function for Flask
def detect_fraud(transaction_amount, transaction_hour):
    """
    Predict fraud from amount and hour.
    Returns a formatted result string.
    """
    if transaction_amount <= 0 or not (0 <= transaction_hour <= 24):
        return "❌ Invalid input values."
    
    input_df = pd.DataFrame([[transaction_amount, transaction_hour]], columns=['Amount', 'Hour'])
    prediction = model.predict(input_df)[0]
    
    return "🚨 Fraud Detected!" if prediction == 1 else "✅ Transaction is Legitimate."
