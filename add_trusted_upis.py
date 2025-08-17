import sqlite3

# Database connect karo (agar file nahi hai toh ban jayegi)
conn = sqlite3.connect("fraud.db")
c = conn.cursor()

# Table banao agar pehle se nahi hai
c.execute('''
CREATE TABLE IF NOT EXISTS trusted_upis (
    upi_id TEXT PRIMARY KEY
)
''')

# Trusted UPI IDs ki list
trusted_upis = [
    "paytm@upi",
    "phonepe@upi",
    "gpay@okicici",
    "gpay@okhdfcbank",
    "icici@upi",
    "sbi@upi",
    "axisbank@upi",
    "hdfcbank@upi",
    "amazonpay@apl",
    "ybl@upi",
    "okaxis@upi",
    "okicici@upi",
    "okhdfcbank@upi",
    "okbizaxis@upi",
    "airtel@upi"
]

# Insert karo DB mein, duplicates ignore karte hue
for upi in trusted_upis:
    c.execute("INSERT OR IGNORE INTO trusted_upis (upi_id) VALUES (?)", (upi,))

# Changes save karo
conn.commit()

# Connection band karo
conn.close()

print("✅ Trusted UPIs added successfully!")
