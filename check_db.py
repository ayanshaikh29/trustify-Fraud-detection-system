import os
import sqlite3

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'fraud.db')   # <-- Use same filename

print(f"Database file exists? {os.path.exists(DB_PATH)}")

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = [t[0] for t in cursor.fetchall()]
print("Tables found:", tables)

if 'predictions' in tables:
    print("\n📌 Columns in 'predictions' table:")
    cursor.execute("PRAGMA table_info(predictions)")
    for col in cursor.fetchall():
        print(f"{col['name']} - {col['type']}")

    print("\n📌 Data in 'predictions' table:")
    cursor.execute("SELECT * FROM predictions")
    rows = cursor.fetchall()
    for row in rows:
        print(dict(row))
else:
    print("Table 'predictions' does NOT exist in the database.")

conn.close()
