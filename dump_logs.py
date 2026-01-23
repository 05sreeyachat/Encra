import sqlite3
import os

DB_PATH = "data/security_audit.db"

def dump_logs():
    if not os.path.exists(DB_PATH):
        print("Database not found.")
        return
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, timestamp, event_type, status, reason FROM audit_logs ORDER BY id DESC LIMIT 50')
    rows = cursor.fetchall()
    
    print(f"{'ID':<5} | {'TIMESTAMP':<25} | {'EVENT':<25} | {'STATUS':<15} | {'REASON'}")
    print("-" * 100)
    for row in rows:
        print(f"{row[0]:<5} | {row[1]:<25} | {row[2]:<25} | {row[3]:<15} | {row[4]}")
    
    conn.close()

if __name__ == "__main__":
    dump_logs()
