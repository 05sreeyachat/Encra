import sqlite3
import os
from datetime import datetime
import csv

DB_PATH = "data/security_audit.db"

def init_audit_db():
    if not os.path.exists('data'):
        os.makedirs('data')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            token_hash TEXT,
            event_type TEXT NOT NULL,
            receiver_email TEXT,
            ip_address TEXT,
            device_info TEXT,
            location TEXT,
            status TEXT,
            reason TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_audit_event(event_type, token_hash=None, receiver_email=None, ip=None, device=None, location=None, status="INFO", reason=None):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_logs (timestamp, token_hash, event_type, receiver_email, ip_address, device_info, location, status, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (datetime.now().isoformat(), token_hash, event_type, receiver_email, ip, device, location, status, reason))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Failed to log audit event: {e}")

def export_audit_logs_csv(output_path):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM audit_logs ORDER BY timestamp DESC')
        rows = cursor.fetchall()
        headers = [description[0] for description in cursor.description]
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        
        conn.close()
        return True
    except Exception as e:
        print(f"Failed to export logs: {e}")
        return False

def get_logs_for_token(token_hash):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM audit_logs WHERE token_hash = ? ORDER BY timestamp DESC', (token_hash,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception as e:
        print(f"Failed to fetch logs: {e}")
        return []

# Initialize on import
init_audit_db()
