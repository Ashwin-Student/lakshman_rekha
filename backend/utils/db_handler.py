import os
import mysql.connector
from dotenv import load_dotenv

load_dotenv()

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "lakshman_rekha_db")
    )

def load_initial_blacklist():
    ips = set()
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address FROM blocked_ips")
        ips = set(row[0] for row in cursor.fetchall())
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"[!] Database Initialization Sync Error: {e}")
    return ips

def save_block_to_db(ip, reason):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT IGNORE INTO blocked_ips (ip_address, reason) VALUES (%s, %s)", (ip, reason))
        cursor.execute("INSERT INTO attack_logs (ip_address, attack_type, payload) VALUES (%s, %s, %s)", (ip, "IP_BLOCKED", f"Reason: {reason}"))
        conn.commit()
        cursor.close()
        conn.close()
        print(f"[+] Persisted Block rules for {ip} into Database.")
    except Exception as e:
        print(f"[!] Write Block Error: {e}")

def remove_block_from_db(ip):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM blocked_ips WHERE ip_address = %s", (ip,))
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"[!] Unblock Error: {e}")
        return False

def save_attack_log(ip, attack_type, payload):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO attack_logs (ip_address, attack_type, payload) VALUES (%s, %s, %s)", (ip, attack_type, str(payload)))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"[!] Write Log Error: {e}")
