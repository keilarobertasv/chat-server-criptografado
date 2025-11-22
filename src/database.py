import sqlite3
import os
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DB_NAME = os.path.join(PROJECT_ROOT, "chat_server.db")

ph = PasswordHasher()

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            public_key TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS offline_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_username TEXT NOT NULL,
            sender_username TEXT NOT NULL,
            message_text TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS offline_handshakes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_username TEXT NOT NULL,
            sender_username TEXT NOT NULL,
            public_key TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def register_user(username, password, public_key):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        return False, "Nome de usuário já existe."
    
    password_hash = ph.hash(password)

    try:
        cursor.execute('INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)', (username, password_hash, public_key))
        conn.commit()
        conn.close()
        return True, "Usuário registrado e chave armazenada com sucesso."
    except sqlite3.Error as e:
        conn.close()
        return False, f"Erro no banco de dados: {e}"

def check_user_credentials(username, password):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        stored_password_hash = result[0]
        try:
            ph.verify(stored_password_hash, password)
            return True
        except (VerifyMismatchError, Exception):
            return False
    else:
        return False

def get_all_users():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users")
    users = [row[0] for row in cursor.fetchall()]

    conn.close()
    return users

def store_offline_message(recipient_username, sender_username, message_text):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO offline_messages (recipient_username, sender_username, message_text) VALUES (?, ?, ?)",
            (recipient_username, sender_username, message_text)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.Error as e:
        print(f"Erro ao salvar mensagem offline: {e}")
        return False

def get_and_delete_offline_messages(recipient_username):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT sender_username, message_text, timestamp FROM offline_messages WHERE recipient_username = ?",
            (recipient_username,)
        )
        messages = cursor.fetchall()

        if messages:
            cursor.execute(
                "DELETE FROM offline_messages WHERE recipient_username = ?",
                (recipient_username,)
            )

        conn.commit()
        conn.close()
        return messages
    except sqlite3.Error as e:
        print(f"Erro ao buscar e apagar mensagens offline: {e}")
        return []

def store_public_key(username, public_key):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET public_key = ? WHERE username = ?", (public_key, username))
        conn.commit()
        conn.close()
        return True, "Chave pública armazenada com sucesso."
    except sqlite3.Error as e:
        conn.close()
        return False, f"Erro no banco de dados ao salvar chave: {e}"

def get_user_public_key(username):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT public_key FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result and result[0]:
            return result[0]
        else:
            return None
    except sqlite3.Error as e:
        print(f"Erro ao buscar chave pública: {e}")
        conn.close()
        return None

def store_offline_handshake(recipient_username, sender_username, public_key):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO offline_handshakes (recipient_username, sender_username, public_key) VALUES (?, ?, ?)",
            (recipient_username, sender_username, public_key)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.Error as e:
        print(f"Erro ao salvar handshake offline: {e}")
        return False

def get_and_delete_offline_handshakes(recipient_username):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT sender_username, public_key FROM offline_handshakes WHERE recipient_username = ?",
            (recipient_username,)
        )
        rows = cursor.fetchall()
        if rows:
            cursor.execute(
                "DELETE FROM offline_handshakes WHERE recipient_username = ?",
                (recipient_username,)
            )
        conn.commit()
        conn.close()
        return rows
    except sqlite3.Error as e:
        print(f"Erro ao buscar/apagar handshakes offline: {e}")
        return []

def verify_password(username, password):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        stored_hash = result[0]
        try:
            ph.verify(stored_hash, password)
            return True
        except:
            return False
    return False

def update_public_key_and_clear_messages(username, new_public_key):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute("UPDATE users SET public_key = ? WHERE username = ?", (new_public_key, username))
        
        cursor.execute("DELETE FROM offline_messages WHERE recipient_username = ?", (username,))
        
        cursor.execute("DELETE FROM offline_handshakes WHERE recipient_username = ?", (username,))
        
        conn.commit()
        conn.close()
        return True
    except sqlite3.Error:
        return False