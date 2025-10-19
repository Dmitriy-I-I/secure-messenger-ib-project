# database.py

import sqlite3
from crypto import crypto_manager, KeyManager
import logging
import json

# Подключение к базе данных
conn = sqlite3.connect('users.db')
cursor = conn.cursor()

# Создание таблиц
def create_tables():
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            public_key BLOB,
            private_key BLOB
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            encrypted_key BLOB NOT NULL,
            iv BLOB NOT NULL,
            content BLOB NOT NULL,
            hmac BLOB NOT NULL,
            is_file BOOLEAN NOT NULL DEFAULT 0,
            filename TEXT,
            original_content TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()

# Вызываем функцию создания таблиц при импорте файла
create_tables()

# Регистрация нового пользователя
def register_user(username, password):
    private_key, public_key = KeyManager.generate_rsa_keys()
    private_key_pem = KeyManager.serialize_private_key(private_key)
    public_key_pem = KeyManager.serialize_public_key(public_key)

    try:
        cursor.execute('''
            INSERT INTO users (username, password, public_key, private_key)
            VALUES (?, ?, ?, ?)
        ''', (username, password, public_key_pem, private_key_pem))
        conn.commit()
        return True
    except sqlite3.IntegrityError as e:
        logging.error(f"error {e}")
        return False
    except Exception as e:
        logging.error(f"error {e}")
        return False

def get_user_keys(username):
    cursor.execute('SELECT public_key, private_key FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    if result:
        public_key_pem, private_key_pem = result
        print(f"Retrieved keys for {username}: public_key_len={len(public_key_pem)}, private_key_len={len(private_key_pem)}")
        public_key = KeyManager.deserialize_public_key(public_key_pem)
        private_key = KeyManager.deserialize_private_key(private_key_pem)
        return public_key, private_key
    return None, None

def save_message(sender, receiver, encrypted_data, is_file=False, filename=None, original_content=None):
    cursor.execute('''
        INSERT INTO messages (
            sender, receiver, encrypted_key, iv, content, hmac, is_file, filename, original_content
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        sender, receiver,
        encrypted_data['encrypted_key'],
        encrypted_data['iv'],
        encrypted_data['content'],
        encrypted_data['hmac'],
        is_file, filename, original_content
    ))
    conn.commit()

def get_chat_messages(user1, user2):
    cursor.execute('''
        SELECT 
            sender,
            encrypted_key,
            iv,
            content,
            hmac,
            is_file,
            filename,
            timestamp,
            original_content
        FROM messages 
        WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
        ORDER BY timestamp ASC
    ''', (user1, user2, user2, user1))
    
    messages = []
    for row in cursor.fetchall():
        messages.append({
            'sender': row[0],
            'encrypted_data': {
                'encrypted_key': row[1],
                'iv': row[2],
                'content': row[3],
                'hmac': row[4]
            },
            'is_file': row[5],
            'filename': row[6],
            'timestamp': row[7],
            'original_content': row[8]
        })
    return messages

def get_chat_list(username):
    cursor.execute('''
        WITH LastMessages AS (
            SELECT 
                CASE 
                    WHEN sender = ? THEN receiver 
                    ELSE sender 
                END as chat_with,
                MAX(timestamp) as last_message_time
            FROM messages 
            WHERE sender = ? OR receiver = ?
            GROUP BY chat_with
        )
        SELECT 
            lm.chat_with,
            m.sender,
            m.encrypted_key,
            m.iv,
            m.content,
            m.hmac,
            m.is_file,
            m.filename,
            m.timestamp,
            m.original_content
        FROM LastMessages lm
        JOIN messages m ON (
            (m.sender = lm.chat_with OR m.receiver = lm.chat_with)
            AND m.timestamp = lm.last_message_time
            AND (m.sender = ? OR m.receiver = ?)
        )
        ORDER BY m.timestamp DESC
    ''', (username, username, username, username, username))
    
    chats = []
    for row in cursor.fetchall():
        chats.append({
            'chat_with': row[0],
            'sender': row[1],
            'encrypted_data': {
                'encrypted_key': row[2],
                'iv': row[3],
                'content': row[4],
                'hmac': row[5]
            },
            'is_file': row[6],
            'filename': row[7],
            'timestamp': row[8],
            'original_content': row[9]
        })
    return chats

def get_user(username):
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    return cursor.fetchone()

def get_all_users():
    cursor.execute('SELECT username FROM users')
    return [row[0] for row in cursor.fetchall()]

def close_db():
    conn.close()