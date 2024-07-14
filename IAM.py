#!/usr/bin/env python3

import sqlite3
import uuid
import bcrypt

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def db(conn, cursor):
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY,
        event_type TEXT,
        username TEST,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    users = [
        ('admin', hash_password('adminpass'), 'admin') 
        ]
    cursor.executemany('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)', users)

    conn.commit()

def log_event(conn, cursor, event_type, username):
    cursor.execute('INSERT INTO events (event_type, username) VALUES (?, ?)', (event_type, username))
    conn.commit

def authenticate(conn, cursor, username, password):
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
        log_event(conn, cursor, 'login_sucess', username)
        print(f"User {user[1]}")
        return user
    else:
        log_event(conn, cursor, 'login_failure', username)
        print("Incorrects credentials")
        return None

def authorize(user, action):
    policies = {
        'admin': ['read', 'write', 'delete'],
        'user': ['read']
    }

    role = user[3]
    allowed_actions = policies.get(role, [])

    return action in allowed_actions

def manage_users(action, username, password=None, role=None):
    if action == 'create':
        hashed_password = hash_password(password)
        cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, hashed_password, role))
    elif action == 'update':
        if password:
            hashed_password = hash_password(password)
            cursor.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_password, username))
        if role:
            cursor.execute('UPDATE users SET role = = WHERE username = ?', (role, username))
    elif action == 'delete':
        cursor.execute('DELETE FROM users WHERE username = ?', (username,))
    con.commit

sessions = {}

def create_session(user):
    session_token = str(uuid.uuid4())
    sessions[session_token] = user
    return session_token

def get_user_from_session(session_token):
    return sessions.get(session_token)

def get_creds():
    username = input("Enter your username: ")
    password = input("Enter your password:")
    return username, password

def main():
    conn = sqlite3.connect('iam.db')
    cursor = conn.cursor()
    db(conn, cursor)
    username, password = get_creds()
    authenticate(conn, cursor, username, password)

if __name__ == '__main__':
    main()

