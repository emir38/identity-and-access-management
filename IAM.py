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

    users = [
        ('admin', hash_password'adminpass', 'admin')
    

    cursor.executemany('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)', users)

    conn.commit()

def authenticate(cursor, username, password):
    cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
    user = cursor.fetchone()
    if user:
        print(f"User {user[1]}")
    else:
        print("Incorrects credentials")

def get_creds():
    username = input("Enter your username...")
    password = input("Enter your password...")
    return username, password

def main():
    conn = sqlite3.connect('iam.db')
    cursor = conn.cursor()
    db(conn, cursor)
    username, password = get_creds()
    authenticate(cursor, username, password)

if __name__ == '__main__':
    main()

