# init_db.py

import sqlite3

def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()

    # existing users table creation…
    c.execute('''
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        email TEXT UNIQUE,
        password_hash TEXT
      )
    ''')

    # ← Add this block for share links
    c.execute('''
      CREATE TABLE IF NOT EXISTS shares (
        id INTEGER PRIMARY KEY,
        token      TEXT UNIQUE,
        filename   TEXT,
        pwd_hash   TEXT,
        expires_at TEXT
      )
    ''')

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
