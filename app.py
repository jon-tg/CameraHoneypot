from flask import Flask, render_template, request
from datetime import datetime
import sqlite3

app = Flask(__name__)
DB_NAME = "honeypot.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        username TEXT,
        password TEXT,
        user_agent TEXT,
        referrer TEXT
        )
        """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS page_visits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        user_agent TEXT
        )
    """)

    conn.commit()
    conn.close()


def log_attempt(source_ip, username, password, user_agent, referrer):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO login_attempts 
        (timestamp, source_ip, username, password, user_agent, referrer)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(timespec="seconds"),
        source_ip,
        username,
        password,
        user_agent,
        referrer
    ))

    conn.commit()
    conn.close()

def log_view(source_ip, user_agent):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO page_visits 
        (timestamp, source_ip, user_agent)
        VALUES (?, ?, ?)
    """, (
        datetime.now().isoformat(timespec="seconds"),
        source_ip,
        user_agent
    ))

    conn.commit()
    conn.close()


@app.route("/")
def index():
    source_ip = request.remote_addr
    user_agent = request.headers.get("User-Agent")
    log_view(source_ip, user_agent)
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    
    source_ip = request.remote_addr
    user_agent = request.headers.get("User-Agent")
    referrer = request.referrer

    log_attempt(source_ip, username, password, user_agent)

    print(f"[+] Login attempt from {source_ip}: {username}/{password}")

    return "Invalid username or password"


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)