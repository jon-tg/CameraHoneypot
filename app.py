from flask import Flask, render_template, request, redirect, session
from datetime import datetime
from dotenv import load_dotenv
import os
import sqlite3

app = Flask(__name__)
load_dotenv()

DB_NAME = "honeypot.db"
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

app.secret_key = os.getenv("SECRET_KEY")

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

def get_dashboard_data():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM login_attempts
        ORDER BY id DESC
        LIMIT 50
    """)
    login_attempts = cursor.fetchall()

    cursor.execute("""
        SELECT * FROM page_visits
        ORDER BY id DESC
        LIMIT 50
    """)
    page_visits = cursor.fetchall()

    conn.close()

    return login_attempts, page_visits

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

    log_attempt(source_ip, username, password, user_agent, referrer)

    print(f"[+] Login attempt from {source_ip}: {username}/{password}")

    return "Invalid username or password"

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect("/admin")

        return render_template("admin_login.html", error="Invalid password")

    if not session.get("admin"):
        return render_template("admin_login.html")

    login_attempts, page_visits = get_dashboard_data()

    return render_template(
        "admin.html",
        login_attempts=login_attempts,
        page_visits=page_visits
    )

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)