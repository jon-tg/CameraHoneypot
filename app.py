from flask import Flask, render_template, request, redirect, session
from datetime import datetime
from dotenv import load_dotenv
from collections import defaultdict
import os
import sqlite3
from scapy.all import sniff, IP, TCP, ARP
import time
import threading

app = Flask(__name__)
load_dotenv()

DB_NAME = "honeypot.db"
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
HONEYPOT_IP = os.getenv("HONEYPOT_IP")

app.secret_key = os.getenv("SECRET_KEY")

seen_devices = {}
port_activity = defaultdict(list)
syn_activity = defaultdict(list)

PORT_SCAN_THRESHOLD = 5
PORT_SCAN_WINDOW = 10

SYN_FLOOD_THRESHOLD = 20
SYN_FLOOD_WINDOW = 10

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
        type TEXT NOT NULL,
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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT,
            source_ip TEXT,
            source_mac TEXT,
            destination_ip TEXT,
            destination_port INTEGER,
            protocol TEXT,
            description TEXT
        )
        """)

    conn.commit()
    conn.close()

def log_network_event(event_type, source_ip=None, source_mac=None, destination_ip=None, destination_port=None, protocol=None, description=None):
    conn = sqlite3.connect("honeypot.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO network_events
        (timestamp, event_type, source_ip, source_mac, destination_ip,
         destination_port, protocol, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(timespec="seconds"),
        event_type,
        source_ip,
        source_mac,
        destination_ip,
        destination_port,
        protocol,
        description
    ))

    conn.commit()
    conn.close()

def log_attempt(source_ip, username, password, user_agent, login_type, referrer):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO login_attempts 
        (timestamp, source_ip, username, password, user_agent, type, referrer)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(timespec="seconds"),
        source_ip,
        username,
        password,
        user_agent,
        login_type,
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

def process_packet(packet):
    current_time = time.time()

    if packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc

        if src_ip and src_mac and src_ip not in seen_devices:
            seen_devices[src_ip] = src_mac

            log_network_event(
                event_type="New Device",
                source_ip=src_ip,
                source_mac=src_mac,
                protocol="ARP",
                description=f"New device discovered: {src_ip} ({src_mac})"
            )

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if dst_ip != HONEYPOT_IP:
            return

        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags

            log_network_event(
                event_type="TCP Packet",
                source_ip=src_ip,
                destination_ip=dst_ip,
                destination_port=dst_port,
                protocol="TCP",
                description=f"TCP traffic from {src_ip} to {dst_ip}:{dst_port}"
            )

            port_activity[src_ip].append((current_time, dst_port))

            port_activity[src_ip] = [
                entry for entry in port_activity[src_ip]
                if current_time - entry[0] <= PORT_SCAN_WINDOW
            ]

            unique_ports = set(port for _, port in port_activity[src_ip])

            if len(unique_ports) >= PORT_SCAN_THRESHOLD:
                log_network_event(
                    event_type="Possible Port Scan",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    protocol="TCP",
                    description=f"{src_ip} contacted {len(unique_ports)} ports within {PORT_SCAN_WINDOW} seconds: {sorted(unique_ports)}"
                )

                port_activity[src_ip].clear()

            if flags == "S":
                syn_activity[src_ip].append(current_time)

                syn_activity[src_ip] = [
                    t for t in syn_activity[src_ip]
                    if current_time - t <= SYN_FLOOD_WINDOW
                ]

                if len(syn_activity[src_ip]) >= SYN_FLOOD_THRESHOLD:
                    log_network_event(
                        event_type="Possible SYN Flood",
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        destination_port=dst_port,
                        protocol="TCP",
                        description=f"{src_ip} sent {len(syn_activity[src_ip])} SYN packets within {SYN_FLOOD_WINDOW} seconds"
                    )

                    syn_activity[src_ip].clear()

def start_scapy_monitor():
    sniff(
        iface="lo",
        prn=process_packet,
        store=False
    )

def get_dashboard_data():
    conn = sqlite3.connect("honeypot.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM login_attempts
        ORDER BY timestamp DESC
    """)
    login_attempts = cursor.fetchall()

    cursor.execute("""
        SELECT *
        FROM page_visits
        ORDER BY timestamp DESC
    """)
    page_visits = cursor.fetchall()

    cursor.execute("""
        SELECT *
        FROM network_events
        ORDER BY timestamp DESC
        LIMIT 100
    """)
    network_events = cursor.fetchall()

    conn.close()

    return login_attempts, page_visits, network_events

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

    log_attempt(source_ip, username, password, user_agent, "regular", referrer)
    return "Invalid username or password"

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect("/admin")
        
        source_ip = request.remote_addr
        user_agent = request.headers.get("User-Agent")
        referrer = request.referrer

        log_attempt(source_ip, username, password, user_agent, "admin", referrer)
        return render_template("admin_login.html", error="Invalid password")

    if not session.get("admin"):
        return render_template("admin_login.html")

    login_attempts, page_visits, network_events = get_dashboard_data()

    return render_template(
        "admin.html",
        login_attempts=login_attempts,
        page_visits=page_visits,
        network_events=network_events
    )

if __name__ == "__main__":
    scapy_thread = threading.Thread(target=start_scapy_monitor, daemon=True)
    scapy_thread.start()
    init_db()
    app.run(host="0.0.0.0", port=5000)