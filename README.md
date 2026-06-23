# Camera Honeypot and Threat Monitoring Lab

A Python-based honeypot that emulates an IP camera interface to capture and analyze unauthorized access attempts and suspicious network activity. The project combines Flask, Scapy, and SQLite to provide visibility into login attempts, service probes, and network events through a web dashboard.

---

## Features

* Fake IP camera login interface built with Flask
* Logging of submitted usernames and passwords
* Page visit tracking and user-agent collection
* Detection of camera service probes
* SYN flood detection using Scapy
* Automatic discovery of new devices via ARP traffic
* SQLite-backed event storage
* Web dashboard for reviewing login attempts, page visits, and security alerts

---

## Technologies

* Python
* Flask
* Scapy
* SQLite
* HTML/CSS
* Kali Linux

---

## Project Structure

```text
CameraHoneypot/
│
├── app.py
├── honeypot.db
├── requirements.txt
│
├── templates/
│   ├── login.html
│   └── admin.html
│
├── static/
│
└── logs/
```

---

## Event Types

### Login Attempts

Records:

* Timestamp
* Source IP address
* Username
* Password
* User-Agent
* Referrer

### Page Visits

Records:

* Timestamp
* Source IP address
* User-Agent

### Network Events

Records:

* Timestamp
* Event Type
* Source IP
* Source MAC
* Destination IP
* Destination Port
* Protocol
* Description
* Severity

Current event types include:

* New Device
* Camera Service Probe
* Possible SYN Flood

---

## Dashboard

The `/admin` endpoint provides:

* Recent login attempts
* Recent page visits
* Security alerts
* Device discovery events

---

## Dashboard Authentication

The administrative dashboard supports credentials configured through environment variables to avoid hardcoding sensitive information.

Example `.env` file:

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change_me
SECRET_KEY=replace_with_random_secret
```

Load environment variables with:

```python
from dotenv import load_dotenv
import os

load_dotenv()

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
```

The `.env` file should not be committed to source control and should be included in `.gitignore`.

Example `.gitignore`:

```text
.env
honeypot.db
__pycache__/
.venv/
```

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/CameraHoneypot.git
cd CameraHoneypot
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Running the Application

Start the Flask server:

```bash
python app.py
```

The honeypot interface will be available at:

```text
http://localhost:5000
```

The dashboard can be accessed at:

```text
http://localhost:5000/admin
```

---

## Testing

### Simulate Login Attempts

Navigate to:

```text
http://localhost:5000
```

Submit any credentials. Login attempts are recorded in the SQLite database.

### Simulate Service Probes

```bash
sudo nmap -sS -p 5000 <HONEYPOT_IP>
```

### Simulate SYN Flood Activity

```bash
sudo hping3 -S -p 5000 --flood <HONEYPOT_IP>
```

---

## Future Improvements

* Brute-force login detection
* Geolocation of attacker IP addresses
* Bootstrap-based dashboard styling
* Event filtering and search
* Automatic report generation
* Bash automation scripts
* Docker deployment
* Threat intelligence integration
* Exportable CSV and JSON reports

---

## Educational Purpose

This project was developed for educational and research purposes to better understand:

* Network reconnaissance
* Honeypot design
* Event logging and monitoring
* Packet analysis with Scapy
* Basic threat detection techniques
* Flask web application development
* Security dashboards and incident visibility
