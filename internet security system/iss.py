from flask import Flask, request, jsonify, render_template, redirect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import scapy.all as scapy
from scapy.layers.http import HTTPRequest
import os
import threading
import nmap
import requests

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# User model
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# Dummy user credentials (store securely in a real system)
USERS = {"admin": "password123"}

@login_manager.user_loader
def load_user(user_id):
    if user_id in USERS:
        return User(user_id)
    return None

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username in USERS and USERS[username] == password:
            login_user(User(username))
            return redirect("/")
        return "Invalid credentials", 401
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")

# Ad blocklist
blocklist = set()

# Load external blocklists
def load_blocklist(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            for line in file:
                blocklist.add(line.strip())

# HTTP Sniffer
sniffer_running = False
logs = []

def sniff_packets():
    def process_packet(packet):
        if packet.haslayer(HTTPRequest):
            host = packet[HTTPRequest].Host.decode(errors="ignore")
            path = packet[HTTPRequest].Path.decode(errors="ignore")
            full_url = f"http://{host}{path}"
            logs.append({"type": "HTTP Request", "url": full_url})
            if any(domain in host for domain in blocklist):
                print(f"Blocked: {full_url}")

    scapy.sniff(prn=process_packet, store=False)

@app.route("/start_sniffer")
@login_required
def start_sniffer():
    global sniffer_running
    if not sniffer_running:
        sniffer_running = True
        threading.Thread(target=sniff_packets, daemon=True).start()
    return "Sniffer started"

@app.route("/stop_sniffer")
@login_required
def stop_sniffer():
    global sniffer_running
    sniffer_running = False
    return "Sniffer stopped"

# Port Scanner
@app.route("/scan_ports")
@login_required
def scan_ports():
    nm = nmap.PortScanner()
    devices = scapy.arping("192.168.1.0/24", verbose=0)[0]
    results = []
    for sent, received in devices:
        ip = received.psrc
        try:
            nm.scan(ip, arguments="-p 1-1024 --open")
            results.append({"ip": ip, "ports": nm[ip].all_tcp()})
        except:
            pass
    return jsonify(results)

# Device Management
connected_devices = []
primary_device = None

def update_connected_devices():
    global connected_devices
    devices = scapy.arping("192.168.1.0/24", verbose=0)[0]
    connected_devices = [{"ip": rcv.psrc, "mac": rcv.hwsrc} for _, rcv in devices]

@app.route("/devices")
@login_required
def list_devices():
    update_connected_devices()
    return render_template("devices.html", devices=connected_devices, primary=primary_device)

@app.route("/set_primary/<ip>")
@login_required
def set_primary(ip):
    global primary_device
    primary_device = ip
    return redirect("/devices")

# HTTP Ping to Primary Device
@app.route("/notify_primary", methods=["POST"])
@login_required
def notify_primary():
    if not primary_device:
        return "No primary device set", 400
    data = request.json
    try:
        response = requests.post(f"http://{primary_device}:5001/notify", json=data)
        return jsonify(response.json())
    except Exception as e:
        return str(e), 500

@app.route("/")
@login_required
def index():
    return render_template("index.html", logs=logs, primary=primary_device)

if __name__ == "__main__":
    load_blocklist("blocklist.txt")
    app.run(host="0.0.0.0", port=5000)
