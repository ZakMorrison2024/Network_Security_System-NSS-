##############################################################################
##############################################################################
                            # Libraries #
from flask import Flask, request, jsonify, render_template, redirect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from scapy.all import ARP, Ether, srp, sniff, DNS, IP, TCP, UDP, Raw, send
import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from collections import defaultdict
import traceback
import logging
import os
import sys
import threading
import nmap
import requests
import re
import time
import psutil
import subprocess
import socket
import ipaddress
import datetime
import matplotlib.pyplot as plt
from io import BytesIO
import base64
##############################################################################
##############################################################################
##############################################################################
from deployment.threats import suspicious_and_threat_patterns
from deployment.action import actions
from deployment.traffic_params import traffic_control_params
from deployment.traffic_reference import protocol_catagorical_params
from deployment.tracker_blocklist import tracker_block_list
##############################################################################
##############################################################################
##############################################################################
                     # Local Lists and Resources #

# ===========================================
#                  Login
# ===========================================

# Dummy user credentials (store securely in a real system)
USERS = {"Admin": "root"} # For the Flask SYSTEM

# ===========================================
#                  Externals 
# ===========================================

threats = suspicious_and_threat_patterns()
params = traffic_control_params()
protocol_names = protocol_catagorical_params() 
potential_actions = actions()

# Extract parameters
protocols = params.get("protocols", {})  # Protocols with associated config
malicious_patterns = params.get("malicious_patterns", [])
geo_blocklist = params.get("geo_blocklist", [])    

# ===========================================
#           Network and Device Management
# ===========================================

# Primary device and network-related information
local_hostname = socket.gethostname()  # Hostname
My_IP = socket.gethostbyname(local_hostname)  # Player IP address
network_ip_range = "192.168.0.0/24" # Local IP directory
admin = "192.168.0.15"  # Primary device IP ("192.168.0.15" is my local host)
hosts_ip = [] # list of network hosts to sniff packets for
connected_devices = []  # List for scanning active devices
known_devices = {}  # Dictionary to associate devices with users (e.g., device name -> user)

# Trusted subnets (trusted network ranges or individual IPs)
TRUSTED_SUBNETS = [
    ipaddress.IPv4Network(network_ip_range),  # Example: Trusted network 1
    ipaddress.IPv4Network("10.0.0.0/8")       # Example: Trusted network 2
]

# Known MAC addresses (map IPs to their corresponding MAC addresses)
KNOWN_MACS = {
    '192.168.1.1': '00:14:22:01:23:45',  # Example MAC mapping
    '192.168.1.2': '00:14:22:67:89:ab',
}

# ===========================================
#            Logs and Monitoring
# ===========================================

# System and traffic logs
logs = []  # General system logs
execution_times = defaultdict(float)  # Execution times for tracking performance
traffic_logs = defaultdict(list)  # Traffic log storage (IP -> [traffic data])
detected_anomalies = []  # List to store simulated detected anomalies
results = [] #  result of port scan

# Intrusion Detection and Security
intrusion_events = []  # List to collect IDS (Intrusion Detection System) events
login_attempts = [] # List of login attempts
connection_attempts = {}  # Track connection attempts by IP address
request_counts = {}  # Count of requests per IP address

# Packet Tally
unsigned = 0 # unsigned packet tally
TCP_num = 0 # TCP packet tally
UDP_num = 0 # UDP packet tally

app_layer_protocols = [] # Application protocol tally

# IPs for Geolocation
checked_ips = [] # Checked External IPs for Geolocation
detected_geofiltered_ip = [] # Checked External IPs from Geolocating and FOUND in BlackListed Countries

#Initialize traffic and packet logs
traffic_log = defaultdict(lambda: defaultdict(list))
packet_log = defaultdict(lambda: defaultdict(list))

# graph data
time_window = 60 # Measure Time Window for traffic monitoring
start_time = 0 # Start time of traffic monitoring
traffic_data = {} # Traffic data for graph

# Admin
messages = [] # Messages for remote Admin

# ===========================================
#             Device and User Monitoring
# ===========================================

# User login data and login tracking
user_login_data = []  # Store user login data (timestamp, user, etc.)
blocklist = tracker_block_list()  # Set to store blocked IP addresses (e.g., for ad-blocking)
dns_servers = ['8.8.8.8', '1.1.1.1']  # External DNS servers for name resolution

# ===========================================
#             System Information
# ===========================================

# Current date
current_date = datetime.now().strftime('%Y-%m-%d')  
# Variables for tracking network traffic data
traffic_data = defaultdict(int)  # Track packet counts by protocol/port
# Port Sniffer
sniffer_running = False
# HTTP Filtering
trackers = False
# Bandwidth
stats = {}

# ===========================================
#             Security and Integrity
# ===========================================

# File Integrity and Security
file_integrity_log = []  # Placeholder to log file changes (could use file monitoring tools)
# List for IP Threat Report
reputation_report = [] # For Countermeasures
# Filter Trackers
filter_tracker = False # Trigger to Start Filtering URLs
# Basic AI driven Automated Countermeasures
automation = False # Trigger to Start AI driven Automated Countermeasures
# Buzz_words for packet inspection
buzz_words = ["Attack", "Malware"]

# ===========================================
#             Countermeasures
# ===========================================

# Task Wheel
task_taken = [] # Automated scripts acted on
# Fake injection
fake_data = "AH! AH! AHHHHH! You didn't say the magic word ..." # Fake Data Injection
# Fake data to simulate responses
FAKE_RESPONSES = {
        "default": "Welcome to Example Corp! Unauthorized access is prohibited.",
        "login": "Invalid credentials. Please try again."
    } # Fake dialog
# Block DNS requests for specific malicious domains
malicious_domains = ["example-malicious.com", "malware.com"] # Check for malicious domains

# ===========================================
#                   APIs
# ===========================================

INTEL_API_KEY = ""   

# ===========================================
#             Simulation/Debug
# ===========================================

simulation_options = {
    "target_ip": "127.0.0.1",
    "packet_type": "TCP",
    "port": 80,
    "interval": 1,
    "count": 10,
    "payload": "Hello!"
}

##############################################################################
##############################################################################
##############################################################################
##############################################################################
                                  # Flask #

app = Flask(__name__)
# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# User model
class User(UserMixin):
    def __init__(self, id):
        self.id = id

##############################################################################
##############################################################################
            #             System Logging                      #
# Configure logging for attack events
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s- %(filename)s:%(lineno)d',
    level=logging.DEBUG,  # You can set it to INFO or WARNING to reduce log verbosity
    handlers=[
        logging.StreamHandler(),  # Print to console
        logging.FileHandler(f'logs/activity_log_{current_date}.txt', mode='a')
    ]
)
# Function to change log level dynamically based on user input
def change_log_level(new_level):
    """
    Changes the log level dynamically at runtime.
    """
    levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }

    if new_level in levels:
        logging.getLogger().setLevel(levels[new_level])
        logging.info(f"Log level changed to {new_level}")
    else:
        logging.error(f"Invalid log level: {new_level}")

# Function to log execution time
def log_execution_time(func_name, start_time):
    elapsed_time = time.time() - start_time
    execution_times[func_name] = elapsed_time
    logging.info(f"Execution time for {func_name}: {elapsed_time:.4f} seconds")

##############################################################################
##############################################################################
##############################################################################
                        # Defence/Attack Functions #

def is_valid_ip(src_ip):
    """
    Check if the source IP is part of a trusted network and valid.
    """
    start_time = time.time()
    try:
        ip_obj = ipaddress.IPv4Address(src_ip)
        
        # Check if the source IP belongs to any of the trusted subnets
        for subnet in TRUSTED_SUBNETS:
            if ip_obj in subnet:
                logging.info(f" Validated: {src_ip}.")
                log_execution_time("is_valid_ip", start_time)
                return True

            
        # If it's not in any trusted subnet, it's considered invalid
        logging.warning(f" Failed to validate: {src_ip}.")
        log_execution_time("is_valid_ip", start_time)
        return False
    except ipaddress.AddressValueError:
        logging.error(f" Invalid Format: {src_ip}.")
        log_execution_time("is_valid_ip", start_time)
        return False

def check_ip_spoofing(src_ip):
    """
    Check for IP spoofing by validating the source IP address.
    """
    start_time = time.time()
    if not is_valid_ip(src_ip):
        logging.warning(f" Possible IP spoofing detected from source IP: {src_ip}")
        log_execution_time("check_ip_spoofing", start_time)
        return True  # Flag as possible spoofed IP
    else:
        logging.info(f" No IP spoofing detected from source IP {src_ip}.")
        log_execution_time("check_ip_spoofing", start_time)
        return False  # Valid IP, no spoofing detected
    
def get_mac(ip_address):
    """
    Send an ARP request to get the MAC address of a given IP address.
    """
    start_time = time.time()
    arp_request = scapy.ARP(pdst=ip_address)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    if answered_list:
        logging.info(f" MAC recieved from source IP {ip_address}.")
        log_execution_time("get_mac", start_time)
        return answered_list[0][1].hwsrc  # Return the MAC address of the first response
    else:
        logging.error(f" MAC unable to be recieved from source IP {ip_address}.")
        log_execution_time("get_mac", start_time)
        return None

def check_arp_poisoning(ip_address):
    """
    Check for ARP poisoning by comparing the MAC address of the given IP address.
    If it does not match the expected MAC address, it could be a sign of ARP poisoning.
    """
    start_time = time.time()
    current_mac = get_mac(ip_address)
    
    if current_mac is None:
        logging.warning(f" Unable to verify arp from: {ip_address}.")
        log_execution_time("check_arp_poisoning", start_time)
        return False  # No response from the IP, cannot determine poisoning
    
    expected_mac = KNOWN_MACS.get(ip_address)
    
    if expected_mac and current_mac != expected_mac:
        logging.warning(f"Warning: Possible ARP poisoning detected for IP {ip_address}! Expected MAC: {expected_mac}, but got MAC: {current_mac}")
        log_execution_time("check_arp_poisoning", start_time)
        return True
    else:
        return False

#################- Block IP Address: Defensive
def block_ip(ip_address):
    """
    Blocks an IP address using iptables and logs the event.
    """
    try:
        # Use iptables to block the IP
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        
        # Log the action
        logging.info(f"Blocked IP: {ip_address}")
    except subprocess.CalledProcessError as e:
        # Handle error if iptables command fails
        logging.error(f"Error blocking IP {ip_address}: {e}")

################-unblock IP Defensive
def unblock_ip(ip_address):
    """
    Unblocks an IP address using iptables and logs the event.
    """
    try:
        # Use iptables to unblock the IP
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        
        # Log the action
        logging.info(f"Unblocked IP: {ip_address}")
    except subprocess.CalledProcessError as e:
        # Handle error if iptables command fails
        logging.error(f"Error unblocking IP {ip_address}: {e}")

 ################-
def detect_port_scan(ip_address, time_limit=60):
    """
    Detects port scanning activity from a given IP address.
    """
    current_time = time.time()
    connection_attempts = {}

    # Clean up old connection attempts
    connection_attempts = {ip: attempts for ip, attempts in connection_attempts.items() if current_time - attempts['time'] < time_limit}
    
    # Track connection attempts
    if ip_address not in connection_attempts:
        connection_attempts[ip_address] = {'count': 1, 'time': current_time}
    else:
        connection_attempts[ip_address]['count'] += 1
    
    # Block IP if too many attempts in a short period
    if connection_attempts[ip_address]['count'] > 10:  # More than 10 attempts in 60 seconds
        logging.warning(f"Port scanning detected from IP: {ip_address}. Blocking IP.")

################-
def detect_ddos(ip_address, time_limit=60):
    """
    Detects potential DDoS attack from a given IP address.
    """
    current_time = time.time()
    request_counts = {}

    # Clean up old requests
    request_counts = {ip: count for ip, count in request_counts.items() if current_time - count['time'] < time_limit}
    
    # Count the requests
    if ip_address not in request_counts:
        request_counts[ip_address] = {'count': 1, 'time': current_time}
    else:
        request_counts[ip_address]['count'] += 1
    
    # Block IP if too many requests in a short period
    if request_counts[ip_address]['count'] > 100:  # More than 100 requests in 60 seconds
        logging.warning(f"Potential DDoS attack detected from IP: {ip_address}. Blocking IP.")
        block_ip(ip_address)

################-
def monitor_suspicious_file_access(file_path, allowed_users):
    """
    Monitors access to sensitive files and logs any suspicious access attempts.
    """
    if os.path.exists(file_path):
        file_owner = os.stat(file_path).st_uid
        # Replace with actual method to get current user
        current_user = os.geteuid()  # Get current user ID
        
        if current_user != file_owner and current_user not in allowed_users:
            logging.warning(f"Suspicious file access detected: {file_path} by user {current_user}")


################-
# Function to detect brute-force login attempts based on failed attempts
def detect_brute_force(ip_address, max_attempts=5, time_limit=60):
    """
    Detects brute-force login attempts based on failed login attempts.
    """
    current_time = time.time()
    failed_logins = defaultdict(int)

    # Clean up old failed login attempts
    failed_logins = {ip: attempts for ip, attempts in failed_logins.items() if current_time - attempts['time'] < time_limit}
    
    # Increment failed attempts count for the IP
    if ip_address not in failed_logins:
        failed_logins[ip_address] = {'count': 1, 'time': current_time}
    else:
        failed_logins[ip_address]['count'] += 1
    
    # Block IP if too many failed attempts
    if failed_logins[ip_address]['count'] > max_attempts:
        logging.warning(f"Brute-force detected from IP: {ip_address}. Blocking IP.")
        block_ip(ip_address)

################-
# Defensive: Rate Limiting (Simple)
def rate_limit(ip_address, time_limit=60, max_requests=100):
    """
    Simple rate limiting mechanism to block IPs with excessive requests in a short time.
    """
    start_time = time.time()
    request_counts = defaultdict(int)
    current_time = time.time()

    # Clean up old requests
    request_counts = {ip: count for ip, count in request_counts.items() if current_time - count['time'] < time_limit}

    # Count the requests
    if ip_address not in request_counts:
        request_counts[ip_address] = {'count': 1, 'time': current_time}
    else:
        request_counts[ip_address]['count'] += 1
    
    if request_counts[ip_address]['count'] > max_requests:
        logging.warning(f"Rate limit exceeded for IP: {ip_address}. Blocking IP.")
        block_ip(ip_address)

    log_execution_time("rate_limit", start_time)

################-
# Defensive: IP Reputation Check
def check_ip_reputation(ip_address):
    """
    Checks if an IP address is in a threat intelligence database and blocks if necessary.
    """
    global reputation_report
    start_time = time.time()
    
    # Threat intelligence API endpoint
    threat_intelligence_api = "https://api.abuseipdb.com/api/v2/check"

    # Parameters for the API request
    params = {
    "ipAddress": ip_address,
    "maxAgeInDays": 90  # Optional: Filter reports within the last 90 days
}


    # Headers for authentication
    headers = {
        "Accept": "application/json",
        "Key": INTEL_API_KEY
    }

    try:
        # Sending GET request
        response = requests.get(threat_intelligence_api, headers=headers, params=params)

        # Check response status
        if response.status_code == 200:
            result = response.json()
            data = result["data"]
            reputation_report.append(response.json())
            logging.info(f"Threat intelligence report for {ip_address}: IP Address: {data['ipAddress']}, Public IP: {data['isPublic']}, Abuse Confidence Score: {data['abuseConfidenceScore']}, Country Code: {data['countryCode']}, ISP: {data['isp']}, Domain: {data['domain']}, Total Reports: {data['totalReports']}, Last Reported At: {data['lastReportedAt']}")
        else:
            logging.warning(f"Error: Received status code {response.status_code}")
            logging.warning(f"Response: {response.text}")

    except requests.exceptions.RequestException as e:
        logging.warning(f"An error occurred: {e}")

    log_execution_time("check_ip_reputation", start_time)

##########
# Aggressive: Honeypot Deployment
def deploy_honeypot():
     """
    Deploys a honeypot (fake service) to deceive attackers and gather intelligence.
    Simulates HTTP servers on ports 8080 and 8081.
    """
     global FAKE_RESPONSES 

     def start_honeypot_service(port, response_message):
        """
        Starts a honeypot HTTP service on a given port.
        """

        @app.route("/", methods=["GET", "POST"])
        def honeypot_root():
            # Log interaction details
            attacker_ip = request.remote_addr
            method = request.method
            logging.info(f"Interaction detected on port {port} - IP: {attacker_ip}, Method: {method}")
            return response_message, 200

        @app.route("/login", methods=["POST", "GET"])
        def fake_login():
            attacker_ip = request.remote_addr
            method = request.method
            logging.info(f"Fake login attempt on port {port} - IP: {attacker_ip}, Method: {method}")
            return FAKE_RESPONSES["login"], 401

        # Start the Flask app
        app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

    # Define honeypot ports and messages
     honeypots = [
        {"port": 8080, "message": FAKE_RESPONSES["default"]},
        {"port": 8081, "message": "Service Temporarily Unavailable."}
     ]

    # Deploy honeypots as threads to run concurrently
     for honeypot in honeypots:
        port = honeypot["port"]
        message = honeypot["message"]
        logging.info(f"Deploying honeypot on port {port}...")
        threading.Thread(target=start_honeypot_service, args=(port, message), daemon=True).start()
        pass
     logging.info("Honeypots deployed. Monitoring for activity...")

  #######################
# Aggressive: IP Rerouting (Redirect malicious traffic to a sandboxed environment)
def reroute_ip_traffic(ip_address):
    """
    Forces malicious traffic from an IP to a sandboxed environment by rerouting.
    """
    logging.info(f"Rerouting IP {ip_address} to a sandboxed environment.")

    try:
        subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-s", ip_address, "-j", "DNAT", "--to-destination", "192.168.1.99"], check=True)
        logging.info(f"IP {ip_address} rerouted to sandbox.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error rerouting IP {ip_address}: {e}")
        traceback.print_exc()  

  ####################
def throttle_brute_force(ip_address, time_limit=60, max_attempts=5):
    """
    Slows down responses for suspected brute-force login attempts to frustrate attackers.

    Args:
        ip_address: The IP address of the suspected attacker.
        time_limit: Time frame (in seconds) to count login attempts.
        max_attempts: Maximum allowed attempts before throttling is applied.
    """
    global login_attempts
    start_time = time.time()

    # Record the current timestamp for the IP address
    current_time = time.time()
    login_attempts[ip_address].append(current_time)

    # Filter out old attempts outside the time limit
    login_attempts[ip_address] = [t for t in login_attempts[ip_address] if current_time - t <= time_limit]

    # If the number of attempts exceeds the threshold, block or throttle the IP
    if len(login_attempts[ip_address]) > max_attempts:
        logging.warning(f"Suspicious activity from IP {ip_address}: {len(login_attempts[ip_address])} attempts in {time_limit} seconds.")
        try:
            # Block the IP address temporarily
            block_ip(ip_address)
        except Exception as e:
            logging.error(f"Failed to throttle IP {ip_address}: {e}")

    log_execution_time("throttle_brute_force", start_time)

########################## 
def network_segmentation(ip_address, segment_chain="SEGMENT_1"):
    """
    Segments the network by creating custom iptables chains for specific IP ranges or hosts.
    
    Args:
        ip_address (str): The IP address to isolate in a segment.
        segment_chain (str): The custom chain representing the network segment.
    """
    start_time = time.time()

    try:
        # Create a custom chain for the segment if it doesn't exist
        subprocess.run(["sudo", "iptables", "-N", segment_chain], check=True)
        logging.info(f"Custom chain {segment_chain} created.")

        # Direct traffic from the IP to the segment chain
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", segment_chain],
            check=True
        )
        logging.info(f"Traffic from {ip_address} directed to segment {segment_chain}.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error segmenting IP {ip_address}: {e}")
    finally:
        log_execution_time("network_segmentation", start_time)  

################# 
def deep_packet_inspection(packet):
    """
    Performs deep packet inspection to detect and block suspicious traffic patterns.

    Args:
        packet: A Scapy packet object to analyze.
    """
    global buzz_words
    start_time = time.time()

    try:
        # Example inspection for HTTP payloads
        if packet.haslayer(Raw):  # Inspect raw payloads
            payload = packet[Raw].load.decode(errors="ignore")  # Decode payload safely
            if buzz_words in payload:  # Replace with actual detection logic
                logging.warning(f"Malicious content detected in packet: {packet.summary()}")
                if IP in packet:
                    block_ip(packet[IP].src)
    except Exception as e:
        logging.error(f"Error during packet inspection: {e}")

    log_execution_time("deep_packet_inspection", start_time)

################# 
   # Defensive: DNS Sinkhole
def dns_sinkhole(domain):
    """
    Redirects malicious DNS queries to a sinkhole.
    """
    global malicious_domains
    start_time = time.time()

    if domain in malicious_domains:
        logging.warning(f"DNS request for malicious domain {domain} blocked.")
        # Redirect to local IP (sinkhole)
        subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-d", domain, "-j", "DNAT", "--to-destination", "127.0.0.1"], check=True)

    log_execution_time("dns_sinkhole", start_time)         

################# 
 # Aggressive: IP Spoofing Defense
def detect_ip_spoofing(packet):
    """
    Detects and blocks IP spoofing attempts.
    """
    start_time = time.time()

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Simple check for IP spoofing (invalid source)
        if not is_valid_ip(src_ip):
            logging.warning(f"IP spoofing detected: {src_ip} attempting to impersonate {dst_ip}.")
            block_ip(src_ip)

    log_execution_time("detect_ip_spoofing", start_time)

################# 
 # Aggressive: Fake Data Injection
def fake_data_injection(ip_address, port, fake_data):
    """
    Simulates injecting fake data into an attacker's communication.

    Args:
        ip_address (str): The attacker's IP address.
        port (int): The port to communicate with the attacker.
        fake_data (str): The fake data to send.
    """
    start_time = time.time()

    try:
        # Create a socket to simulate communication
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((ip_address, port))
            server_socket.listen(1)
            logging.info(f"Listening on {ip_address}:{port} for attacker communication.")

            # Accept a connection from the attacker
            conn, attacker_addr = server_socket.accept()
            with conn:
                logging.info(f"Connection established with {attacker_addr}.")
                conn.sendall(fake_data.encode("utf-8"))
                logging.info(f"Injected fake data: {fake_data}")
    except Exception as e:
        logging.error(f"Error injecting fake data: {e}")
    finally:
        log_execution_time("fake_data_injection", start_time)

################# 
# Aggressive: Man-in-the-Middle (MitM) Prevention
def mitm_prevention(ip_address):
    """
    Detects and blocks attempts to intercept network traffic and perform MITM attacks.
    """
    start_time = time.time()

    if check_arp_poisoning(ip_address):
        logging.warning(f"MITM attack detected from IP {ip_address}. Blocking IP.")
        block_ip(ip_address)

    log_execution_time("mitm_prevention", start_time)

##############################################################################
##############################################################################
                        # PACKET Functions #

def get_protocol_name(packet, protocol, ip_dst, ip_src):
    """
    Returns the protocol name and related metadata based on the packet's transport layer and ports.
    """
    global unsigned, TCP_num, UDP_num, app_layer_protocols
    if packet.haslayer("TCP") or packet.haslayer("UDP"):
        # Determine the transport layer
        layer = "TCP" if packet.haslayer("TCP") else "UDP"
        if layer == "TCP":
            TCP_num += 1
        if layer == "UDP":
            UDP_num += 1
        src_port = packet[layer].sport
        dst_port = packet[layer].dport

        # Check the protocol against the mapping
        for  protocol_name, details in protocol_catagorical_params.items():
            if dst_port in details["ports"]:
                 return logging.info(f"src_ip: {ip_src}, dst_ip: {ip_dst} src_port: {src_port}, dst_port: {dst_port}, protocol_name: {protocol_name}")

        # If no match, return unknown protocol
        return logging.info(f"src_ip: {ip_src}, dst_ip: {ip_dst} src_port: {src_port}, dst_port: {dst_port}, protocol_name: Unknown Protocol")
        
    else:
        # If neither TCP nor UDP is present
        return logging.warning(f"Error: Packet does not contain TCP/UDP layers")

def check_threshold(self, src_ip, protocol):
        """Check if packet count exceeds the defined threshold."""
        if protocol in protocols:
            threshold = protocols[protocol].get("threshold", float('inf'))
            if len(traffic_log[src_ip][protocol]) > threshold:
                logging.warning(f"Threshold exceeded for {protocol} from {src_ip}")

def check_packet_size(packet, protocol):
        """Check if packet size exceeds protocol limit."""
        if protocol in protocols:
            packet_size_limit = protocols[protocol].get("packet_size_limit", float('inf'))
            packet_size = len(packet)
            if packet_size > packet_size_limit:
                logging.warning(f"Packet size exceeds limit for {protocol} from {packet[scapy.IP].src} (Size: {packet_size} bytes)")

def check_malicious_patterns(packet):
        """Check for malicious patterns in the packet data."""
        packet_data = bytes(packet)
        for pattern in malicious_patterns:
            if pattern in packet_data:
                logging.warning(f"Malicious pattern detected in packet from {packet[scapy.IP].src}")

def get_country_from_ip(ip):
        """Simulate an IP-to-country lookup."""
        global checked_ips
        if ip not in checked_ips:
            try:
                response = requests.get(f"https://ipinfo.io/{ip}/json")
                if response.status_code == 200:
                    data = response.json()
                    country = data.get('country', 'Unknown')
                    logging.info(f"IP: {ip} is located in country: {country}")
                    if country in geo_blocklist:
                        logging.warning(f"Traffic from {country} (IP: {ip})")
                        detected_geofiltered_ip.append(str(ip)+":"+str(country))
                    checked_ips.append(ip)
                    return country
                else:
                    checked_ips.append(ip)
                    logging.warning(f"Failed to get information for IP: {ip}")
                    return None
            
            except Exception as e:
                logging.warning(f"Error occurred while fetching country for IP: {ip}. Error: {e}")
                return None

def packet_callback(packet):
        """Callback function to handle each captured packet."""
        global time_window, hosts_ip, start_time, filter_tracker, packett
        packett = packet
        time.sleep(time_window)  # Wait for the time window
        elapsed_time = int(time.time() - start_time)
        packet_size = len(packet)

        if packet.haslayer("IP"):
             ip_src = packet["IP"].src
             ip_dst = packet["IP"].dst
             protocol = packet.proto

            # Determine upload or download based on source and destination IP
             if packet.src == hosts_ip:
            # Outgoing packet (Upload)
                upload_bytes += packet_size
             elif packet.dst == hosts_ip:
             # Incoming packet (Download)
                download_bytes += packet_size

             protocol_name = get_protocol_name(packet,protocol,ip_dst, ip_src)
             traffic_data[ip_dst]["time"].append(elapsed_time)

             if upload_bytes:
                traffic_data[ip_src]["upload"].append(upload_bytes)
                upload_bytes = 0
             if download_bytes:   
                traffic_data[ip_dst]["download"].append(download_bytes)
                download_bytes = 0

             traffic_data[ip_dst]["TRANSPORT_LAYER"].append(protocol)
             traffic_data[ip_dst]["APP_LAYER"].append(protocol_name)
      
             traffic_log[ip_src][protocol_name].append(time.time())
             packet_log[ip_src][protocol_name].append(len(packet))

             check_threshold(ip_src, protocol)
             check_packet_size(packet, protocol)
             check_malicious_patterns(packet)
             get_country_from_ip(ip_src)
  
             if filter_tracker == True:
                filter_trackers(packet)

             packet_size = 0
        else: 
            logging.warning("Unsigned packet recieved")

def sniff_packets():
    global sniffer_running, start_time
    if sniffer_running == False:
        sniffer_running = True
         # Record start time
        start_time = time.time()
        print("Starting packet capture...")
        scapy.sniff(prn=packet_callback, store=0)

def filter_trackers(packet):  
    if packet.haslayer(HTTPRequest):
        host = packet[HTTPRequest].Host.decode(errors="ignore")
        path = packet[HTTPRequest].Path.decode(errors="ignore")  
        full_url = f"http://{host}{path}"
        logs.append({"type": "HTTP Request", "url": full_url})
        if any(domain in host for domain in blocklist):
                print(f"Blocked: {full_url}")
            
        
   ################
   

   # Function to generate graph for traffic data ##########################################
def generate_traffic_graph():
    global traffic_data
    labels = list(traffic_data.keys())
    values = list(traffic_data.values())

    fig, ax = plt.subplots()
    ax.barh(labels, values)
    ax.set_xlabel('Packet Count')
    ax.set_ylabel('Protocol/Port')
    ax.set_title('Network Traffic Data')

    # Save graph to BytesIO and encode to base64
    img_io = BytesIO()
    plt.savefig(img_io, format='png')
    img_io.seek(0)
    graph_url = base64.b64encode(img_io.getvalue()).decode()
    return f"data:image/png;base64,{graph_url}"

 # Function to generate traffic data ########################################
def generate_traffic_data():
    # Return traffic data for the frontend
    return dict(traffic_data)

##############################################################################
##############################################################################
##############################################################################
                          # Web UI HOOKS #

@login_manager.user_loader
def load_user(user_id):
    if user_id in USERS:
        return User(user_id)
    return None   

##############################
# Login:

@app.route("/login", methods=["GET", "POST"])
def login():
    activated = time.time()
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username in USERS and USERS[username] == password:
            login_user(User(username))
            log_execution_time("webhook_login", activated)
            logging.info(f"webhook_login from {username}")
            return redirect("/")
        log_execution_time("webhook_login", activated)
        logging.warning(f"Failed webhook_login from {username}")
        return "Invalid credentials", 401 
    log_execution_time("webhook_login", activated)
    logging.info(f"loaded webhook_login")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    activated = time.time()
    log_execution_time("webhook_login", activated)
    logging.info(f"webhook_logged out")
    logout_user()
    return redirect("/login")

##############################
# Page Routes:
@app.route("/")
@login_required
def index():
    monitor_bandwidth()
    return render_template("index.html", logs=logs, primary=admin, stats=stats)

# Control Page
@app.route("/controls")
@login_required
def controls():
    return render_template("controls.html", logs=logs)

@app.route("/devices")
@login_required
def list_devices():
    update_connected_devices()
    return render_template("devices.html", devices=connected_devices, primary=admin)

##############################
# Commands:

@app.route("/simulation", methods=["GET", "POST"])
@login_required
def simulation_controls():
     global simulation_options, log
     if request.method == "POST":
        for key in simulation_options.keys():
            if key in request.form:
                simulation_options[key] = request.form[key]
            try:    
                 with open('logs/activity_log_{current_date}.txt', "r") as loogs:
                    log = loogs.readlines()[-100:]  
            except FileNotFoundError:
                    log = ["No logs available."]
     # Render the template with current options
     return render_template("simulation_options.html", options=simulation_options, logs=logs)

@app.route('/automation')
def index():
    global automation
    if automation == False:
        automation = True
    else:
        automation = False
    return redirect("/control")

@app.route('/run_action/<action>')
def run_action(action):
    global fake_data
    TARGET_IP = request.form.get('ip_address')  # Get the IP address from the form
    action = request.form.get('action')  # Get the selected action

    if action == "block_ip":
        return block_ip(TARGET_IP)
    elif action == "unblock_ip":
        return unblock_ip(TARGET_IP)
    elif action == "reroute_ip_traffic":
        return reroute_ip_traffic(TARGET_IP)
    elif action == "detect_port_scan":
        return detect_port_scan(TARGET_IP)
    elif action == "detect_ddos":
        return detect_ddos(TARGET_IP)
    elif action == "detect_brute_force":
        return detect_brute_force(TARGET_IP)
    elif action == "rate_limit":
        return rate_limit(TARGET_IP)
    elif action == "check_ip_reputation":
        return check_ip_reputation(TARGET_IP)
    elif action == "network_segmentation":
        return network_segmentation(TARGET_IP)
    elif action == "dns_sinkhole":
        return dns_sinkhole("8.8.8.8")
    elif action == "deploy_honeypot":
        return deploy_honeypot()
    elif action == "throttle_brute_force":
        return throttle_brute_force(TARGET_IP)
    elif action == "check_ip_spoofing":
        return check_ip_spoofing(TARGET_IP)
    elif action == "mitm_prevention":
        return mitm_prevention(network_ip_range)
    elif action == "fake_data_injection":
        return fake_data_injection(TARGET_IP, 8080, fake_data)
    else:
        return f"Action {action} not found."

########################################

@app.route("/start_sniffer")
@login_required
def start_sniffer():
    global sniffer_running
    if not sniffer_running:
        sniffer_running = True
        # Start packet sniffing in a separate thread
        sniffing_thread = threading.Thread(target=sniff_packets())
        sniffing_thread.daemon = True  # Make the thread a daemon so it exits when the main program exits
        sniffing_thread.start()
        logging.info(f"Started Packet Sniffer")
    return redirect("/")

#############################

@app.route("/stop_sniffer")
@login_required
def stop_sniffer():
    global sniffer_running
    if sniffer_running:
        sniffer_running = False
        logging.info(f"Stopped Packet Sniffer")
    return redirect("/")

# Port Scanner
@app.route("/scan_ports")
@login_required
def scan_ports():
    nm = nmap.PortScanner()
    devices = scapy.arping(network_ip_range, verbose=0)[0]
    for sent, received in devices:
        ip = received.psrc
        try:
            nm.scan(ip, arguments="-p 1-1024 --open")
            tcp_ports = nm[ip].all_tcp()  # Open TCP ports
            udp_ports = nm[ip].all_udp()  # Open UDP ports
            
            results.append({
                "ip": ip,
                "tcp_ports": tcp_ports,
                "udp_ports": udp_ports
            })
        except Exception as e:
            print(f"Error scanning {ip}: {e}")

    # Render results in HTML template
    return render_template("scan_ports.html", results=results)

# HTTP Ping to Remote Admin ###############################################################################
# Page to send message to admin
@app.route("/notify_admin", methods=["GET", "POST"])
def admin():
    if not admin:
        return "No Remote Administrator device set", 400

    if request.method == "POST":
        data = request.form
        try:
            # Send POST request to the primary device
            response = requests.post(f"http://{admin}:5001/notify", json=data)
            return render_template("notify_admin.html", success=True)
        except Exception as e:
            return render_template("notify_admin.html", error=str(e))

    # Render the form on GET
    return render_template("notify_admin.html")

######################

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        # Handle POST request for webhook (receiving messages)
        data = request.json
        if not data or 'message' not in data:
            return jsonify({"error": "No message in the data"}), 400

        # Store the message
        messages.append(data['message'])
        
        return jsonify({"status": "success", "message": data['message']}), 200

    # Handle GET request for displaying dashboard (showing received messages)
    return render_template("admin_dashboard.html", messages=messages)

##############################
                            #     Traffic              #

# Route to monitor network traffic
@app.route("/network_traffic")
@login_required
def network_traffic():
    monitor_bandwidth()
    # Generate traffic data and graph
    traffic_info = generate_traffic_data()
    traffic_graph = generate_traffic_graph()
    return render_template("network_traffic.html", traffic_data=traffic_info, traffic_graph=traffic_graph, stats=stats)

##############################
                            #     Settings        #

@app.route("/set_admin/<ip>")
@login_required
def set_primary(ip):
    global admin
    admin = ip
    return redirect("/devices")

@app.route("/HTTP_filter_on")
@login_required
def start_filter_HTTP():
    global filter_tracker
    filter_tracker = True
    logging.info(f"Started HTTP Tracker blocking")
    return redirect("/controls")

@app.route("/HTTP_filter_off")
@login_required
def stop_filter_HTTP():
    global filter_tracker
    filter_tracker = False
    logging.info(f"StoppedPacket Sniffer")
    return redirect("/controls")

##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
                        # Primary Defence Organiser #
                        
def detect_intrusions():
    # List to store detected intrusion events
    global automation, task_taken
    
    intrusion_events = []
    
    try:
        with open(f"logs/activity_log_{current_date}.txt", "r") as log:
            logs = log.readlines()[-100:]  
        
      
        ip_regex = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        
        # Check logs for patterns
        for activity in logs:
            for threat_code, threat_info in suspicious_and_threat_patterns.items():
                if threat_code in activity:
                    ip_matches = re.findall(ip_regex, activity)
                    if ip_matches and ip_matches not in hosts_ip:
                        for TARGET_IP in ip_matches:
                            print(f"Found suspicious activity from IP: {TARGET_IP}")


                        response = {
                            "event": threats["description"],
                            "severity": threats["risk_evaluation"],
                            "action": threats["counter_measures"]
                        }
                        
                        # Store the intrusion event
                        intrusion_events.append({
                            "timestamp": time.time(),
                            "event": response["event"],
                            "severity": response["severity"],
                            "source_ip": TARGET_IP,
                            "action": response["action"]
                        })
                        
                    
                    if automation == True:
                        index = intrusion_events["action"]
                        actions_links = ["NONE",
                                block_ip(TARGET_IP),
                                unblock_ip(TARGET_IP),
                                detect_port_scan(TARGET_IP),
                                detect_ddos(TARGET_IP),
                                detect_brute_force(TARGET_IP),
                                rate_limit(TARGET_IP),
                                check_ip_reputation(TARGET_IP),
                                network_segmentation(TARGET_IP),
                                dns_sinkhole("8.8.8.8"),
                                deploy_honeypot(),
                                reroute_ip_traffic(TARGET_IP),
                                throttle_brute_force(TARGET_IP),
                                check_ip_spoofing(TARGET_IP),
                                mitm_prevention(network_ip_range),
                                fake_data_injection(TARGET_IP,8080,fake_data)]
                        task_taken.append(actions_links[index])
                        for script in actions_links:
                            script()

    except Exception as e:
          return intrusion_events

##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
                       #     Debug/Stimulators    #

def simulate_traffic(target_ip, packet_type="TCP", port=80, interval=1, count=10, payload="Hello!"):
    """
    Simulate traffic using Scapy.
    
    Parameters:
    - target_ip (str): The target IP address.
    - packet_type (str): Type of traffic ("TCP", "UDP", "ICMP").
    - port (int): Target port for TCP/UDP traffic.
    - interval (float): Time interval between packets (in seconds).
    - count (int): Number of packets to send.
    - payload (str): Custom payload for the packets.
    """
    print(f"Simulating {packet_type} traffic to {target_ip} on port {port}...")

    try:
        for i in range(count):
            if packet_type.upper() == "TCP":
                pkt = IP(dst=target_ip) / TCP(dport=port) / payload
            elif packet_type.upper() == "UDP":
                pkt = IP(dst=target_ip) / UDP(dport=port) / payload
            else:
                print(f"Unknown packet type: {packet_type}")
                return

            send(pkt, verbose=False)
            print(f"Packet {i+1} sent to {target_ip}.")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Simulation interrupted by user.")
    except Exception as e:
        print(f"Error: {e}")

##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
                     # Network scanning/info functions #

def monitor_bandwidth():
    # Get system bandwidth usage stats
    global stats
    net_io = psutil.net_io_counters()
    stats = {
        "bytes_sent": net_io.bytes_sent,
        "bytes_recv": net_io.bytes_recv,
    }

def update_connected_devices():
    global connected_devices, host_ips
    start_time = time.time()
    devices = scapy.arping(network_ip_range, verbose=0)[0]
    connected_devices = [{"ip": rcv.psrc, "mac": rcv.hwsrc} for _, rcv in devices]
    host_ips = [{"ip": rcv.psrc} for _, rcv in devices]
    logging.info(f" Tested connectiong in {network_ip_range}.")
    log_execution_time("update_connected_devices", start_time)                          
##############################################################################
##############################################################################                       
                          # Run Script #
if __name__ == "__main__":
    # List of required packages to install
    required_packages = [
    'flask',  # Flask framework
    'flask-login',  # Flask login extension
    'scapy',  # Scapy library for packet manipulation
    'nmap',  # Python Nmap library for network scanning
    'requests',  # HTTP library for making requests
    'psutil',  # Library for system monitoring
    'matplotlib',  # Plotting library for charts
    'ipaddress',  # Library for dealing with IP addresses
     ]

    # Function to install missing packages
    def install_package(package):
         subprocess.check_call([sys.executable, "-m", "pip", "install", package])

    # Try importing each package and install it if missing
    for package in required_packages:
        try:
            __import__(package)
            print(f"Package '{package}' is already installed.")
        except ImportError:
            print(f"Package '{package}' not found. Installing...")
            install_package(package)
            print(f"Package '{package}' installed successfully.")

    monitor_bandwidth() # intial bandwidth check
    update_connected_devices() # intial list of devices on network
    app.run(host="0.0.0.0", port=5000)
