
# NSS - Network Security System

A system that uses non-ML AI to monitor and defend against unwanted and potentially threatening traffic.

A sophisticated system leveraging rule-based artificial intelligence to monitor, analyze, and defend against malicious or unwanted network traffic, ensuring proactive threat detection and response without relying on machine learning models

Everything is modular and free to edit.


# FOR EDUCATIONAL PURPOSES ONLY!


## Need to do:
- SO MUCH TESTING ; _ ;
- Clean code and do something about the data structures
- Update "suspicious_and_threat_patterns" data structure
- Fix UI
- Fix Script not working in UI
- Fix Bandwidth test
- Fix logs not showing in Web-UI
- And more!! : _ :

## Personal:
- I have no idea about network security, this thing is 100% flawed, but I tried something left field. (You can say whatever you want man, taunting me for trying is a sign of weakness! :L)
- I haven’t done vigorous testing; that is coming with more improvements.
- This is just a fun project for no reason but to learn.
- I plan on implementing this on a Raspberry Pi next to my hub 🙂

## Installation:
There is a small script at the first run that will install these packages automatically:

### Required packages:
- 'flask',  # Flask framework
- scapy',  # Scapy library for packet manipulation
- nmap',  # Python Nmap library for network scanning
- 'requests',  # HTTP library for making requests
- 'psutil',  # Library for system monitoring
- 'matplotlib',  # Plotting library for charts
- 'ipaddress',  # Library for dealing with IP addresses

Requires `nmap` https://nmap.org/ and `npcap` https://npcap.com/


- pip install flask scapy python-nmap requests psutil matplotlib ipaddress


## TO USE:
- run NSS.py
- goto localhost:5000 in web-browser

## Features:
- **Flask - Web UI** - with various features and commands
- **Scapy - Packet capture**
- Packet Defence tactics against packets and malicious IPs
- Logging system for information

### Pages:
- Admin Dashboard
- Controls
- Devices
- Index
- Login
- Network Traffic Graphics
- Message Administrator
- Scan
- Simulation

## Defensive actions:
- block_ip # Blocks Target IP
- unblock_ip # Unblocks Target IP (Will need to impliment this better!)
- detect_port_scan # Detects if someone is port scanning you
- detect_ddos # Detect Denial of Service Attack
- detect_brute_force # Detect Brute Force Attack
- rate_limit # Limit Requests
- check_ip_reputation # Compares IP Address with External Intelligence Database
- network_segmentation # Segments Network
- dns_sinkhole # DNS Sinkhole
- deploy_honeypot # Honeypot to Scam Invaders
- reroute_ip_traffic # Reroute Traffic
- throttle_brute_force # Limit Requests
- check_ip_spoofing # Check for Spoofing
- mitm_prevention # Prevents Man in the Middle Attack
- Fake_data_injection # "Ah! Ah! Ahhhhhh!, You forgot the magic word!"

### -

Please message me with any problems.

There may not be updates for a while.
