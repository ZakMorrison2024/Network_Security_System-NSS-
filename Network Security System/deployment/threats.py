suspicious_and_threat_patterns = {
    # Brute Force and Credential-based Attacks
    "brute force": {
        "counter_measures": [2, 5, 6, 7],
        "risk_evaluation": 0.85,
        "activity_code": 1001,
        "description": "Repeated attempts to guess passwords by trying all possible combinations."
    },

    "credential stuffing": {
        "counter_measures": [2, 7, 10],
        "risk_evaluation": 0.88,
        "activity_code": 1002,
        "description": "Using stolen credentials from data breaches to gain unauthorized access."
    },
    "password spraying": {
        "counter_measures": [2, 5, 7],
        "risk_evaluation": 0.83,
        "activity_code": 1003,
        "description": "Attempting common passwords across many accounts to avoid lockouts."
    },

    # Unauthorized Access and Privilege Escalation
    "unauthorized access": {
        "counter_measures": [1, 9, 11],
        "risk_evaluation": 0.90,
        "activity_code": 2001,
        "description": "Accessing systems or data without proper authorization."
    },
    "privilege escalation": {
        "counter_measures": [9, 11, 12],
        "risk_evaluation": 0.92,
        "activity_code": 2002,
        "description": "Gaining higher access privileges to perform unauthorized actions."
    },
    "account takeover": {
        "counter_measures": [6, 9, 14],
        "risk_evaluation": 0.89,
        "activity_code": 2003,
        "description": "Hijacking a user's account, typically through credential compromise."
    },

    # Network-based Attacks
    "malicious IP": {
        "counter_measures": [1, 3, 9],
        "risk_evaluation": 0.87,
        "activity_code": 3001,
        "description": "Suspicious activity originating from known malicious IP addresses."
    },
    "port scanning": {
        "counter_measures": [1, 4, 9],
        "risk_evaluation": 0.84,
        "activity_code": 3002,
        "description": "Scanning for open network ports to identify vulnerabilities."
    },
    "DDoS attack": {
        "counter_measures": [5, 7, 10],
        "risk_evaluation": 0.95,
        "activity_code": 3003,
        "description": "Overwhelming a system with traffic to make it unavailable."
    },
    "reconnaissance": {
        "counter_measures": [4, 9, 12],
        "risk_evaluation": 0.81,
        "activity_code": 3004,
        "description": "Gathering information about a system for potential exploitation."
    },
    "man-in-the-middle attack": {
        "counter_measures": [11, 13, 15],
        "risk_evaluation": 0.93,
        "activity_code": 3005,
        "description": "Intercepting and altering communication between two parties."
    },

    # Data Theft and Exfiltration
    "data exfiltration": {
        "counter_measures": [1, 10, 12],
        "risk_evaluation": 0.91,
        "activity_code": 4001,
        "description": "Unauthorized transfer of sensitive data outside a network."
    },
    "unusual data transfer": {
        "counter_measures": [11, 10, 12],
        "risk_evaluation": 0.88,
        "activity_code": 4002,
        "description": "Anomalous volume or frequency of data transfers."
    },
    "unencrypted transmission": {
        "counter_measures": [11, 10, 12],
        "risk_evaluation": 0.85,
        "activity_code": 4003,
        "description": "Sending data without encryption, exposing it to interception."
    },
    "fileless malware": {
        "counter_measures": [11, 13, 14],
        "risk_evaluation": 0.89,
        "activity_code": 4004,
        "description": "Malware that operates in memory without using traditional files."
    },

    # Insider Threats and Suspicious User Behavior
    "insider threat": {
        "counter_measures": [12, 14],
        "risk_evaluation": 0.80,
        "activity_code": 5001,
        "description": "Threats originating from employees or trusted insiders."
    },
    "unusual login hours": {
        "counter_measures": [14],
        "risk_evaluation": 0.75,
        "activity_code": 5002,
        "description": "Logins occurring outside of normal working hours."
    },
    "high-volume file access": {
        "counter_measures": [12, 14],
        "risk_evaluation": 0.82,
        "activity_code": 5003,
        "description": "Accessing a large number of files in a short timeframe."
    },
    "suspicious user behavior": {
        "counter_measures": [14],
        "risk_evaluation": 0.79,
        "activity_code": 5004,
        "description": "Behavior that deviates from typical user activity patterns."
    },

    # Application and System Exploits
    "SQL injection": {
        "counter_measures": [11, 12, 14],
        "risk_evaluation": 0.91,
        "activity_code": 6001,
        "description": "Injecting malicious SQL queries to manipulate databases."
    },
    "cross-site scripting (XSS)": {
        "counter_measures": [11, 12, 14],
        "risk_evaluation": 0.87,
        "activity_code": 6002,
        "description": "Injecting scripts into web applications to attack users."
    },
    "remote code execution": {
        "counter_measures": [11, 12, 14],
        "risk_evaluation": 0.92,
        "activity_code": 6003,
        "description": "Executing malicious code remotely on a target system."
    },

    # Phishing and Social Engineering
    "phishing attempt": {
        "counter_measures": [11, 12],
        "risk_evaluation": 0.86,
        "activity_code": 7001,
        "description": "Deceptive emails or messages to steal sensitive information."
    },
    "spear phishing": {
        "counter_measures": [11, 12],
        "risk_evaluation": 0.88,
        "activity_code": 7002,
        "description": "Highly targeted phishing aimed at specific individuals."
    },
    "social engineering": {
        "counter_measures": [14],
        "risk_evaluation": 0.79,
        "activity_code": 7003,
        "description": "Manipulating people into revealing confidential information."
    },

    # Malicious Software and Malware Detection
    "malware infection": {
        "counter_measures": [11, 12, 13],
        "risk_evaluation": 0.94,
        "activity_code": 8001,
        "description": "Infecting systems with harmful software to damage or control them."
    },
    "ransomware": {
        "counter_measures": [11, 12, 13],
        "risk_evaluation": 0.96,
        "activity_code": 8002,
        "description": "Encrypting data and demanding a ransom for decryption."
    },
    "trojan horse": {
        "counter_measures": [11, 12, 13],
        "risk_evaluation": 0.93,
        "activity_code": 8003,
        "description": "Malware disguised as legitimate software to gain access."
    },
    "backdoor access": {
        "counter_measures": [11, 12, 13],
        "risk_evaluation": 0.91,
        "activity_code": 8004,
        "description": "Creating unauthorized access points in systems for later use."
    },
       #"Data Integrity and System Anomalies"
        "system integrity breach": {
            "counter_measures": [12, 14],
            "risk_evaluation": 0.8,
            "activity_code": 9001,
            "description": "Compromising the integrity of a system's files or configurations."
        },
        "rootkit detected": {
            "counter_measures": [11, 12, 13],
            "risk_evaluation": 0.9,
            "activity_code": 9002,
            "description": "Identifying malicious software that hides its presence on a system."
        },
        "file integrity violation": {
            "counter_measures": [12, 14],
            "risk_evaluation": 0.75,
            "activity_code": 9003,
            "description": "Detecting unauthorized changes to files that compromise their integrity."
        },
        "unusual outbound traffic": {
            "counter_measures": [11, 12, 10],
            "risk_evaluation": 0.85,
            "activity_code": 9004,
            "description": "Observing abnormal data transfer patterns from within the network."
        },
    
        # External Threats
        "botnet traffic": {
            "counter_measures": [1, 5, 9],
            "risk_evaluation": 0.7,
            "activity_code": 9005,
            "description": "Network traffic originating from a botnet, often used for DDoS attacks or spam."
        },
        "command and control communication": {
            "counter_measures": [11, 12, 9],
            "risk_evaluation": 0.9,
            "activity_code": 9006,
            "description": "Malicious communication between compromised devices and their command servers."
        },
        "CVE exploitation": {
            "counter_measures": [11, 9],
            "risk_evaluation": 0.85,
            "activity_code": 9007,
            "description": "Exploiting known vulnerabilities (CVE) in software to gain unauthorized access."
        },
        "zero-day attack": {
            "counter_measures": [11, 13, 14],
            "risk_evaluation": 0.95,
            "activity_code": 9008,
            "description": "Exploiting an unknown vulnerability that has not yet been patched."
        },
    
        # General Anomalies and Suspicious Behavior
        "anomalous login location": {
            "counter_measures": [9, 14],
            "risk_evaluation": 0.6,
            "activity_code": 9009,
            "description": "Logins from unusual or untrusted locations, potentially indicating unauthorized access."
        },
        "unusual packet size": {
            "counter_measures": [11, 12],
            "risk_evaluation": 0.65,
            "activity_code": 9010,
            "description": "Packets that deviate significantly from normal size, possibly used for data exfiltration."
        },
        "suspicious API calls": {
            "counter_measures": [11, 12],
            "risk_evaluation": 0.7,
            "activity_code": 9011,
            "description": "Unusual or unauthorized API requests that could be indicative of an attack."
        },
        "malicious script execution": {
            "counter_measures": [11, 12, 14],
            "risk_evaluation": 0.8,
            "activity_code": 9012,
            "description": "Execution of scripts that are likely to be malicious, including XSS or injection attacks."
        },
        "unauthorized device connection": {
            "counter_measures": [14],
            "risk_evaluation": 0.75,
            "activity_code": 9013,
            "description": "Devices connecting to the network without proper authorization or credentials."
        },
        "unusual network latency": {
            "counter_measures": [5, 7, 11],
            "risk_evaluation": 0.6,
            "activity_code": 9014,
            "description": "Network latency spikes, which can indicate a DDoS attack or other malicious activity."
        },
        "system misconfiguration": {
            "counter_measures": [10, 12],
            "risk_evaluation": 0.55,
            "activity_code": 9015,
            "description": "Incorrect configuration of systems or devices, leading to potential vulnerabilities."
        },
        "unauthorized cloud access": {
            "counter_measures": [14],
            "risk_evaluation": 0.8,
            "activity_code": 9016,
            "description": "Access to cloud services without proper authorization or credentials."
        },
        "unauthorized application installation": {
            "counter_measures": [14],
            "risk_evaluation": 0.7,
            "activity_code": 9017,
            "description": "Installation of applications or software without appropriate permissions or oversight."
        },
        "network sniffing": {
            "counter_measures": [11, 12],
            "risk_evaluation": 0.75,
            "activity_code": 9018,
            "description": "Intercepting network traffic to capture sensitive data, such as passwords or encryption keys."
        },
        "data manipulation": {
            "counter_measures": [11, 12],
            "risk_evaluation": 0.85,
            "activity_code": 9019,
            "description": "Tampering with data to alter its integrity, often for malicious purposes."
        },
        "unauthorized VPN access": {
            "counter_measures": [1, 14],
            "risk_evaluation": 0.7,
            "activity_code": 9020,
            "description": "Accessing a private network via VPN without proper authorization or credentials."
        },
        "DNS poisoning": {
            "counter_measures": [12, 14],
            "risk_evaluation": 0.85,
            "activity_code": 9021,
            "description": "Manipulating DNS records to redirect traffic to malicious websites or intercept data."
        },
        "remote desktop protocol (RDP) brute force": {
            "counter_measures": [2, 5],
            "risk_evaluation": 0.9,
            "activity_code": 9022,
            "description": "Attempting to guess RDP credentials through repeated login attempts (brute force)."
        },
}