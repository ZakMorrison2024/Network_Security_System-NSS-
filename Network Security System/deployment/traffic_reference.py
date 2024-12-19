protocol_catagorical_params = {
    "HTTP": {
        "ports": [80],
        "protocol": "TCP",
        "indicators": [
            "High request rates",
            "Unusual or malformed headers",
            "Excessive POST requests",
            "Large response payloads",
        ],
        "common_uses": [
            "Web browsing and file transfers",
            "API communication for web services",
            "Sending unencrypted data over the internet",
        ],
    },
    "HTTPS": {
        "ports": [443],
        "protocol": "TCP",
        "indicators": [
            "High request rates",
            "Unusual certificate activity",
            "Large encrypted payloads",
        ],
        "common_uses": [
            "Secure web browsing",
            "Encrypted API communication",
            "E-commerce transactions and secure data transfer",
        ],
    },
    "DNS": {
        "ports": [53],
        "protocol": ["UDP", "TCP"],
        "indicators": [
            "High query frequency from a single IP",
            "Unusual domain names (e.g., random strings or suspicious TLDs)",
            "Excessive NXDOMAIN responses",
        ],
        "common_uses": [
            "Resolving domain names to IP addresses",
            "Load balancing and failover systems",
            "Reverse lookups for diagnostics and logging",
        ],
    },
    "FTP": {
        "ports": [21],
        "protocol": "TCP",
        "indicators": [
            "Frequent connection attempts (brute force)",
            "Unusual file uploads/downloads",
            "Anonymous access attempts",
        ],
        "common_uses": [
            "File transfer between client and server",
            "Backup and data synchronization",
            "Accessing large files in enterprise systems",
        ],
    },
    "SSH": {
        "ports": [22],
        "protocol": "TCP",
        "indicators": [
            "Frequent failed login attempts",
            "Unusual commands or activity patterns",
            "Unusual IP addresses connecting",
        ],
        "common_uses": [
            "Secure remote server access",
            "Encrypted tunneling for data transmission",
            "System administration and configuration",
        ],
    },
    "SMTP": {
        "ports": [25, 587],
        "protocol": "TCP",
        "indicators": [
            "High email sending rates",
            "Connections from blacklisted IPs",
            "Unusual email payloads or headers",
        ],
        "common_uses": [
            "Sending emails",
            "Relaying emails between servers",
            "Automated system notifications and alerts",
        ],
    },
    "SNMP": {
        "ports": [161, 162],
        "protocol": "UDP",
        "indicators": [
            "Unusual polling frequency",
            "Requests for sensitive OIDs",
            "Unauthorized SNMP versions",
        ],
        "common_uses": [
            "Monitoring network devices and performance",
            "Gathering device statistics (e.g., CPU, memory)",
            "Configuring routers, switches, and IoT devices",
        ],
    },
    "RDP": {
        "ports": [3389],
        "protocol": "TCP",
        "indicators": [
            "Frequent failed login attempts",
            "Connections from non-standard IP ranges",
            "Unusual session durations",
        ],
        "common_uses": [
            "Remote desktop access for administration",
            "Accessing Windows servers and workstations",
            "Collaborative or remote technical support",
        ],
    },
    "MySQL": {
        "ports": [3306],
        "protocol": "TCP",
        "indicators": [
            "Brute force login attempts",
            "Unusual query patterns",
            "Large data exports",
        ],
        "common_uses": [
            "Relational database management",
            "Storing and retrieving data for web applications",
            "Data warehousing and analytics",
        ],
    },
    "Telnet": {
        "ports": [23],
        "protocol": "TCP",
        "indicators": [
            "Frequent failed login attempts",
            "Unencrypted sensitive data in traffic",
            "Connections from unusual IPs",
        ],
        "common_uses": [
            "Legacy remote command execution",
            "Accessing network devices for configuration",
            "Debugging network issues",
        ],
    },
    "LDAP": {
        "ports": [389, 636],
        "protocol": "TCP",
        "indicators": [
            "High authentication failure rates",
            "Unusual directory queries",
            "Access from unexpected IP ranges",
        ],
        "common_uses": [
            "User authentication and directory services",
            "Managing centralized access control",
            "Storing user and device information in Active Directory",
        ],
    },
    "NetBIOS": {
        "ports": [137, 138, 139],
        "protocol": ["UDP", "TCP"],
        "indicators": [
            "Unexpected broadcast traffic",
            "High traffic volume from a single host",
            "Suspicious file-sharing requests",
        ],
        "common_uses": [
            "File and printer sharing in Windows networks",
            "Legacy LAN communication",
            "Local network name resolution",
        ],
    },
    "SMB": {
        "ports": [445],
        "protocol": "TCP",
        "indicators": [
            "Unauthorized file access attempts",
            "Excessive file transfer activity",
            "Connections from unusual IPs",
        ],
        "common_uses": [
            "File and printer sharing in Windows networks",
            "Accessing shared drives and network resources",
            "Remote access to files and services",
        ],

    "FTP": {
        "ports": [21],
        "protocol": "TCP",
        "indicators": [
            "Frequent connection attempts (brute force)",
            "Unusual file uploads/downloads",
            "Anonymous access attempts",
        ],
        "common_uses": [
            "File transfer between client and server",
            "Backup and data synchronization",
            "Accessing large files in enterprise systems",
        ]
    }


    },
}
