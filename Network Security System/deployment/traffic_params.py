# Define parameters
traffic_control_params = {
    "protocols": {
        "HTTP": {
            "threshold": 20,  # Max 20 HTTP requests per time window
            "packet_size_limit": 2000  # HTTP max packet size: 2 KB
        },
        "SSH": {
            "threshold": 5,  # Max 5 SSH requests
            "packet_size_limit": 500  # SSH max packet size: 500 bytes
        },
        "FTP": {
            "threshold": 10,  # Max 10 FTP connections
            "packet_size_limit": 1500  # FTP max packet size: 1.5 KB
        },
        "DNS": {
            "threshold": 50,  # Max 50 DNS queries
            "packet_size_limit": 512  # DNS max packet size: 512 bytes
        },
    },
    "malicious_patterns": [b"attack", b"malware", b"DROP TABLE"],  # Malicious patterns
    "geo_blocklist": ["RU", "CN"]  # Geo-block Russia and China
}
