# --------------------------------------------------
# Application Protocol Detection
# --------------------------------------------------

def detect_application_protocol(port: int) -> str:
    common_ports = {
        80: "HTTP",
        443: "HTTPS",
        53: "DNS",
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        5228: "Google Services"
    }
    return common_ports.get(port, "Unknown")