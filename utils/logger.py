import json
from datetime import datetime

# --------------------------------------------------
# Phase 5 JSON Security Logging
# --------------------------------------------------

def log_security_event(event_type, data, logfile="alerts.json"):

    event = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event": event_type,
        "details": data
    }

    with open(logfile, "a") as f:
        f.write(json.dumps(event) + "\n")