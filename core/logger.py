from datetime import datetime
import os
import json


# ===================== LOGGING ACTION ========================

def log_action(username, action, filename, success):
    
    os.makedirs("logs", exist_ok=True)

    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "username": username or "ANONYMOUS",
        "action": action,
        "filename": filename,
        "success": success
    }

    with open("logs/audit.log", "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    
    print(f"Logged: {action} by {username} - {'SUCCESS' if success else 'FAILED'}")