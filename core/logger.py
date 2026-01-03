from datetime import datetime
import os
import json
import hmac
import hashlib
import base64

# Generating a secret key

def generate_secret_key():

    return os.urandom(32)


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

    # Converting log entry to a JSON string

    log_json = json.dumps(log_entry)
    log_bytes = log_json.encode('utf-8')

    # Generating HMAC using the secret key

    secret_key = generate_secret_key()
    hmac_digest = hmac.new(secret_key, log_bytes, hashlib.sha256).digest()
    hmac_b64 = base64.b64encode(hmac_digest).decode('utf-8')

    with open("logs/audit.log", "a") as f:
        f.write(f"{log_json}\nHMAC: {hmac_b64}\n")
    
    print(f"Logged: {action} by {username} - {'SUCCESS' if success else 'FAILED'}")

    def verify_hmac(log_entry, hmac_b64):
        secret_key = generate_secret_key()  
        log_bytes = log_entry.encode('utf-8')
        expected_hmac = hmac.new(secret_key, log_bytes, hashlib.sha256).digest()
        expected_hmac_b64 = base64.b64encode(expected_hmac).decode('utf-8')
        return hmac_b64 == expected_hmac_b64
    
    if __name__ == "__main__":
        log_action("user123", "login", "system", True)