from argon2 import PasswordHasher
import os
import json
import pyotp
import base64
from core.logger import log_action

ph = PasswordHasher()


# ===================== TOTP HELPER ===================

def generate_totp_code(secret):
    totp = pyotp.TOTP(secret)
    return totp.now()


# ===================== USER REGISTRATION =====================

def register_user():

    # making a directory to store user data if it doesn't exist
    
    os.makedirs("users", exist_ok=True)

    username = input("Enter your name: ").strip()
    password = input("Enter your password: ")
    role = input("Enter your role (Analyst/Commander/Pilot/Technician): ")

    password_hash = ph.hash(password)

    # Generate a unique salt for each user

    salt = os.urandom(16)
    base64_salt = base64.b64encode(salt).decode('utf-8')

    totp_secret = pyotp.random_base32()

    user_data = {
        "username": username,
        "role": role,
        "password_hash": password_hash,
        "totp_secret": totp_secret,
        "salt": base64_salt
        }
    
    with open(f"users/{username}.json", "w") as f:
        json.dump(user_data, f)

    print(f"User '{username}' registered as '{role}' successfully.")
    print(f"Your TOTP secret (store this safely) is: {totp_secret}")
    print(f"Current 6 digit TOTP code: {generate_totp_code(totp_secret)}")
    print(f"Save this! You will need it to generate 2FA codes.")
   

# ==================== LOGIN SYSTEM =====================

# function for logging in a user

def login_user():

    username = input("Enter your name: ").strip()
    password = input("Enter your password: ")

    try:
        with open(f"users/{username}.json", "r") as f:
            user_data = json.load(f)

        # Retrieve the salt from the user data
        base64_salt = user_data['salt']
        salt = base64.b64decode(base64_salt)    
        
        # verifying the password
        if not ph.verify(user_data["password_hash"], password):
            print("Invalid password.")
            log_action(username, "login", "system", False)
            return None

        # verifying TOTP
        totp_secret = user_data.get("totp_secret")
        if totp_secret:
            print("Two factor authentication is required.")
            user_code = input("Enter 6 digit TOTP code: ")

            totp = pyotp.TOTP(totp_secret)
            if not totp.verify(user_code, valid_window=1):
                print("Invalid TOTP code.")
                log_action(username, "login", "system", False)
                return None

        # if we reach here, the password is correct, so we will allow login

        print(f"Welcome back {username}! Your role: {user_data['role']}")
        log_action(username, "login", "system", True)
        return user_data
    
    except FileNotFoundError:
        print("User not found")
        log_action(username, "login", "system", False)
        return None
    except Exception as e:
        print(f"Login failed: {e}")
        log_action(username, "login", "system", False)
        return None