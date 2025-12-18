from argon2 import PasswordHasher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hmac
from datetime import datetime
import os
import json
import pyotp
import base64

ph = PasswordHasher()
# ===================== KEY MAKER =====================
# function to derive a key from password using PBKDF2

def derive_key(password, salt=b'my_fixed_salt'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )

    return kdf.derive(password.encode())

# ===================== TOTP HELPER ===================

def generate_totp_code(secret):
    totp = pyotp.TOTP(secret)
    return totp.now()

# ===================== ENCRYPTOR =====================

def encrypt_file(file_path, key):

    # reading the original file data
    with open(file_path, "rb") as f:
        original_data = f.read()
    
    # generating a random IV

    iv = os.urandom(16)

    # creating the AES cipher

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # padding the data

    while len(original_data) % 16 != 0:
        original_data += b' '
    
    # encrypting the data

    encrypted_data = encryptor.update(original_data) + encryptor.finalize()

    # generating HMAC for integrity

    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(iv + encrypted_data)
    hmac_value = h.finalize()

    # saving IV and encrypted data together

    with open(f"storage/encrypted_{os.path.basename(file_path)}", "wb") as f:
        f.write(iv + encrypted_data + hmac_value)
    
    print(f"File '{file_path}' encrypted successfully with HMAC seal!")
    log_action(logged_in_user['username'] if logged_in_user else "SYSTEM", "encrypt", file_path, True)

# ===================== DECRYPTOR ======================

def decrypt_file(encrypted_path, key):

    # reading the encrypted file data
    with open(encrypted_path, "rb") as f:
        data = f.read()
    
    # extracting IV, encrypted data, and HMAC

    iv = data[:16]
    hmac_value = data[-32:]
    encrypted_data = data[16:-32]

    # verifying HMAC

    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(iv + encrypted_data)
    h.verify(hmac_value)

    # creating the AES cipher for decryption

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # decrypting the data

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # removing padding

    decrypted_data = decrypted_data.rstrip(b' ')

    # saving the decrypted data

    with open(f"decrypted_{os.path.basename(encrypted_path)[10:]}", "wb") as f:
        f.write(decrypted_data)
    
    print(f"File decrypted successfully: decrypted_mission_plan.txt")
    log_action(logged_in_user['username'] if logged_in_user else "SYSTEM", "decrypt", encrypted_path, True)




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

# ==================== CREATE AND ENCRYPT MISSION FILE =====================
def create_and_encrypt_mission_file():
    
    filename = input("Enter mission filename (e.g., op_night_hawk.txt): ")
    print("Enter mission content (type 'EOF' on a new line when done): ")

    lines = []
    while True:
        line = input()
        if line.strip().upper() == "EOF":
            break
        lines.append(line)

    content = "\n".join(lines)

    #creating the file

    filepath = f"mission_files/{filename}"
    with open(filepath, "w") as f:
        f.write(content)

    print(f"Mission file created successfully: {filepath}")

    # immediately encrypt it

    key = derive_key(input("Enter encryption password: "))
    encrypt_file(filepath, key)

    print(f"Mission file encrypted and saved to storage/encrypted_{filename}")


# ===================== USER REGISTRATION =====================

def register_user():

    # making a directory to store user data if it doesn't exist
    os.makedirs("users", exist_ok=True)

    username = input("Enter your name: ").strip()
    password = input("Enter your password: ")
    role = input("Enter your role (Analyst/Commander/Pilot/Technician): ")

    password_hash = ph.hash(password)

    totp_secret = pyotp.random_base32()

    user_data = {
        "username": username,
        "role": role,
        "password_hash": password_hash,
        "totp_secret": totp_secret
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
        
        # verifying the password
        ph.verify(user_data["password_hash"], password)

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
    
    except:
        print("Login failed")
        log_action(username, "login", "system", False)
        return None



# ===================== ROLE BASED ACCESS =====================

PERMISSIONS = {
    "Commander": {"encrypt" : True, "decrypt" : True, "delete" : True},
    "Pilot": {"encrypt" : False, "decrypt" : True, "delete" : False},
    "Analyst": {"encrypt" : False, "decrypt" : True, "delete" : False},
    "Technician": {"encrypt" : False, "decrypt" : False, "delete" : False},
}

def check_permission(role, action):
    
    if PERMISSIONS.get(role, {}).get(action, False):
        return True
    
    print(f"Access Denied! {role} cannot {action} files.")
    return False



# ===================== MAIN MENU ========================

logged_in_user = None

while True:
    print("\n================== Military Grade Mission Data Locker ==================")

    if logged_in_user:
        print(f"Logged in: {logged_in_user['username']}({logged_in_user['role']})")
    else:
        print("Not logged in.")

    print("1. Register User")
    print("2. Login User")
    print("3. Create & Encrypt Mission File")
    print("4. Decrypt File")
    print("5. Logout")
    print("6. Exit")
    print("9. Generate TOTP Code (for testing)")

    choice = input("Enter your choice (1-6 or 9): ")
    
    if choice == '1':
        register_user()

    elif choice == '2':
        logged_in_user = login_user()

    elif choice == '3':
        if not logged_in_user:
            print("Must login first")
        elif check_permission(logged_in_user['role'], 'encrypt'):
            create_and_encrypt_mission_file()
        else:
            print("Access Denied")

    elif choice == '4':
        if not logged_in_user:
            print("Must login first")
        elif check_permission(logged_in_user['role'], 'decrypt'):
            filename = input("Enter file to decrypt: ")
            encrypted_path = f"storage/encrypted_{filename}"
            if not os.path.exists(encrypted_path):
                print(f"Encrypted File '{encrypted_path}' not found.")
            else:
                key = derive_key(input("Enter decryption password: "))
                decrypt_file(encrypted_path, key)

    elif choice == '5':
        if logged_in_user:
            log_action(logged_in_user['username'], "logout", "system", True)
        logged_in_user = None
        print("Logged out successfully!")

    elif choice == '6':
        break

    elif choice == '9':
        secret = input("Enter your TOTP secret to generate code: ")
        print(f"Current 6 digit TOTP code: {generate_totp_code(secret)}")    
    else:
        print("Invalid choice. Please try again.")


