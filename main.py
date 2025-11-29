from argon2 import PasswordHasher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hmac
import os
import json

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

# ===================== USER REGISTRATION =====================

# function for registering a new user

def register_user():

    # making a directory to store user data if it doesn't exist
    os.makedirs("users", exist_ok=True)

    username = input("Enter your name: ")
    password = input("Enter your password: ")
    role = input("Enter your role: ")

    password_hash = ph.hash(password)

    user_data = {
        "username": username,
        "role": role,
        "password_hash": password_hash
        }
    
    with open(f"users/{username}.json", "w") as f:
        json.dump(user_data, f)

    print(f"User '{username}' registered as '{role}' successfully.")
   

# ==================== LOGIN SYSTEM =====================

# function for logging in a user

def login_user():

    username = input("Enter your name: ")
    password = input("Enter your password: ")

    try:
        with open(f"users/{username}.json", "r") as f:
            user_data = json.load(f)
        
        # verifying the password
        ph.verify(user_data["password_hash"], password)

        # if we reach here, the password is correct, so we will allow login

        print(f"Welcome back {username}! Your role: {user_data['role']}")
        return user_data
    
    except:
        print(f"No ID Card found for the user '{username}' !")
        return None

# ===================== ROLE BASED ACCESS =====================

PERMISSIONS = {
    "Commander": {"encrypt" : True, "decrypt" : True, "delete" : True},
    "Pilot": {"encrypt" : False, "decrypt" : True, "delete" : False},
    "Analyst": {"decrypt" : False, "encrypt" : True, "delete" : False},
    "Technician": {"encrypt" : False, "decrypt" : False, "delete" : False},
}

def check_permission(role, action):
    
    if PERMISSIONS.get(role, {}).get(action, False):
        return True
    
    print(f"Access Denied! {role} cannot {action} files.")
    return False

# ===================== TESTING MENU =====================

logged_in_user = None

while True:
    print("\n================ Military Grade Mission Data Locker ================")

    if logged_in_user:
        print(f"Logged in: {logged_in_user['username']}({logged_in_user['role']})")
    else:
        print("Not logged in.")

    print("1. Register User")
    print("2. Login User")
    print("3. Encrypt File")
    print("4. Decrypt File")
    print("5. Exit")

    choice = input("Enter your choice (1-6): ")
    
    if choice == '1':
        register_user()
    elif choice == '2':
        login_user()
    elif choice == '3':

        if not logged_in_user:
            print("Must login first")
        elif check_permission(logged_in_user['role'], 'encrypt'):
            key = derive_key(input("Enter encryption password: "))
            encrypt_file("mission_plan.txt", key)
    elif choice == '4':

        if not logged_in_user:
            print("Must login first")
        elif check_permission(logged_in_user['role'], 'decrypt'):
            key = derive_key(input("Enter decryption password: "))
            decrypt_file("storage/encrypted_mission_plan.txt", key)
        
    elif choice == '5':

        logged_in_user = None
        print("Logged out successfully!")
    elif choice == '6':
        break
    else:
        print("Invalid choice. Please try again.")


