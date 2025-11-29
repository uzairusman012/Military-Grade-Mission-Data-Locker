from argon2 import PasswordHasher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
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

    # saving IV and encrypted data together

    with open(f"storage/encrypted_{os.path.basename(file_path)}", "wb") as f:
        f.write(iv + encrypted_data)
    
    print(f"File '{file_path}' encrypted successfully.")

# ===================== USER MANAGEMENT =====================

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


# ===================== TEST MENU =====================

while True:
    print("\n================ Military Grade Mission Data Locker ================")
    print("1. Register User")
    print("2. Login User")
    print("3. Encrypt Mission File")
    print("4. Exit")

    choice = input("Enter your choice (1-4): ")
    
    if choice == '1':
        register_user()
    elif choice == '2':
        login_user()
    elif choice == '3':
        key = derive_key("testing123")
        encrypt_file("mission_plan.txt", key)
    elif choice == '4':
        print("Exiting...")
        break
    else:
        print("Invalid choice. Please try again.")


