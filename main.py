import os
import pyotp
from core.crypto import derive_key, encrypt_file, decrypt_file
from core.auth import register_user, login_user, generate_totp_code
from core.access_control import check_permission
from core.logger import log_action
import json
import base64


# ==================== CREATE AND ENCRYPT MISSION FILE =====================
def create_and_encrypt_mission_file(logged_in_user):
    if not logged_in_user:
        print("Must login first")
        return
    
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

    # retrieve the salt for the logged-in user

    try:
        with open(f"users/{logged_in_user['username']}.json", "r") as f:
            user_data = json.load(f)
        salt = base64.b64decode(user_data['salt'])
    except FileNotFoundError:
        print("User data file not found.")
        return
    except json.JSONDecodeError:
        print("Error decoding user data.")
        return

    # immediately encrypt it

    key = derive_key(input("Enter encryption password: "), salt = salt)

    if encrypt_file(filepath, key):
        print(f"Mission file encrypted: storage/encrypted_{filename}")

        # ADD LOGGING HERE

        log_action(logged_in_user['username'], "encrypt", filepath, True)
    else:
        log_action(logged_in_user['username'], "encrypt", filepath, False)



# ===================== MAIN MENU ========================

def main():
    global logged_in_user
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
                create_and_encrypt_mission_file(logged_in_user)
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
                    log_action(logged_in_user['username'], "decrypt", filename, False)

                else:
                    try:
                        with open(f"users/{logged_in_user['username']}.json", "r") as f:
                            user_data = json.load(f)
                        salt = base64.b64decode(user_data['salt'])
                    except FileNotFoundError:
                        print("User data file not found.")
                        return
                    except json.JSONDecodeError:
                        print("Error decoding user data.")
                        return
                    
                    key = derive_key(input("Enter decryption password: "), salt = salt)
                    if decrypt_file(encrypted_path, key):
                        log_action(logged_in_user['username'], "decrypt", encrypted_path, True)
                    else:
                        log_action(logged_in_user['username'], "decrypt", encrypted_path, False)

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


if __name__ == "__main__":
    main()


