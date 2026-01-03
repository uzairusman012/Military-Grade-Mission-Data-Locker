from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import padding
import os

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

    try:
        # reading the original file data
        with open(file_path, "rb") as f:
            original_data = f.read()
        
        # generating a random IV

        iv = os.urandom(16)

        # creating the AES cipher

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # using PKCS7 padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(original_data) + padder.finalize()
        
        # encrypting the data

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # generating HMAC for integrity

        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(iv + encrypted_data)
        hmac_value = h.finalize()

        # saving IV and encrypted data together

        with open(f"storage/encrypted_{os.path.basename(file_path)}", "wb") as f:
            f.write(iv + encrypted_data + hmac_value)
        
        print(f"File '{file_path}' encrypted successfully with HMAC seal!")
        return True
    except Exception as e:
        print("Encrytion failed: {e}")
        return False


    # ===================== DECRYPTOR ======================

def decrypt_file(encrypted_path, key):

    try:
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

        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # removing PKCS7 padding
        unpadder = padding.PKCS7(128).unpadder()
        try:
            decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        except ValueError:
            print("Invalid padding.")
            return False

        # saving the decrypted data

        with open(f"decrypted_{os.path.basename(encrypted_path)[10:]}", "wb") as f:
            f.write(decrypted_data)
        
        print(f"File decrypted successfully: decrypted_mission_plan.txt")
        return True
    except Exception as e:
        print(f"Decryption failed")
        return False