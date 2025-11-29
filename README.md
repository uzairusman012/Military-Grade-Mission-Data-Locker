# Military-Grade Mission Data Locker

A Python-based secure encryption system designed to protect sensitive mission data, simulating real-world military and cybersecurity practices. It uses AES-256 encryption, HMAC for integrity, role-based access control (RBAC), and audit logging.

## Project Overview
This tool safeguards critical files like flight plans, drone routes, and intelligence notes. It demonstrates modern cryptography in Python, ensuring data is confidential, tamper-proof, and accessible only to authorized users.

## Problem Statement
In high-stakes environments (e.g., military ops or emergency teams), data breaches can cause severe risks. Common vulnerabilities include unauthorized access, tampering, weak passwords, and unencrypted storage. This project addresses these with encryption, integrity checks, and access controls.

## Objectives
- Encrypt files with AES-256.
- Prevent tampering using HMAC.
- Restrict access via user roles.
- Store keys securely with password hashing (Argon2 or PBKDF2).
- Log all access attempts.

## Key Features
- **User Registration & Roles**: Predefined roles like Commander (full access), Pilot/Operator (read-only), Analyst (decryption only), Technician (limited).
- **Strong Password Hashing**: Uses Argon2 or PBKDF2-HMAC-SHA256; passwords are never stored plainly.
- **AES-256 Encryption**: In CBC or GCM mode with random IV for confidentiality.
- **HMAC-SHA256 Integrity Check**: Detects any file modifications; rejects decryption if failed.
- **Role-Based Access**: Verifies user auth, role, and action permissions before access.
- **Audit Logging**: Records username, timestamp, action, file, and success/failure.

## Technologies Used
- Python 3.x
- `cryptography` library (for AES, HMAC, PBKDF2)
- `argon2-cffi` (for password hashing)
- Built-in modules: `os`, `json`, `hashlib`, `getpass`
- Optional: Tkinter for GUI       #not for now

## Folder Structure
Organized repo like this:

military-grade-mission-data-locker/
├── encryption/     # Encryption scripts and utils
├── users/          # User data and roles (e.g., JSON files)
├── logs/           # Audit logs
├── storage/        # Encrypted files
├── main.py         # Main application script
├── requirements.txt 


## Installation
1. Clone the repo: `git clone https://github.com/yourusername/military-grade-mission-data-locker.git`
2. Install dependencies: `pip install -r requirements.txt`
   - requirements.txt content:
     cryptography
     argon2-cffi


## Usage
1. Run `main.py` (or GUI if implemented).
2. Register a user with a role and password.
3. Encrypt/decrypt files based on your role.
4. Check logs for activity.

Example commands (in code):
- Encrypt: Use AES-256 with HMAC.
- Decrypt: Verify role, integrity, then decrypt.

**Note for Beginners**: Test in a safe environment. This is educational— not for real classified data!

## Impact & Use Cases
Teaches secure data handling, cryptography, key management, and access control. Adaptable for military sims, corporate vaults, research docs, or personal storage.

## Contributing
Fork the repo, make changes, and submit a pull request. Beginners welcome—focus on bug fixes or feature adds.


