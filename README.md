# 🔐 Military Grade Mission Data Locker

<div align="center">

**A Secure File Encryption System with Multi-Factor Authentication and Role-Based Access Control**

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-AES--256-red.svg)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

</div>

---

## 👥 Project Team

<div align="center">

<table>
<tr>
<td align="center" width="350px">

### 👨‍💻 Project Lead

<img src="https://github.com/uzairusman012.png" width="120px;" alt="Profile Picture" style="border-radius: 50%; border: 3px solid #00ff00;"/>

**🎓 M Uzair Usman**

`Lead Developer & Security Architect`

<a href="https://github.com/uzairusman012">
<img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white" />
</a>
<a href="mailto:muzairusman2@gmail.com">
<img src="https://img.shields.io/badge/Email-D14836?style=for-the-badge&logo=gmail&logoColor=white" />
</a>

**📋 Responsibilities:**
- Core Architecture Design
- Cryptographic Implementation
- Security Protocol Development
- Code Review & Testing

</td>
<td align="center" width="350px">

### 🤝 Contributor

<img src="https://github.com/Husnain-Shahid.png" width="120px;" alt="Contributor Picture" style="border-radius: 50%; border: 3px solid #0088ff;"/>

**🎓 Husnain Shahid**

`Developer & Documentation Specialist`

<a href="https://github.com/Husnain-Shahid">
<img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white" />
</a>
<a href="mailto:husnainshahid146276@gmail.com">
<img src="https://img.shields.io/badge/Email-D14836?style=for-the-badge&logo=gmail&logoColor=white" />
</a>

**📋 Contributions:**
- Feature Development
- Documentation & README
- Testing & Debugging
- GUI Development

</td>
</tr>
</table>

### 📊 Project Overview

```text
🏫 Institution:     COMSATS University, Sahiwal
📚  Course:         Information Security (Semester Project)
⏱️ Development:     November 2025 - January 2026  
🔐 Focus:           Cryptography & Access Control                                                  
👥 Team Size:       2 Developers
```

### 🛠️ Tech Stack Used

`Python` `Cryptography` `Argon2` `AES-256` `HMAC` `TOTP` `PBKDF2`

### 💡 Learning Outcomes

✅ Applied modern cryptographic algorithms  
✅ Implemented secure authentication systems  
✅ Designed role-based access control  
✅ Built audit logging mechanisms  
✅ Integrated multi-factor authentication  

```
╔═══════════════════════════════════════════════════════════════════════╗
║  "Security is not a product, but a process."                          ║
║                                        - Bruce Schneier                ║
╚═══════════════════════════════════════════════════════════════════════╝
```

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Security Architecture](#security-architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Role-Based Permissions](#role-based-permissions)
- [Project Structure](#project-structure)
- [Technical Details](#technical-details)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

---

## 🎯 Overview

**Military Grade Mission Data Locker** is a robust, security-focused file encryption system designed as an undergraduate Information Security project. It implements industry-standard cryptographic practices to ensure confidential data remains protected with multiple layers of security including encryption, authentication, and access control.

This system simulates a secure military-grade file storage environment where sensitive mission files are encrypted, and access is strictly controlled based on user roles and authentication levels.

---

## ✨ Features

### 🔒 Core Security Features

- **AES-256-CBC Encryption**: Military-grade symmetric encryption for file protection
- **PBKDF2 Key Derivation**: Secure password-based key generation with 100,000 iterations
- **HMAC Integrity Verification**: SHA-256 based message authentication codes to detect tampering
- **Two-Factor Authentication (2FA)**: Time-based One-Time Password (TOTP) implementation
- **Argon2 Password Hashing**: Modern, secure password storage using Argon2 algorithm

### 👥 User Management

- **User Registration System**: Secure account creation with role assignment
- **Multi-Factor Login**: Password + TOTP verification for enhanced security
- **Role-Based Access Control (RBAC)**: Four distinct user roles with granular permissions
- **Session Management**: Secure login/logout with activity tracking

### 📁 File Operations

- **Mission File Creation**: Interactive file creation with immediate encryption
- **Secure Encryption**: Automatic IV generation and HMAC sealing
- **Secure Decryption**: Integrity verification before decryption
- **Audit Logging**: Complete activity tracking with timestamps

### 📊 Audit & Compliance

- **Comprehensive Logging**: All user actions logged with timestamps
- **JSON-formatted Logs**: Structured logging for easy parsing and analysis
- **Success/Failure Tracking**: Detailed records of authentication and file operations

---

## 🛡️ Security Architecture

### Cryptographic Components

| Component | Implementation | Purpose |
|-----------|---------------|---------|
| **Encryption** | AES-256-CBC | Symmetric file encryption |
| **Key Derivation** | PBKDF2-HMAC-SHA256 | Password-to-key conversion |
| **Password Hashing** | Argon2 | Secure password storage |
| **Integrity Check** | HMAC-SHA256 | Tampering detection |
| **2FA** | TOTP (RFC 6238) | Time-based OTP authentication |

### Security Flow

```
User Input → Password Hashing (Argon2)
                     ↓
          TOTP Verification (2FA)
                     ↓
          Role-Based Permission Check
                     ↓
          PBKDF2 Key Derivation
                     ↓
          AES-256-CBC Encryption/Decryption
                     ↓
          HMAC Verification
                     ↓
          Audit Log Entry
```

---

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Required Libraries

Install all dependencies using pip:

```bash
pip install argon2-cffi cryptography pyotp
```

Or create a `requirements.txt`:

```txt
argon2-cffi>=21.3.0
cryptography>=41.0.0
pyotp>=2.9.0
```

Then install:

```bash
pip install -r requirements.txt
```

### Setup

1. **Clone or download the project**

```bash
git clone <repository-url>
cd military-grade-mission-data-locker
```

2. **Create required directories**

```bash
mkdir users mission_files storage logs
```

3. **Run the application**

```bash
python main.py
```

---

## 🚀 Usage

### 1. Register a New User

```
Choose option 1: Register User
- Enter username
- Enter password (will be hashed with Argon2)
- Select role (Commander/Pilot/Analyst/Technician)
- Save the provided TOTP secret for 2FA
```

**⚠️ Important**: Store your TOTP secret safely! You'll need it for generating 2FA codes.

### 2. Login

```
Choose option 2: Login User
- Enter username
- Enter password
- Enter 6-digit TOTP code (generated from your TOTP secret)
```

Use option 9 to generate TOTP codes from your secret if needed.

### 3. Create and Encrypt Mission Files

```
Choose option 3: Create & Encrypt Mission File
- Requires: Commander role
- Enter filename (e.g., op_night_hawk.txt)
- Enter mission content (line by line)
- Type 'EOF' when done
- Enter encryption password
- File is automatically encrypted and stored
```

### 4. Decrypt Files

```
Choose option 4: Decrypt File
- Requires: Commander, Pilot, or Analyst role
- Enter encrypted filename
- Enter decryption password
- File is decrypted and integrity-verified
```

### 5. View Audit Logs

All activities are logged in `logs/audit.log` with:
- Timestamp (ISO format)
- Username
- Action performed
- Filename involved
- Success/failure status

---

## 👤 Role-Based Permissions

| Role | Encrypt Files | Decrypt Files | Delete Files |
|------|--------------|---------------|--------------|
| **Commander** | ✅ | ✅ | ✅ |
| **Pilot** | ❌ | ✅ | ❌ |
| **Analyst** | ❌ | ✅ | ❌ |
| **Technician** | ❌ | ❌ | ❌ |

### Role Descriptions

- **Commander**: Full access to all operations (create, encrypt, decrypt, delete)
- **Pilot**: Can decrypt mission files for field operations
- **Analyst**: Can decrypt files for intelligence analysis
- **Technician**: Limited access (can only view, no cryptographic operations)

---

## 📁 Project Structure

```
MILITARY-GRADE-MISSION-DATA-LOCKER/
│
├── main.py                          # Main application file
├── README.md                        # Project documentation
├── requirements.txt                 # Python dependencies
│
├── users/                           # User credential storage
│   └── <username>.json             # Individual user data files
│
├── mission_files/                   # Plaintext mission files (pre-encryption)
│   └── <filename>.txt
│
├── storage/                         # Encrypted files storage
│   └── encrypted_<filename>        # AES-256 encrypted files
│
└── logs/                            # Audit logs
    └── audit.log                    # JSON-formatted activity log
```

---

## 🔧 Technical Details

### Key Derivation Function (PBKDF2)

```python
Algorithm: SHA-256
Key Length: 32 bytes (256 bits)
Salt: Fixed salt (configurable)
Iterations: 100,000
```

### AES Encryption Parameters

```python
Algorithm: AES
Mode: CBC (Cipher Block Chaining)
Key Size: 256 bits
Block Size: 128 bits
IV: Random 16 bytes (generated per encryption)
Padding: PKCS#7 (space padding)
```

### HMAC Configuration

```python
Algorithm: SHA-256
Key: Same as encryption key
Purpose: Integrity verification
Output: 32 bytes
```

### Password Hashing (Argon2)

```python
Variant: Argon2id
Memory Cost: Default (65536 KB)
Time Cost: Default (3 iterations)
Parallelism: Default (4 threads)
Salt: Auto-generated
```

### TOTP Settings

```python
Algorithm: SHA-1 (TOTP standard)
Digits: 6
Period: 30 seconds
Valid Window: ±1 period (90 seconds total)
```

---

## 📸 Screenshots

### Main Menu
```
================== Military Grade Mission Data Locker ==================
Logged in: john_doe(Commander)
1. Register User
2. Login User
3. Create & Encrypt Mission File
4. Decrypt File
5. Logout
6. Exit
9. Generate TOTP Code (for testing)
```

### Sample Audit Log Entry
```json
{
  "timestamp": "2024-12-18T14:32:45.123456",
  "username": "john_doe",
  "action": "encrypt",
  "filename": "mission_files/op_night_hawk.txt",
  "success": true
}
```

---

## 🤝 Contributing

This is an academic project, but contributions and suggestions are welcome!

### Areas for Enhancement

- [ ] Add database support for user management
- [ ] Implement file sharing between users
- [ ] Support for multiple encryption algorithms
- [ ] Implement file version control
- [ ] Add backup and recovery mechanisms
- [ ] Integrate hardware security module (HSM) support

---

## 📄 License

MIT License

Copyright (c) 2024 M Uzair Usman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## 📚 Course Information

<div align="center">

| Attribute | Details |
|-----------|---------|
| **Subject** | Information Security |
| **Level** | Undergraduate |
| **Project Type** | Semester Final Project |
| **Academic Year** | 2025 |
| **Institution** | COMSATS University, Sahiwal |
| **Department** | Software Engineering |

</div>

---

## 🙏 Acknowledgments

- **Cryptography Library**: [pyca/cryptography](https://cryptography.io/)
- **Argon2**: [Password Hashing Competition Winner](https://www.password-hashing.net/)
- **PyOTP**: [TOTP/HOTP Implementation](https://pyauth.github.io/pyotp/)
- Course Instructor and Teaching Assistants

---

## ⚠️ Disclaimer

This project is designed for **educational purposes** as part of an undergraduate Information Security course. While it implements industry-standard cryptographic practices, it should not be used for actual military or highly sensitive operations without proper security audit and professional review.

**⚠️ Important Notes:**
- This is an academic demonstration project
- Professional security audit recommended for production use
- Use at your own risk for any real-world applications
- Ensure compliance with local laws and regulations

---

<div align="center">

**Made with 🔒 and ❤️ for Information Security**

⭐ Star this repository if you found it helpful!

---

### 📊 Repository Stats

![GitHub code size](https://img.shields.io/github/languages/code-size/uzairusman012/military-grade-mission-data-locker)
![GitHub repo size](https://img.shields.io/github/repo-size/uzairusman012/military-grade-mission-data-locker)
![GitHub last commit](https://img.shields.io/github/last-commit/uzairusman012/military-grade-mission-data-locker)
![GitHub issues](https://img.shields.io/github/issues/uzairusman012/military-grade-mission-data-locker)

</div>
