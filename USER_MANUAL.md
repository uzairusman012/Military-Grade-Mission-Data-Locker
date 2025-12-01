# **User Manual: Military-Grade Mission Data Locker**

**Version 1.0** | **Last Updated**: 2025-11-30

---

## **Purpose of This Manual**

This manual provides step-by-step instructions for operating the Mission Data Locker system. It is designed for users with minimal technical background, including military personnel, analysts, and security officers.

---

## **Before You Begin**

**Required Setup:**
1. Python 3.8+ installed
2. `cryptography` and `argon2-cffi` libraries installed (`pip install cryptography argon2-cffi`)
3. A test file named `mission_plan.txt` exists in the project folder
4. Three empty folders: `users/`, `storage/`, `logs/`

---

## **System Overview**

The system operates through a **menu-driven interface** with these options:

================ Military Grade Mission Data Locker ================

- Register User
- Login User
- Encrypt File
- Decrypt File
- Logout
- Exit

---


## **Test Case 1: First-Time Setup & Commander Operations**

### **Step 1: Register a Commander**
**Purpose**: Create a high-privilege user who can encrypt/decrypt files.

**Action:** Select `1`

**Input:**

- Enter your name: commander_tom
- Enter your password: TopSecret2024
- Enter your role: Commander


**Expected Output:**

User 'commander_tom' registered as Commander successfully.


**What Happened:**
- System created `users/commander_tom.json`
- Password was hashed with Argon2 (never stored in plain text)
- Role assigned for future permission checks

---

### **Step 2: Login as Commander**
**Action:** Select `2`

**Input:**

- Enter your name: commander_tom
- Enter your password: TopSecret2024


**Expected Output:**

Welcome back commander_tom! Your role: Commander  
================ Military Grade Mission Data Locker ================  
Logged in: commander_tom(Commander)


**What Happened:**
- System verified password hash
- Session activated with Commander privileges
- Menu now shows logged-in status

---

### **Step 3: Encrypt a Mission File**
**Purpose**: Transform readable `mission_plan.txt` into protected ciphertext.

**Action:** Select `3`

**Input:**

Enter encryption password: TopSecret2024


**Expected Output:**

File 'mission_plan.txt' encrypted successfully with HMAC seal!     
Logged: encrypt by CURRENT_USER - SUCCESS


**What Happened:**
- System derived 256-bit AES key from password
- Generated random IV (16 bytes)
- Scrambled file contents with AES-256-CBC
- Added HMAC-SHA256 tamper-proof seal
- Saved result to `storage/encrypted_mission_plan.txt`
- Logged action to `logs/audit.log`

**Verification:**
- Open `storage/encrypted_mission_plan.txt` → Should be gibberish

---

### **Step 4: Decrypt the File**
**Purpose**: Restore encrypted file to readable format.

**Action:** Select `4`

**Input:**

Enter decryption password: TopSecret2024


**Expected Output:**

File decrypted successfully: decrypted_mission_plan.txt             
Logged: decrypt by CURRENT_USER - SUCCESS


**What Happened:**
- System verified HMAC seal (detected no tampering)
- Used same password-derived key to unscramble
- Removed padding and saved readable file
- Logged decryption action

**Verification:**
- Open `decrypted_mission_plan.txt` → Should show original text

---

### **Step 5: Logout**
**Action:** Select `5`

**Expected Output:**

Logged: logout by commander_tom - SUCCESS                     
Logged out successfully!


---

## **Test Case 2: Testing Role Enforcement (Pilot)**

### **Step 1: Register a Pilot**
**Action:** Select `1`

**Input:**

- Enter your name: pilot_alice
- Enter your password: SkyHigh456
- Enter your role: Pilot


**Expected:** `User 'pilot_alice' registered as Pilot successfully.`

---

### **Step 2: Login as Pilot**
**Action:** Select `2`

**Input:**

- Enter your name: pilot_alice
- Enter your password: SkyHigh456


**Expected:**

Welcome back pilot_alice! Your role: Pilot                        
================ Military Grade Mission Data Locker ================     
Logged in: pilot_alice(Pilot)


---

### **Step 3: Attempt to Encrypt (Should Fail)**
**Action:** Select `3`

**Input:**

- Enter encryption password: SkyHigh456


**Expected:**

Access Denied! Pilot cannot encrypt files.


**What Happened:**
- `check_permission()` returned False for Pilot + encrypt action
- Request was blocked before encryption occurred

---

### **Step 4: Decrypt (Should Succeed)**
**Action:** Select `4`

**Input:**

- Enter decryption password: TopSecret2024


*(Use Commander's password from earlier)*

**Expected:**

File decrypted successfully: decrypted_mission_plan.txt                  
Logged: decrypt by CURRENT_USER - SUCCESS



**What Happened:**
- Pilot has `decrypt: True` permission
- System allowed decryption
- File successfully restored

---

## **Test Case 3: Security Features**

### **Tamper Detection Test**
**Purpose**: Prove HMAC seal detects file modifications.

**Step 1:** Use Notepad to open `storage/encrypted_mission_plan.txt`  
**Step 2:** Change **any single character** (add/delete one letter)  
**Step 3:** Save and close  
**Step 4:** Login as Commander → Select `4` → Enter password

**Expected Result:**


Traceback (most recent call last):                                
...                                                                    
cryptography.exceptions.InvalidSignature: Signature did not match digest.



**What Happened:**
- HMAC verification detected mismatch
- System refused to decrypt corrupted file
- **Critical Security**: Prevents tampering and corruption

---

## **Understanding the Logs**

**Location**: `logs/audit.log`

**Sample Log Entries:**
```json
{"timestamp": "2025-11-29T14:30:00", "username": "commander_tom", "action": "login", "file": "system", "success": true}
{"timestamp": "2025-11-29T14:31:15", "username": "CURRENT_USER", "action": "encrypt", "file": "mission_plan.txt", "success": true}
{"timestamp": "2025-11-29T14:32:30", "username": "pilot_alice", "action": "login", "file": "system", "success": true}
{"timestamp": "2025-11-29T14:33:00", "username": "pilot_alice", "action": "decrypt", "file": "storage/encrypted_mission_plan.txt", "success": true}

```


### **Fields Explained:**

- **timestamp:** When action occurred (ISO format)
- **username:** Who performed the action
- **action:** What was attempted (login/encrypt/decrypt/logout)
- **file:** System or specific file targeted
- **success:** True/False result (for security auditing)


### **Common Issues & Solutions**


| Problem             | Cause                      | Solution                                   |
| ------------------- | -------------------------- | ------------------------------------------ |
| `FileNotFoundError` | Missing `mission_plan.txt` | Create the file in main folder             |
| `Access Denied`     | Wrong role for action      | Use Commander for encrypt/delete           |
| `InvalidSignature`  | File was tampered          | Check HMAC seal integrity                  |
| `Login failed`      | Wrong password             | Passwords are case-sensitive               |
| `Module not found`  | Libraries not installed    | Run `pip install cryptography argon2-cffi` |



### **Security Best Practices**

- **Strong Passwords:** Use 12+ characters with mixed case, numbers, symbols
- **Role Separation:** Never share Commander credentials
- **Log Review:** Check audit.log regularly for suspicious activity
- **File Backup:** Keep unencrypted originals in secure offline storage
- **Tamper Check:** Always verify HMAC before decrypting critical files



## Support & Troubleshooting

If you encounter issues:                                           

- Check logs/audit.log for error details
- Verify folder structure matches requirements
- Ensure Python version is 3.8+
- Confirm all dependencies are installed

---