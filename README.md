# **Military-Grade Mission Data Locker**

A Python-based secure information system designed to protect highly sensitive digital files using modern cryptographic methods, simulating defense-grade data protection systems.

## **Project Overview**

The **Military-Grade Mission Data Locker** is a complete security framework that demonstrates real-world cryptography implementation. It safeguards mission-critical data through multi-layered protection: military-strength encryption, tamper-proof integrity verification, role-based access control, and comprehensive audit trails.

---

## **Key Features**

### **Core Security**
- ✅ **AES-256 Encryption** with CBC mode
- ✅ **HMAC-SHA256** integrity verification
- ✅ **Argon2** password hashing
- ✅ **PBKDF2** key derivation

### **Access Control**
- **Commander**: Full access
- **Pilot**: Read-only
- **Analyst**: Decrypt only
- **Technician**: Limited access

---

## **Project Structure**

```

Military Grade Mission Data Locker/
│
├── main.py                  # Main application
├── mission_plan.txt         # Sample file (create for testing)
├── users/                   # User profiles
├── storage/                 # Encrypted files
└── logs/                    # Audit logs

```

---

## **Installation**

1. **Install Python 3.8+**
2. **Install dependencies:**
   ```bash
   pip install cryptography argon2-cffi

---

### **Create Test File**
```

echo "CLASSIFIED: Operation data" > mission_plan.txt

```

---

## **How to Use**

### **Run the Program**
```
python main.py
```

### **Register the User**

Select 1,
Enter name, password, role

### **Login**

Select 2,
Enter credentials

### **Encrypt File**

Select 3,
Enter encryption password

### **Decrypt File**

Select 4,
Enter same password

---

## **Verification Tests**

- [ ] Passwords stored as `$argon2id$` hashes in the `users/` directory  
- [ ] Encrypted files in `storage/` appear as unreadable ciphertext  
- [ ] `logs/audit.log` records all system actions  
- [ ] Pilot role is restricted from encrypting files (Access Denied)  
- [ ] Commander role has full system privileges  

---

## **Learning Outcomes**

This project demonstrates core concepts in:

- Practical cryptographic implementation  
- Secure software architecture  
- Role-Based Access Control (RBAC)  
- Audit log design and monitoring  
- Professional Python development practices  

---

## **Authors**

Developed as part of an Information Security course project.

**Institution:**  

Comsats University Islamabad, Sahiwal Campus  

**Developers:**  
- M. Uzair Usman  
- Husnain Shahid  

---


## **License**

MIT License - Educational Use

---








