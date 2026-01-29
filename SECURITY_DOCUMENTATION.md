# Cyber Security Concepts Implemented

## Overview

The **Secure Digital Time Capsule System** is a full-stack web application that demonstrates comprehensive cybersecurity concepts suitable for university-level evaluation. This document explains each security mechanism implemented in the system.

---

## 1️⃣ AUTHENTICATION

### What is Authentication?
Authentication is the process of verifying the identity of a user. It answers the question: **"Who are you?"**

### Implementation in Our System

#### A. Password Hashing with Bcrypt
- **Technology**: Bcrypt with salt (10 rounds)
- **Location**: `backend/models/User.js`
- **How it works**:
  1. User provides password during registration
  2. Bcrypt generates a random salt
  3. Password + salt is hashed using bcrypt algorithm
  4. Only the hash is stored in database (never plaintext password)
  5. During login, provided password is hashed and compared with stored hash

**Security Benefits**:
- Protects passwords even if database is compromised
- Salt prevents rainbow table attacks
- Slow hashing algorithm prevents brute-force attacks

#### B. JWT (JSON Web Token) Authentication
- **Technology**: jsonwebtoken library
- **Location**: `backend/routes/auth.js`, `backend/middleware/auth.js`
- **How it works**:
  1. After successful login, server generates JWT token
  2. Token contains user ID and role (signed with secret key)
  3. Client stores token in localStorage
  4. Client sends token in Authorization header for subsequent requests
  5. Server verifies token signature before processing requests

**Security Benefits**:
- Stateless authentication (no server-side session storage)
- Tamper-proof (any modification invalidates signature)
- Expiration time prevents indefinite access

#### C. Multi-Factor Authentication (MFA/2FA)
- **Technology**: TOTP (Time-based One-Time Password) using Speakeasy
- **Location**: `backend/routes/auth.js`, `frontend/src/pages/MFASetup.jsx`
- **How it works**:
  1. User enables MFA and receives a secret key
  2. Secret key is encoded in QR code
  3. User scans QR code with authenticator app (Google Authenticator, Authy)
  4. App generates 6-digit code that changes every 30 seconds
  5. During login, user must provide both password AND current TOTP code

**Security Benefits**:
- Protects against password theft
- Even if password is compromised, attacker cannot login without TOTP device
- Follows NIST guidelines for multi-factor authentication

---

## 2️⃣ AUTHORIZATION (ACCESS CONTROL)

### What is Authorization?
Authorization determines what an authenticated user is allowed to do. It answers: **"What can you do?"**

### Implementation: Role-Based Access Control (RBAC)

#### Access Control Matrix
**Location**: `backend/middleware/rbac.js`

| Role    | Create Capsule | View Own Capsule | Manage Users | View Audit Logs | Read Capsule Content |
|---------|----------------|------------------|--------------|-----------------|----------------------|
| **user**    | ✅ Yes | ✅ Yes | ❌ No | ❌ No | ✅ Yes (own only) |
| **admin**   | ❌ No | ❌ No | ✅ Yes | ❌ No | ❌ No |
| **auditor** | ❌ No | ❌ No | ❌ No | ✅ Yes | ❌ No |

#### How it Works:
1. Each user is assigned a role during registration
2. Middleware checks user role before allowing access to routes
3. Permissions are enforced at both route level and function level

**Security Principle**: **Principle of Least Privilege**
- Users only get minimum permissions needed for their role
- Admins can manage users but CANNOT read capsule contents (separation of duties)
- Auditors can view logs but CANNOT access or modify capsules

---

## 3️⃣ ENCRYPTION (CONFIDENTIALITY)

### What is Encryption?
Encryption transforms readable data (plaintext) into unreadable data (ciphertext) to protect confidentiality.

### Implementation: Hybrid Encryption (AES + RSA)

#### A. AES-256-CBC Encryption
- **Technology**: Node.js crypto module
- **Location**: `backend/utils/crypto.js`
- **Algorithm**: AES-256-CBC (Advanced Encryption Standard, 256-bit key, Cipher Block Chaining mode)

**How it works**:
1. Generate random 256-bit AES key
2. Generate random 128-bit Initialization Vector (IV)
3. Encrypt capsule content using AES key and IV
4. Store encrypted content, AES key, and IV

**Why AES?**
- Symmetric encryption (same key for encrypt/decrypt)
- Very fast for large data
- Industry standard (used by governments and banks)

#### B. RSA-2048 Encryption
- **Technology**: Node.js crypto module
- **Location**: `backend/utils/crypto.js`
- **Algorithm**: RSA-2048 with OAEP padding

**How it works**:
1. Server generates RSA key pair on startup (2048-bit)
2. Public key encrypts data
3. Private key decrypts data

**Why RSA?**
- Asymmetric encryption (different keys for encrypt/decrypt)
- Solves key distribution problem
- Public key can be shared safely

#### C. Hybrid Encryption Architecture

**The Problem**: 
- AES is fast but requires secure key sharing
- RSA is secure for key sharing but slow for large data

**The Solution**: Use both!

**Process**:
1. Encrypt content with AES (fast)
2. Encrypt AES key with RSA public key (secure key distribution)
3. Store both encrypted content and encrypted AES key

**Decryption Process**:
1. Decrypt AES key using RSA private key
2. Decrypt content using AES key

**Security Benefits**:
- Combines speed of AES with security of RSA
- Even if encrypted content is stolen, attacker cannot decrypt without RSA private key
- Each capsule has unique AES key

---

## 4️⃣ KEY EXCHANGE MECHANISM

### What is Key Exchange?
Key exchange is the method of securely sharing encryption keys between parties.

### Implementation: RSA Public Key Encryption

**Location**: `backend/utils/crypto.js`, `backend/server.js`

**How it works**:
1. Server generates RSA key pair on startup
2. Public key is used to encrypt AES keys
3. Private key (kept secret on server) decrypts AES keys
4. No need to transmit keys over network

**Security Benefits**:
- Solves the "key distribution problem"
- Public key can be shared openly
- Only server with private key can decrypt

---

## 5️⃣ HASHING & DIGITAL SIGNATURES

### A. Hashing (Integrity Verification)

**What is Hashing?**
Hashing is a one-way function that converts data into a fixed-size string (hash). Same input always produces same hash.

**Implementation**: SHA-256
- **Location**: `backend/utils/crypto.js`
- **Algorithm**: SHA-256 (Secure Hash Algorithm, 256-bit output)

**How it works**:
1. Before encryption, create SHA-256 hash of original content
2. Store hash with capsule
3. After decryption, hash the decrypted content
4. Compare hashes - if different, content was tampered with

**Security Benefits**:
- Detects any modification to content
- One-way function (cannot reverse hash to get original)
- Collision-resistant (extremely hard to find two inputs with same hash)

### B. Digital Signatures (Authentication + Integrity)

**What is a Digital Signature?**
A digital signature proves that data came from a specific source and hasn't been modified.

**Implementation**: RSA Signatures
- **Location**: `backend/utils/crypto.js`
- **Algorithm**: RSA with SHA-256

**How it works**:

**Creating Signature**:
1. Hash the content (SHA-256)
2. Encrypt hash with RSA private key = signature
3. Store signature with capsule

**Verifying Signature**:
1. Hash the decrypted content
2. Decrypt signature with RSA public key
3. Compare hashes - if match, signature is valid

**Security Benefits**:
- **Authentication**: Only private key holder could create signature
- **Integrity**: If content changes, signature verification fails
- **Non-repudiation**: Signer cannot deny creating signature

---

## 6️⃣ ENCODING

### What is Encoding?
Encoding converts data from one format to another for transmission or storage. **NOT the same as encryption!**

### Implementation: QR Code Generation

**Technology**: qrcode library
**Location**: `backend/utils/crypto.js`

**How it works**:
1. Capsule ID is encoded into QR code
2. QR code is Base64 encoded image
3. Stored with capsule for easy sharing

**Difference from Encryption**:
- Encoding is reversible without a key
- QR code can be scanned to reveal capsule ID
- Purpose is convenience, not security

**Use Case**:
- Easy sharing of capsule IDs
- Scan QR code to quickly access capsule

---

## 🛡️ ATTACK VECTORS & MITIGATIONS

### 1. Password Attacks

**Attack**: Brute force, dictionary attacks, rainbow tables

**Mitigations**:
- ✅ Bcrypt hashing with salt (slow hashing prevents brute force)
- ✅ Password minimum length requirement
- ✅ MFA adds second factor even if password is cracked

### 2. Man-in-the-Middle (MITM) Attacks

**Attack**: Attacker intercepts communication between client and server

**Mitigations**:
- ✅ HTTPS should be used in production (encrypts all traffic)
- ✅ JWT tokens prevent session hijacking
- ✅ Token expiration limits damage if token is stolen

### 3. SQL Injection

**Attack**: Attacker injects malicious SQL code

**Mitigations**:
- ✅ Using MongoDB with Mongoose (NoSQL, parameterized queries)
- ✅ Input validation on all user inputs
- ✅ Mongoose schema validation

### 4. Cross-Site Scripting (XSS)

**Attack**: Attacker injects malicious JavaScript

**Mitigations**:
- ✅ React automatically escapes output
- ✅ Content-Type headers set correctly
- ✅ No use of dangerouslySetInnerHTML

### 5. Unauthorized Access

**Attack**: User tries to access resources they don't own

**Mitigations**:
- ✅ JWT authentication on all protected routes
- ✅ Ownership verification (users can only access own capsules)
- ✅ Role-based access control

### 6. Data Tampering

**Attack**: Attacker modifies encrypted data

**Mitigations**:
- ✅ SHA-256 hash verification detects any changes
- ✅ Digital signature verification ensures authenticity
- ✅ Decryption fails if data is corrupted

### 7. Replay Attacks

**Attack**: Attacker reuses captured authentication tokens

**Mitigations**:
- ✅ JWT token expiration (24 hours)
- ✅ TOTP codes expire after 30 seconds
- ✅ Audit logging tracks all authentication attempts

### 8. Privilege Escalation

**Attack**: User tries to gain higher privileges

**Mitigations**:
- ✅ Role stored in JWT token (server-side verification)
- ✅ Middleware checks permissions on every request
- ✅ Admins cannot access capsule content (separation of duties)

---

## 📊 AUDIT LOGGING

**Location**: `backend/models/AuditLog.js`, `backend/routes/admin.js`

**What is logged**:
- User login/logout
- Failed login attempts
- MFA setup and verification
- Capsule creation, viewing, deletion
- Role changes

**Security Benefits**:
- **Accountability**: Track who did what and when
- **Forensics**: Investigate security incidents
- **Compliance**: Meet regulatory requirements
- **Anomaly Detection**: Identify suspicious patterns

---

## 🔐 SECURITY BEST PRACTICES FOLLOWED

1. ✅ **Defense in Depth**: Multiple layers of security
2. ✅ **Principle of Least Privilege**: Minimal permissions
3. ✅ **Separation of Duties**: Admins can't read content
4. ✅ **Secure by Default**: MFA encouraged, strong encryption
5. ✅ **Input Validation**: All user inputs validated
6. ✅ **Error Handling**: No sensitive info in error messages
7. ✅ **Audit Trail**: Complete logging of security events
8. ✅ **Encryption at Rest**: All capsule content encrypted
9. ✅ **Time-based Access Control**: Capsules unlock at specific time
10. ✅ **Non-repudiation**: Digital signatures prove authorship

---

## 📚 TECHNOLOGIES USED

### Backend
- **Node.js**: Runtime environment
- **Express**: Web framework
- **MongoDB**: Database
- **Bcrypt**: Password hashing
- **JWT**: Token-based authentication
- **Speakeasy**: TOTP/MFA
- **Node Crypto**: Encryption, hashing, signatures
- **QRCode**: QR code generation

### Frontend
- **React**: UI framework
- **Vite**: Build tool
- **React Router**: Navigation
- **Axios**: HTTP client

---

## 🎓 EDUCATIONAL VALUE

This system demonstrates:

1. **Cryptography**: Symmetric, asymmetric, hybrid encryption
2. **Authentication**: Password hashing, JWT, MFA
3. **Authorization**: RBAC, access control matrix
4. **Integrity**: Hashing, digital signatures
5. **Confidentiality**: Encryption
6. **Accountability**: Audit logging
7. **Secure Development**: Input validation, error handling
8. **Security Architecture**: Defense in depth, least privilege

Perfect for cybersecurity lab evaluation and demonstration of real-world security concepts.

---

## 📖 REFERENCES

- NIST Cybersecurity Framework
- OWASP Top 10
- RFC 6238 (TOTP)
- RFC 7519 (JWT)
- AES (FIPS 197)
- RSA (PKCS #1)
- SHA-256 (FIPS 180-4)
