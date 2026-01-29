# 🔐 Secure Digital Time Capsule System

A full-stack web application demonstrating comprehensive cybersecurity concepts including authentication, authorization, encryption, hashing, digital signatures, and encoding. Built for university cybersecurity lab evaluation.

![Security Features](https://img.shields.io/badge/Security-Enterprise%20Grade-success)
![Encryption](https://img.shields.io/badge/Encryption-AES%20256%20%2B%20RSA%202048-blue)
![Auth](https://img.shields.io/badge/Auth-JWT%20%2B%20MFA-orange)

---

## 🎯 Project Overview

The Secure Digital Time Capsule System allows users to store encrypted messages or files that can only be unlocked after a chosen future date. The system implements enterprise-grade security features suitable for academic demonstration and evaluation.

### Key Features

- ✅ **Hybrid Encryption**: AES-256-CBC + RSA-2048
- ✅ **Multi-Factor Authentication**: TOTP-based MFA
- ✅ **Role-Based Access Control**: User, Admin, Auditor roles
- ✅ **Digital Signatures**: RSA signatures for integrity
- ✅ **Time-Based Unlocking**: Capsules unlock at specific dates
- ✅ **QR Code Generation**: Easy capsule sharing
- ✅ **Audit Logging**: Complete security event tracking
- ✅ **Modern UI**: Premium dark theme with glassmorphism

---

## 🔒 Security Concepts Implemented

### 1. Authentication
- Bcrypt password hashing with salt
- JWT token-based sessions
- TOTP multi-factor authentication (Google Authenticator compatible)

### 2. Authorization
- Role-Based Access Control (RBAC)
- Access Control Matrix
- Principle of least privilege

### 3. Encryption (Confidentiality)
- AES-256-CBC for content encryption
- RSA-2048 for key encryption
- Hybrid encryption architecture

### 4. Key Exchange
- RSA public key encryption
- Secure key distribution

### 5. Hashing & Digital Signatures
- SHA-256 content hashing
- RSA digital signatures
- Integrity verification

### 6. Encoding
- QR code generation (Base64)
- Easy capsule ID sharing

For detailed security documentation, see [SECURITY_DOCUMENTATION.md](./SECURITY_DOCUMENTATION.md)

---

## 📁 Project Structure

```
secure-digital-time-capsule-system/
├── backend/
│   ├── models/
│   │   ├── User.js              # User model with bcrypt hashing
│   │   ├── Capsule.js           # Encrypted capsule model
│   │   └── AuditLog.js          # Security audit logging
│   ├── routes/
│   │   ├── auth.js              # Authentication routes (register, login, MFA)
│   │   ├── capsules.js          # Capsule CRUD operations
│   │   └── admin.js             # Admin and auditor routes
│   ├── middleware/
│   │   ├── auth.js              # JWT authentication middleware
│   │   └── rbac.js              # Role-based access control
│   ├── utils/
│   │   └── crypto.js            # Cryptographic functions
│   ├── server.js                # Express server entry point
│   ├── package.json
│   └── .env                     # Environment variables
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Navbar.jsx       # Navigation bar
│   │   │   └── ProtectedRoute.jsx
│   │   ├── pages/
│   │   │   ├── Home.jsx         # Landing page
│   │   │   ├── Register.jsx     # User registration
│   │   │   ├── Login.jsx        # Login with MFA
│   │   │   ├── Dashboard.jsx    # User dashboard
│   │   │   ├── CreateCapsule.jsx
│   │   │   ├── ViewCapsule.jsx
│   │   │   └── MFASetup.jsx     # MFA configuration
│   │   ├── context/
│   │   │   └── AuthContext.jsx  # Authentication state
│   │   ├── utils/
│   │   │   └── api.js           # Axios instance with JWT
│   │   ├── App.jsx              # Main app component
│   │   ├── main.jsx             # React entry point
│   │   └── index.css            # Premium dark theme styles
│   ├── package.json
│   └── vite.config.js
├── SECURITY_DOCUMENTATION.md    # Detailed security explanations
└── README.md                    # This file
```

---

## 🚀 Setup Instructions

### Prerequisites

- **Node.js** (v18 or higher)
- **MongoDB** (v6 or higher)
- **npm** or **yarn**

### Installation

#### 1. Clone the Repository

```bash
cd C:\Users\DELL\Desktop\CYBEREVAL
cd secure-digital-time-capsule-system
```

#### 2. Setup Backend

```bash
cd backend
npm install
```

Create `.env` file (or use the existing one):
```env
PORT=5000
MONGODB_URI=mongodb://localhost:27017/timecapsule
JWT_SECRET=cyber_security_lab_jwt_secret_key_2026
NODE_ENV=development
```

#### 3. Setup Frontend

```bash
cd ../frontend
npm install
```

#### 4. Start MongoDB

Make sure MongoDB is running on your system:

**Windows**:
```bash
# If MongoDB is installed as a service, it should already be running
# Otherwise, start it manually:
mongod
```

**Mac/Linux**:
```bash
sudo systemctl start mongod
# or
brew services start mongodb-community
```

#### 5. Run the Application

**Terminal 1 - Backend**:
```bash
cd backend
npm start
```

You should see:
```
✅ MongoDB connected successfully
✅ RSA Key Pair Generated (2048-bit)
🚀 Server running on: http://localhost:5000
```

**Terminal 2 - Frontend**:
```bash
cd frontend
npm run dev
```

You should see:
```
  VITE v5.x.x  ready in xxx ms

  ➜  Local:   http://localhost:5173/
```

#### 6. Open in Browser

Navigate to: **http://localhost:5173**

---

## 🧪 Testing the Application

### 1. User Registration & Authentication

1. Click "Register" and create a new account
2. Login with your credentials
3. (Optional) Setup MFA from dashboard or `/mfa-setup`

### 2. Create Time Capsule

1. Go to "Create Capsule"
2. Enter title and message
3. Choose unlock date (must be in future)
4. Click "Create Capsule"
5. Note: Content is encrypted with AES-256, key is encrypted with RSA-2048

### 3. View Locked Capsule

1. Go to Dashboard
2. Click on a locked capsule
3. See countdown timer
4. View QR code
5. Content remains encrypted until unlock date

### 4. View Unlocked Capsule

1. Create a capsule with unlock date in the past (or wait for timer)
2. View the capsule
3. Content is decrypted automatically
4. Digital signature is verified
5. SHA-256 hash is checked for integrity

### 5. Test MFA

1. Go to `/mfa-setup`
2. Scan QR code with Google Authenticator or Authy
3. Enter 6-digit code to enable MFA
4. Logout and login again
5. You'll be prompted for MFA code

### 6. Test Role-Based Access Control

**Create Admin User** (via MongoDB):
```javascript
// Connect to MongoDB
use timecapsule

// Update a user's role to admin
db.users.updateOne(
  { email: "admin@example.com" },
  { $set: { role: "admin" } }
)
```

**Admin Features**:
- Can view all users
- Can change user roles
- CANNOT read capsule contents (separation of duties)

**Create Auditor User**:
```javascript
db.users.updateOne(
  { email: "auditor@example.com" },
  { $set: { role: "auditor" } }
)
```

**Auditor Features**:
- Can view audit logs
- CANNOT access capsules or manage users

### 7. Verify Encryption in Database

```javascript
// Connect to MongoDB
use timecapsule

// View a capsule
db.capsules.findOne()
```

You'll see:
- `encryptedContent`: Encrypted with AES (hex string)
- `encryptedAESKey`: AES key encrypted with RSA (base64)
- `iv`: Initialization vector for AES
- `contentHash`: SHA-256 hash of original content
- `signature`: RSA digital signature
- `qrCode`: Base64 encoded QR code image

---

## 🔧 API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login (returns JWT)
- `POST /api/auth/setup-mfa` - Generate MFA secret
- `POST /api/auth/verify-mfa` - Verify MFA code
- `POST /api/auth/enable-mfa` - Enable MFA
- `GET /api/auth/me` - Get current user

### Capsules
- `POST /api/capsules/create` - Create encrypted capsule
- `GET /api/capsules` - Get user's capsules
- `GET /api/capsules/:id` - Get specific capsule (decrypt if unlocked)
- `DELETE /api/capsules/:id` - Delete capsule

### Admin (Admin role only)
- `GET /api/admin/users` - List all users
- `PUT /api/admin/users/:id/role` - Change user role
- `GET /api/admin/capsules` - View capsule metadata (no content)
- `GET /api/admin/stats` - System statistics

### Auditor (Auditor role only)
- `GET /api/admin/audit-logs` - View audit logs

---

## 🎨 UI Features

- **Premium Dark Theme**: Modern glassmorphism design
- **Responsive Layout**: Works on all screen sizes
- **Smooth Animations**: Micro-interactions for better UX
- **Real-time Countdown**: Live timer for locked capsules
- **QR Code Display**: Easy capsule sharing
- **Role Badges**: Visual indication of user roles
- **Status Indicators**: Locked/unlocked badges
- **Error Handling**: Clear user feedback

---

## 🛡️ Security Best Practices

1. ✅ Never store passwords in plaintext
2. ✅ Use environment variables for secrets
3. ✅ Implement HTTPS in production
4. ✅ Validate all user inputs
5. ✅ Use parameterized queries (Mongoose)
6. ✅ Implement rate limiting (recommended for production)
7. ✅ Keep dependencies updated
8. ✅ Use Content Security Policy headers
9. ✅ Implement CORS properly
10. ✅ Log security events

---

## 📊 Technologies Used

### Backend
- **Node.js** - Runtime environment
- **Express** - Web framework
- **MongoDB** - NoSQL database
- **Mongoose** - ODM for MongoDB
- **Bcrypt** - Password hashing
- **JWT** - Token authentication
- **Speakeasy** - TOTP/MFA
- **QRCode** - QR code generation
- **Node Crypto** - Encryption & signatures

### Frontend
- **React 18** - UI library
- **Vite** - Build tool
- **React Router** - Client-side routing
- **Axios** - HTTP client
- **CSS3** - Modern styling

---

## 🎓 Educational Value

This project is perfect for:

- **Cybersecurity Courses**: Demonstrates real-world security concepts
- **Cryptography Labs**: Shows practical encryption implementation
- **Web Security**: Covers authentication, authorization, and secure coding
- **Full-Stack Development**: Complete MERN-like stack example

### Learning Outcomes

Students will understand:
- How encryption protects data
- Difference between symmetric and asymmetric encryption
- How digital signatures work
- Authentication vs Authorization
- Role-based access control
- Secure password storage
- Multi-factor authentication
- Audit logging importance

---

## 🐛 Troubleshooting

### MongoDB Connection Error
```
Error: connect ECONNREFUSED 127.0.0.1:27017
```
**Solution**: Make sure MongoDB is running

### Port Already in Use
```
Error: listen EADDRINUSE: address already in use :::5000
```
**Solution**: Change PORT in `.env` or kill process using port 5000

### JWT Token Expired
**Solution**: Login again to get new token

### MFA Code Invalid
**Solution**: Make sure your device time is synchronized

---

## 📝 License

This project is created for educational purposes as part of a cybersecurity lab evaluation.

---

## 👨‍💻 Author

Created for CYBEREVAL - University Cybersecurity Lab

---

## 🙏 Acknowledgments

- NIST Cybersecurity Framework
- OWASP Security Guidelines
- Node.js Crypto Documentation
- React Best Practices

---

**For detailed security explanations, see [SECURITY_DOCUMENTATION.md](./SECURITY_DOCUMENTATION.md)**