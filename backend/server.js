/**
 * SECURE DIGITAL TIME CAPSULE SYSTEM - SERVER
 * 
 * This is the main entry point for the backend server.
 * 
 * SECURITY FEATURES IMPLEMENTED:
 * 1. RSA Key Pair Generation (on startup)
 * 2. JWT Authentication
 * 3. Role-Based Access Control (RBAC)
 * 4. Hybrid Encryption (AES + RSA)
 * 5. Digital Signatures
 * 6. Multi-Factor Authentication (TOTP)
 * 7. Audit Logging
 * 8. Password Hashing (bcrypt)
 */

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { generateECCKeyPair, generateRSAKeyPair } = require('./utils/crypto');

// Initialize Express app
const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logging middleware
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

// Import routes
const authRoutes = require('./routes/auth');
const capsuleRoutes = require('./routes/capsules');
const adminRoutes = require('./routes/admin');

// Mount routes
app.use('/api/auth', authRoutes);
app.use('/api/capsules', capsuleRoutes);
app.use('/api/admin', adminRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: 'Secure Digital Time Capsule System is running.',
        timestamp: new Date().toISOString()
    });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        success: true,
        message: 'Welcome to Secure Digital Time Capsule System API',
        version: '1.0.0',
        endpoints: {
            auth: '/api/auth',
            capsules: '/api/capsules',
            admin: '/api/admin',
            health: '/api/health'
        }
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({
        success: false,
        message: 'Internal server error.',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Endpoint not found.'
    });
});

// Database connection and server startup
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/timecapsule';

async function startServer() {
    try {
        // Connect to MongoDB
        console.log('🔌 Connecting to MongoDB...');
        await mongoose.connect(MONGODB_URI);
        console.log('✅ MongoDB connected successfully');

        // Generate cryptographic key pairs
        console.log('🔐 Initializing cryptographic keys...');

        // Generate ECC key pair (primary - v2)
        console.log('📐 Generating ECC P-256 key pair (v2)...');
        generateECCKeyPair();

        // Generate RSA key pair (legacy - v1)
        console.log('🔑 Generating RSA-2048 key pair (v1 - backward compatibility)...');
        generateRSAKeyPair();

        // Start server
        app.listen(PORT, () => {
            console.log('');
            console.log('═══════════════════════════════════════════════════════');
            console.log('🚀 SECURE DIGITAL TIME CAPSULE SYSTEM');
            console.log('═══════════════════════════════════════════════════════');
            console.log(`📡 Server running on: http://localhost:${PORT}`);
            console.log(`🗄️  Database: ${MONGODB_URI}`);
            console.log(`🔒 Security Features Enabled:`);
            console.log('   ✓ ECC P-256 Key Pair (Hybrid Encryption v2) 🆕');
            console.log('   ✓ RSA-2048 Key Pair (Legacy v1 Support)');
            console.log('   ✓ AES-256-CBC Encryption');
            console.log('   ✓ SHA-256 Hashing');
            console.log('   ✓ Digital Signatures (ECDSA + RSA)');
            console.log('   ✓ JWT Authentication');
            console.log('   ✓ Multi-Factor Authentication (TOTP)');
            console.log('   ✓ Role-Based Access Control');
            console.log('   ✓ Bcrypt Password Hashing');
            console.log('   ✓ Audit Logging');
            console.log('═══════════════════════════════════════════════════════');
            console.log('');
        });

    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}

// Handle graceful shutdown
process.on('SIGINT', async () => {
    console.log('\n🛑 Shutting down gracefully...');
    await mongoose.connection.close();
    console.log('✅ Database connection closed');
    process.exit(0);
});

// Start the server
startServer();

module.exports = app;
