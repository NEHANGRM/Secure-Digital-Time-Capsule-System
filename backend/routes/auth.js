/**
 * AUTHENTICATION ROUTES
 * 
 * SECURITY CONCEPTS IMPLEMENTED:
 * 1. Password Hashing (bcrypt)
 * 2. JWT Token Generation
 * 3. Multi-Factor Authentication (TOTP)
 * 4. Audit Logging
 */

const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const authenticate = require('../middleware/auth');

/**
 * REGISTER NEW USER
 * 
 * SECURITY: Password is automatically hashed by User model pre-save hook
 */
router.post('/register', async (req, res) => {
    try {
        const { username, email, password, role } = req.body;

        // Validation
        if (!username || !email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username, email, and password are required.'
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'User with this email or username already exists.'
            });
        }

        // Create new user (password will be hashed automatically)
        const user = new User({
            username,
            email,
            password,
            role: role || 'user' // Default to 'user' role
        });

        await user.save();

        // Log the registration
        await AuditLog.create({
            user: user._id,
            action: 'REGISTER',
            details: `User registered: ${username}`,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent']
        });

        res.status(201).json({
            success: true,
            message: 'User registered successfully.',
            user: user.toJSON()
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Registration failed.',
            error: error.message
        });
    }
});

/**
 * LOGIN
 * 
 * SECURITY: 
 * - Verifies password using bcrypt
 * - Issues JWT token for session management
 * - Requires MFA if enabled
 */
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validation
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required.'
            });
        }

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            // Log failed login attempt
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password.'
            });
        }

        // Verify password
        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            // Log failed login
            await AuditLog.create({
                user: user._id,
                action: 'FAILED_LOGIN',
                details: 'Invalid password',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                status: 'FAILURE'
            });

            return res.status(401).json({
                success: false,
                message: 'Invalid email or password.'
            });
        }

        // Check if MFA is enabled
        if (user.mfaEnabled) {
            // Return temporary token for MFA verification
            const tempToken = jwt.sign(
                { userId: user._id, mfaPending: true },
                process.env.JWT_SECRET,
                { expiresIn: '5m' }
            );

            return res.json({
                success: true,
                mfaRequired: true,
                tempToken,
                message: 'MFA verification required.'
            });
        }

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Log successful login
        await AuditLog.create({
            user: user._id,
            action: 'LOGIN',
            details: 'Successful login',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent']
        });

        res.json({
            success: true,
            token,
            user: user.toJSON(),
            message: 'Login successful.'
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Login failed.',
            error: error.message
        });
    }
});

/**
 * SETUP MFA (Multi-Factor Authentication)
 * 
 * SECURITY: Uses TOTP (Time-based One-Time Password)
 * - Generates secret key
 * - Returns QR code for authenticator apps (Google Authenticator, Authy, etc.)
 */
router.post('/setup-mfa', authenticate, async (req, res) => {
    try {
        // Generate secret
        const secret = speakeasy.generateSecret({
            name: `TimeCapsule (${req.user.email})`,
            length: 32
        });

        // Generate QR code
        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

        // Save secret to user (but don't enable MFA yet)
        req.user.mfaSecret = secret.base32;
        await req.user.save();

        // Log MFA setup
        await AuditLog.create({
            user: req.user._id,
            action: 'MFA_SETUP',
            details: 'MFA secret generated',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent']
        });

        res.json({
            success: true,
            secret: secret.base32,
            qrCode: qrCodeUrl,
            message: 'Scan this QR code with your authenticator app.'
        });

    } catch (error) {
        console.error('MFA setup error:', error);
        res.status(500).json({
            success: false,
            message: 'MFA setup failed.',
            error: error.message
        });
    }
});

/**
 * VERIFY MFA CODE
 * 
 * SECURITY: Verifies TOTP code from authenticator app
 */
router.post('/verify-mfa', async (req, res) => {
    try {
        const { tempToken, code } = req.body;

        if (!tempToken || !code) {
            return res.status(400).json({
                success: false,
                message: 'Temporary token and MFA code are required.'
            });
        }

        // Verify temp token
        const decoded = jwt.verify(tempToken, process.env.JWT_SECRET);

        if (!decoded.mfaPending) {
            return res.status(400).json({
                success: false,
                message: 'Invalid token.'
            });
        }

        // Get user
        const user = await User.findById(decoded.userId);
        if (!user || !user.mfaSecret) {
            return res.status(400).json({
                success: false,
                message: 'MFA not set up for this user.'
            });
        }

        // Verify TOTP code
        const verified = speakeasy.totp.verify({
            secret: user.mfaSecret,
            encoding: 'base32',
            token: code,
            window: 2 // Allow 2 time steps before/after for clock skew
        });

        if (!verified) {
            // Log failed MFA
            await AuditLog.create({
                user: user._id,
                action: 'FAILED_MFA',
                details: 'Invalid MFA code',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                status: 'FAILURE'
            });

            return res.status(401).json({
                success: false,
                message: 'Invalid MFA code.'
            });
        }

        // Generate full access token
        const token = jwt.sign(
            { userId: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Log successful MFA
        await AuditLog.create({
            user: user._id,
            action: 'MFA_VERIFY',
            details: 'MFA verification successful',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent']
        });

        res.json({
            success: true,
            token,
            user: user.toJSON(),
            message: 'MFA verification successful.'
        });

    } catch (error) {
        console.error('MFA verification error:', error);
        res.status(500).json({
            success: false,
            message: 'MFA verification failed.',
            error: error.message
        });
    }
});

/**
 * ENABLE MFA
 * 
 * Enables MFA after successful verification
 */
router.post('/enable-mfa', authenticate, async (req, res) => {
    try {
        const { code } = req.body;

        if (!code) {
            return res.status(400).json({
                success: false,
                message: 'MFA code is required.'
            });
        }

        if (!req.user.mfaSecret) {
            return res.status(400).json({
                success: false,
                message: 'MFA not set up. Call /setup-mfa first.'
            });
        }

        // Verify code
        const verified = speakeasy.totp.verify({
            secret: req.user.mfaSecret,
            encoding: 'base32',
            token: code,
            window: 2
        });

        if (!verified) {
            return res.status(401).json({
                success: false,
                message: 'Invalid MFA code.'
            });
        }

        // Enable MFA
        req.user.mfaEnabled = true;
        await req.user.save();

        res.json({
            success: true,
            message: 'MFA enabled successfully.'
        });

    } catch (error) {
        console.error('Enable MFA error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to enable MFA.',
            error: error.message
        });
    }
});

/**
 * GET CURRENT USER
 */
router.get('/me', authenticate, (req, res) => {
    res.json({
        success: true,
        user: req.user.toJSON()
    });
});

module.exports = router;
