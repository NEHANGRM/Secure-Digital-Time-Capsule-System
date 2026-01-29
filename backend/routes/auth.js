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

        console.log(`✅ New user registered: ${email}`);

        res.status(201).json({
            success: true,
            message: 'User registered successfully. Please login to set up MFA.',
            user: user.toJSON()
        });

    } catch (error) {
        console.error('❌ Registration error:', error);
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

        console.log(`🔐 Login attempt for: ${email}`);

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
            console.log(`❌ User not found: ${email}`);
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password.'
            });
        }

        console.log(`✅ User found: ${email}, MFA Enabled: ${user.mfaEnabled}, MFA Secret: ${user.mfaSecret ? 'SET' : 'NOT SET'}`);

        // Verify password
        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            console.log(`❌ Invalid password for: ${email}`);
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

        console.log(`✅ Password verified for: ${email}`);

        // Check if MFA is enabled - MANDATORY FOR ALL USERS
        if (!user.mfaEnabled || !user.mfaSecret) {
            console.log(`⚠️  MFA not set up for: ${email} - Redirecting to MFA setup`);
            // User hasn't set up MFA yet - force them to set it up
            const setupToken = jwt.sign(
                { userId: user._id, mfaSetupRequired: true },
                process.env.JWT_SECRET,
                { expiresIn: '15m' }
            );

            return res.json({
                success: true,
                mfaSetupRequired: true,
                setupToken,
                message: 'MFA setup is required. Please set up MFA to continue.'
            });
        }

        console.log(`✅ MFA is enabled for: ${email} - Requiring verification`);

        // MFA is enabled - require verification
        const tempToken = jwt.sign(
            { userId: user._id, mfaPending: true },
            process.env.JWT_SECRET,
            { expiresIn: '5m' }
        );

        return res.json({
            success: true,
            mfaRequired: true,
            tempToken,
            message: 'Please enter your MFA code.'
        });


    } catch (error) {
        console.error('❌ Login error:', error);
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
 * - Can be called with either JWT token or setup token
 */
router.post('/setup-mfa', async (req, res) => {
    try {
        let user;
        const authHeader = req.headers.authorization;
        const setupToken = req.body.setupToken;

        console.log(`🔐 MFA Setup request - Has setupToken: ${!!setupToken}, Has authHeader: ${!!authHeader}`);

        // Check if using setup token (first-time MFA setup) or regular auth token
        if (setupToken) {
            // Verify setup token
            try {
                const decoded = jwt.verify(setupToken, process.env.JWT_SECRET);
                if (!decoded.mfaSetupRequired) {
                    return res.status(400).json({
                        success: false,
                        message: 'Invalid setup token.'
                    });
                }
                user = await User.findById(decoded.userId);
                console.log(`✅ Setup token verified for user: ${user?.email}`);
            } catch (err) {
                console.error('❌ Setup token verification failed:', err.message);
                return res.status(401).json({
                    success: false,
                    message: 'Setup token expired or invalid. Please login again.'
                });
            }
        } else if (authHeader && authHeader.startsWith('Bearer ')) {
            // Regular authenticated request
            const token = authHeader.substring(7);
            try {
                const decoded = jwt.verify(token, process.env.JWT_SECRET);
                user = await User.findById(decoded.userId);
                console.log(`✅ Auth token verified for user: ${user?.email}`);
            } catch (err) {
                console.error('❌ Auth token verification failed:', err.message);
                return res.status(401).json({
                    success: false,
                    message: 'Authentication token expired or invalid.'
                });
            }
        } else {
            return res.status(401).json({
                success: false,
                message: 'Authentication required. Please provide setupToken or authorization header.'
            });
        }

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found.'
            });
        }

        let secret;
        let isNewSecret = false;

        // IMPORTANT: Reuse existing secret if one exists and MFA is not yet enabled
        // This prevents the QR code mismatch issue
        if (user.mfaSecret && !user.mfaEnabled) {
            console.log(`🔄 Reusing existing MFA secret for: ${user.email}`);
            // Reuse existing secret
            secret = {
                base32: user.mfaSecret,
                otpauth_url: `otpauth://totp/TimeCapsule%20(${encodeURIComponent(user.email)})?secret=${user.mfaSecret}&issuer=Secure%20Time%20Capsule`
            };
        } else {
            console.log(`🔑 Generating NEW MFA secret for: ${user.email}`);
            isNewSecret = true;
            // Generate NEW secret only if user doesn't have one
            secret = speakeasy.generateSecret({
                name: `TimeCapsule (${user.email})`,
                length: 32,
                issuer: 'Secure Time Capsule'
            });

            // Save new secret to user
            user.mfaSecret = secret.base32;
            user.mfaEnabled = false;
            await user.save();
        }

        // Generate QR code
        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

        console.log(`✅ MFA setup ready for: ${user.email} (${isNewSecret ? 'NEW secret' : 'EXISTING secret'})`);

        // Log MFA setup
        await AuditLog.create({
            user: user._id,
            action: 'MFA_SETUP',
            details: isNewSecret ? 'New MFA secret generated' : 'Existing MFA secret reused',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent']
        });

        res.json({
            success: true,
            secret: secret.base32,
            qrCode: qrCodeUrl,
            userId: user._id,
            message: 'Scan this QR code with your authenticator app. MFA is required to continue.'
        });

    } catch (error) {
        console.error('❌ MFA setup error:', error);
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

        // Clean the code - remove any spaces and ensure it's a string
        const cleanCode = String(code || '').replace(/\s/g, '').trim();

        console.log(`🔐 MFA Verification attempt`);
        console.log(`   Raw code: "${code}"`);
        console.log(`   Clean code: "${cleanCode}"`);

        if (!tempToken || !cleanCode || cleanCode.length !== 6) {
            return res.status(400).json({
                success: false,
                message: 'Temporary token and 6-digit MFA code are required.'
            });
        }

        // Verify temp token
        let decoded;
        try {
            decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
        } catch (err) {
            console.error('❌ Temp token verification failed:', err.message);
            return res.status(401).json({
                success: false,
                message: 'Token expired or invalid. Please login again.'
            });
        }

        if (!decoded.mfaPending) {
            return res.status(400).json({
                success: false,
                message: 'Invalid token.'
            });
        }

        // Get user
        const user = await User.findById(decoded.userId);
        if (!user || !user.mfaSecret) {
            console.log(`❌ User not found or MFA not set up: ${decoded.userId}`);
            return res.status(400).json({
                success: false,
                message: 'MFA not set up for this user.'
            });
        }

        console.log(`🔍 Verifying MFA code for: ${user.email}`);
        console.log(`   Secret (first 10 chars): ${user.mfaSecret.substring(0, 10)}...`);
        console.log(`   Code provided: ${cleanCode}`);

        // Verify TOTP code with wider window for clock skew
        const verified = speakeasy.totp.verify({
            secret: user.mfaSecret,
            encoding: 'base32',
            token: cleanCode,
            window: 4 // Allow 4 time steps (2 minutes) for clock skew
        });

        console.log(`   Verification result: ${verified}`);

        if (!verified) {
            // Generate current code for debugging
            const currentCode = speakeasy.totp({
                secret: user.mfaSecret,
                encoding: 'base32'
            });
            console.log(`   Expected code: ${currentCode}`);
            console.log(`   Code match: ${currentCode === cleanCode}`);

            console.log(`❌ Invalid MFA code for: ${user.email}`);
            // Log failed MFA
            await AuditLog.create({
                user: user._id,
                action: 'FAILED_MFA',
                details: `Invalid MFA code. Submitted: ${cleanCode}`,
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                status: 'FAILURE'
            });

            return res.status(401).json({
                success: false,
                message: 'Invalid MFA code. Make sure your phone time is synchronized and try again.'
            });
        }

        console.log(`✅ MFA verification successful for: ${user.email}`);

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
            message: 'MFA verification successful. Welcome back!'
        });

    } catch (error) {
        console.error('❌ MFA verification error:', error);
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
 * Returns JWT token for immediate login after setup
 */
router.post('/enable-mfa', async (req, res) => {
    try {
        const { code, setupToken, userId } = req.body;

        // Clean the code - remove any spaces and ensure it's a string
        const cleanCode = String(code || '').replace(/\s/g, '').trim();

        console.log(`🔐 Enable MFA request`);
        console.log(`   Raw code: "${code}"`);
        console.log(`   Clean code: "${cleanCode}"`);
        console.log(`   UserId: ${userId}`);
        console.log(`   Has setupToken: ${!!setupToken}`);

        if (!cleanCode || cleanCode.length !== 6) {
            return res.status(400).json({
                success: false,
                message: `MFA code must be 6 digits. Received: ${cleanCode.length} digits`
            });
        }

        let user;

        // Check if using setup token or regular auth
        if (setupToken) {
            try {
                const decoded = jwt.verify(setupToken, process.env.JWT_SECRET);
                user = await User.findById(decoded.userId);
                console.log(`✅ Setup token verified for: ${user?.email}`);
            } catch (err) {
                console.error('❌ Setup token verification failed:', err.message);
                return res.status(401).json({
                    success: false,
                    message: 'Setup token expired or invalid. Please login again.'
                });
            }
        } else if (userId) {
            user = await User.findById(userId);
            console.log(`✅ User found by ID: ${user?.email}`);
        } else {
            // Try to get from auth header
            const authHeader = req.headers.authorization;
            if (authHeader && authHeader.startsWith('Bearer ')) {
                const token = authHeader.substring(7);
                try {
                    const decoded = jwt.verify(token, process.env.JWT_SECRET);
                    user = await User.findById(decoded.userId);
                    console.log(`✅ Auth token verified for: ${user?.email}`);
                } catch (err) {
                    console.error('❌ Auth token verification failed:', err.message);
                    return res.status(401).json({
                        success: false,
                        message: 'Authentication token expired or invalid.'
                    });
                }
            }
        }

        if (!user) {
            console.log('❌ User not found');
            return res.status(404).json({
                success: false,
                message: 'User not found. Please try logging in again.'
            });
        }

        if (!user.mfaSecret) {
            console.log(`❌ MFA secret not found for: ${user.email}`);
            return res.status(400).json({
                success: false,
                message: 'MFA not set up. Please refresh and try again.'
            });
        }

        console.log(`🔍 Verifying MFA code for: ${user.email}`);
        console.log(`   User's secret (first 10 chars): ${user.mfaSecret.substring(0, 10)}...`);
        console.log(`   Submitted code: ${cleanCode}`);

        // Verify code with wider window for clock skew
        const verified = speakeasy.totp.verify({
            secret: user.mfaSecret,
            encoding: 'base32',
            token: cleanCode,
            window: 4 // Allow 4 time steps (2 minutes) for clock skew
        });

        console.log(`   Verification result: ${verified}`);

        // If verification fails, try to generate current code for debugging
        if (!verified) {
            const currentCode = speakeasy.totp({
                secret: user.mfaSecret,
                encoding: 'base32'
            });
            console.log(`   Expected code (current): ${currentCode}`);
            console.log(`   Code match: ${currentCode === cleanCode}`);

            console.log(`❌ Invalid MFA code for: ${user.email}`);
            await AuditLog.create({
                user: user._id,
                action: 'FAILED_MFA_SETUP',
                details: `Invalid MFA code during setup. Submitted: ${cleanCode}`,
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                status: 'FAILURE'
            });

            return res.status(401).json({
                success: false,
                message: 'Invalid MFA code. Make sure your phone time is synchronized and try the current code.'
            });
        }

        // Enable MFA
        user.mfaEnabled = true;
        await user.save();

        console.log(`✅ MFA enabled successfully for: ${user.email}`);

        // Log successful MFA enablement
        await AuditLog.create({
            user: user._id,
            action: 'MFA_ENABLED',
            details: 'MFA enabled successfully (MANDATORY)',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent']
        });

        // Generate full access token
        const token = jwt.sign(
            { userId: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            token,
            user: user.toJSON(),
            message: 'MFA enabled successfully. You are now logged in!'
        });

    } catch (error) {
        console.error('❌ Enable MFA error:', error);
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
