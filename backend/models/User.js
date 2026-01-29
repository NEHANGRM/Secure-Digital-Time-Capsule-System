/**
 * USER MODEL
 * 
 * SECURITY CONCEPT: AUTHENTICATION
 * 
 * This model stores user credentials and authentication data:
 * - Password: Hashed using bcrypt (never stored in plaintext)
 * - Role: For authorization and access control
 * - MFA: Multi-factor authentication using TOTP (Time-based One-Time Password)
 */

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        minlength: 3
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    role: {
        type: String,
        enum: ['user', 'admin', 'auditor'],
        default: 'user'
    },
    mfaSecret: {
        type: String,
        default: null
    },
    mfaEnabled: {
        type: Boolean,
        default: false
    }
}, {
    timestamps: true
});

/**
 * SECURITY CONCEPT: PASSWORD HASHING
 * 
 * Pre-save hook to hash password before storing in database
 * - Uses bcrypt with salt rounds (10)
 * - Salt: Random data added to password before hashing
 * - This prevents rainbow table attacks
 */
userSchema.pre('save', async function (next) {
    // Only hash if password is modified
    if (!this.isModified('password')) {
        return next();
    }

    try {
        // Generate salt and hash password
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

/**
 * Method to compare password during login
 */
userSchema.methods.comparePassword = async function (candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

/**
 * Method to get user data without sensitive fields
 */
userSchema.methods.toJSON = function () {
    const user = this.toObject();
    delete user.password;
    delete user.mfaSecret;
    return user;
};

module.exports = mongoose.model('User', userSchema);
