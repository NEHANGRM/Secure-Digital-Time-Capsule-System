/**
 * CAPSULE MODEL
 * 
 * SECURITY CONCEPT: ENCRYPTION & DIGITAL SIGNATURES
 * 
 * This model stores encrypted time capsules with:
 * - Encrypted content (AES-256-CBC)
 * - Encrypted AES key (RSA)
 * - Content hash (SHA-256) for integrity
 * - Digital signature for authenticity
 * - QR code for easy sharing
 */

const mongoose = require('mongoose');

const capsuleSchema = new mongoose.Schema({
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    title: {
        type: String,
        required: true,
        trim: true
    },
    type: {
        type: String,
        enum: ['text', 'file'],
        default: 'text'
    },
    // ENCRYPTED CONTENT (AES-256-CBC)
    encryptedContent: {
        type: String,
        required: true
    },
    // ENCRYPTED AES KEY (RSA)
    encryptedAESKey: {
        type: String,
        required: true
    },
    // INITIALIZATION VECTOR for AES
    iv: {
        type: String,
        required: true
    },
    // SHA-256 HASH of original content
    contentHash: {
        type: String,
        required: true
    },
    // DIGITAL SIGNATURE (RSA)
    signature: {
        type: String,
        required: true
    },
    // QR CODE (Base64 encoded image)
    qrCode: {
        type: String,
        required: true
    },
    // UNLOCK DATE (time-based access control)
    unlockDate: {
        type: Date,
        required: true
    },
    // File metadata (if type is 'file')
    fileName: {
        type: String
    },
    fileType: {
        type: String
    },
    // CRYPTO VERSION (for backward compatibility)
    // v1 = RSA-2048 encryption, v2 = ECC P-256 encryption
    cryptoVersion: {
        type: String,
        default: 'v2',
        enum: ['v1', 'v2']
    }
}, {
    timestamps: true
});

/**
 * Method to check if capsule is unlocked
 */
capsuleSchema.methods.isUnlocked = function () {
    return new Date() >= this.unlockDate;
};

/**
 * Method to get time remaining until unlock
 */
capsuleSchema.methods.getTimeRemaining = function () {
    const now = new Date();
    const unlock = new Date(this.unlockDate);

    if (now >= unlock) {
        return { unlocked: true };
    }

    const diff = unlock - now;
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((diff % (1000 * 60)) / 1000);

    return {
        unlocked: false,
        days,
        hours,
        minutes,
        seconds,
        totalMilliseconds: diff
    };
};

module.exports = mongoose.model('Capsule', capsuleSchema);
