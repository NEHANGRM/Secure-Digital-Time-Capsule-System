/**
 * AUDIT LOG MODEL
 * 
 * SECURITY CONCEPT: ACCOUNTABILITY & NON-REPUDIATION
 * 
 * This model tracks all security-relevant events:
 * - User actions (login, logout, capsule creation, etc.)
 * - Timestamps for forensic analysis
 * - IP addresses for tracking
 * - Action results (success/failure)
 */

const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    action: {
        type: String,
        required: true,
        enum: [
            'LOGIN',
            'LOGOUT',
            'REGISTER',
            'MFA_SETUP',
            'MFA_VERIFY',
            'CAPSULE_CREATE',
            'CAPSULE_VIEW',
            'CAPSULE_DELETE',
            'ROLE_CHANGE',
            'FAILED_LOGIN',
            'FAILED_MFA'
        ]
    },
    details: {
        type: String
    },
    ipAddress: {
        type: String
    },
    userAgent: {
        type: String
    },
    status: {
        type: String,
        enum: ['SUCCESS', 'FAILURE'],
        default: 'SUCCESS'
    },
    metadata: {
        type: mongoose.Schema.Types.Mixed
    }
}, {
    timestamps: true
});

// Index for efficient querying
auditLogSchema.index({ user: 1, createdAt: -1 });
auditLogSchema.index({ action: 1, createdAt: -1 });

module.exports = mongoose.model('AuditLog', auditLogSchema);
