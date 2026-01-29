/**
 * ADMIN ROUTES
 * 
 * SECURITY CONCEPTS IMPLEMENTED:
 * - Role-based Access Control
 * - Admin can manage users but CANNOT read capsule contents
 * - Auditor can view logs but CANNOT access capsules
 */

const express = require('express');
const router = express.Router();
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const Capsule = require('../models/Capsule');
const authenticate = require('../middleware/auth');
const { requireRole, requirePermission } = require('../middleware/rbac');

/**
 * GET ALL USERS (Admin only)
 * 
 * SECURITY: Only admins can view user list
 */
router.get('/users', authenticate, requireRole('admin'), async (req, res) => {
    try {
        const users = await User.find()
            .select('-password -mfaSecret')
            .sort({ createdAt: -1 });

        res.json({
            success: true,
            users
        });

    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve users.',
            error: error.message
        });
    }
});

/**
 * UPDATE USER ROLE (Admin only)
 * 
 * SECURITY: Admins can change user roles
 */
router.put('/users/:id/role', authenticate, requireRole('admin'), async (req, res) => {
    try {
        const { role } = req.body;

        if (!['user', 'admin', 'auditor'].includes(role)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid role. Must be: user, admin, or auditor.'
            });
        }

        const user = await User.findById(req.params.id);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found.'
            });
        }

        const oldRole = user.role;
        user.role = role;
        await user.save();

        // Log role change
        await AuditLog.create({
            user: req.user._id,
            action: 'ROLE_CHANGE',
            details: `Changed ${user.username}'s role from ${oldRole} to ${role}`,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            metadata: { targetUser: user._id, oldRole, newRole: role }
        });

        res.json({
            success: true,
            message: `User role updated to ${role}.`,
            user: user.toJSON()
        });

    } catch (error) {
        console.error('Update role error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update user role.',
            error: error.message
        });
    }
});

/**
 * GET CAPSULE METADATA (Admin only - NO CONTENT ACCESS)
 * 
 * SECURITY: Admins can see capsule metadata but CANNOT decrypt content
 * This demonstrates separation of duties
 */
router.get('/capsules', authenticate, requireRole('admin'), async (req, res) => {
    try {
        const capsules = await Capsule.find()
            .populate('owner', 'username email')
            .select('title type unlockDate createdAt owner')
            .sort({ createdAt: -1 });

        res.json({
            success: true,
            message: 'Metadata only. Admins cannot access capsule content.',
            capsules
        });

    } catch (error) {
        console.error('Get capsules metadata error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve capsules.',
            error: error.message
        });
    }
});

/**
 * GET AUDIT LOGS (Auditor only)
 * 
 * SECURITY: Only auditors can view system logs
 */
router.get('/audit-logs', authenticate, requireRole('auditor'), async (req, res) => {
    try {
        const { limit = 100, action, userId } = req.query;

        let query = {};

        if (action) {
            query.action = action;
        }

        if (userId) {
            query.user = userId;
        }

        const logs = await AuditLog.find(query)
            .populate('user', 'username email role')
            .sort({ createdAt: -1 })
            .limit(parseInt(limit));

        res.json({
            success: true,
            logs
        });

    } catch (error) {
        console.error('Get audit logs error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve audit logs.',
            error: error.message
        });
    }
});

/**
 * GET SYSTEM STATISTICS (Admin only)
 */
router.get('/stats', authenticate, requireRole('admin'), async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const totalCapsules = await Capsule.countDocuments();
        const lockedCapsules = await Capsule.countDocuments({ unlockDate: { $gt: new Date() } });
        const unlockedCapsules = await Capsule.countDocuments({ unlockDate: { $lte: new Date() } });

        const usersByRole = await User.aggregate([
            { $group: { _id: '$role', count: { $sum: 1 } } }
        ]);

        res.json({
            success: true,
            stats: {
                totalUsers,
                totalCapsules,
                lockedCapsules,
                unlockedCapsules,
                usersByRole
            }
        });

    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve statistics.',
            error: error.message
        });
    }
});

module.exports = router;
