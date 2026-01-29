/**
 * CAPSULE ROUTES
 * 
 * SECURITY CONCEPTS IMPLEMENTED:
 * 1. Hybrid Encryption (AES + RSA)
 * 2. Digital Signatures
 * 3. Time-based Access Control
 * 4. Role-based Authorization
 */

const express = require('express');
const router = express.Router();
const Capsule = require('../models/Capsule');
const AuditLog = require('../models/AuditLog');
const authenticate = require('../middleware/auth');
const { requirePermission, canAccessCapsule } = require('../middleware/rbac');
const { encryptCapsuleContent, decryptCapsuleContent } = require('../utils/crypto');

/**
 * CREATE TIME CAPSULE
 * 
 * SECURITY:
 * - Content is encrypted with AES-256-CBC
 * - AES key is encrypted with RSA
 * - Digital signature is created for integrity
 * - QR code is generated for sharing
 */
router.post('/create', authenticate, requirePermission('canCreateCapsule'), async (req, res) => {
    try {
        const { title, content, unlockDate, type } = req.body;

        // Validation
        if (!title || !content || !unlockDate) {
            return res.status(400).json({
                success: false,
                message: 'Title, content, and unlock date are required.'
            });
        }

        // Validate unlock date is at least 1 minute in the future (for demo purposes)
        const unlock = new Date(unlockDate);
        const minTime = new Date(Date.now() + 60 * 1000); // 1 minute from now
        if (unlock < minTime) {
            return res.status(400).json({
                success: false,
                message: 'Unlock date must be at least 1 minute in the future.'
            });
        }

        // Create temporary capsule to get ID
        const tempCapsule = new Capsule({
            owner: req.user._id,
            title,
            type: type || 'text',
            unlockDate: unlock,
            // Temporary values (will be replaced)
            encryptedContent: 'temp',
            encryptedAESKey: 'temp',
            iv: 'temp',
            contentHash: 'temp',
            signature: 'temp',
            qrCode: 'temp'
        });

        await tempCapsule.save();

        // Encrypt content with capsule ID
        const {
            encryptedContent,
            encryptedAESKey,
            iv,
            contentHash,
            signature,
            qrCode
        } = await encryptCapsuleContent(content, tempCapsule._id.toString());

        // Update capsule with encrypted data
        tempCapsule.encryptedContent = encryptedContent;
        tempCapsule.encryptedAESKey = encryptedAESKey;
        tempCapsule.iv = iv;
        tempCapsule.contentHash = contentHash;
        tempCapsule.signature = signature;
        tempCapsule.qrCode = qrCode;

        await tempCapsule.save();

        // Log capsule creation
        await AuditLog.create({
            user: req.user._id,
            action: 'CAPSULE_CREATE',
            details: `Created capsule: ${title}`,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            metadata: { capsuleId: tempCapsule._id }
        });

        res.status(201).json({
            success: true,
            message: 'Time capsule created successfully.',
            capsule: {
                id: tempCapsule._id,
                title: tempCapsule.title,
                unlockDate: tempCapsule.unlockDate,
                qrCode: tempCapsule.qrCode,
                timeRemaining: tempCapsule.getTimeRemaining()
            }
        });

    } catch (error) {
        console.error('Create capsule error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create capsule.',
            error: error.message
        });
    }
});

/**
 * GET ALL USER'S CAPSULES
 * 
 * SECURITY: Users can only see their own capsules
 */
router.get('/', authenticate, canAccessCapsule, async (req, res) => {
    try {
        const capsules = await Capsule.find({ owner: req.user._id })
            .select('-encryptedContent -encryptedAESKey -iv -contentHash -signature')
            .sort({ createdAt: -1 });

        // Add time remaining for each capsule
        const capsulesWithTime = capsules.map(capsule => ({
            id: capsule._id,
            title: capsule.title,
            type: capsule.type,
            unlockDate: capsule.unlockDate,
            createdAt: capsule.createdAt,
            qrCode: capsule.qrCode,
            isUnlocked: capsule.isUnlocked(),
            timeRemaining: capsule.getTimeRemaining()
        }));

        res.json({
            success: true,
            capsules: capsulesWithTime
        });

    } catch (error) {
        console.error('Get capsules error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve capsules.',
            error: error.message
        });
    }
});

/**
 * GET SPECIFIC CAPSULE
 * 
 * SECURITY:
 * - Verifies ownership
 * - Only decrypts if unlock date has passed
 * - Verifies digital signature
 * - Checks content integrity (hash)
 */
router.get('/:id', authenticate, canAccessCapsule, async (req, res) => {
    try {
        const capsule = await Capsule.findById(req.params.id);

        if (!capsule) {
            return res.status(404).json({
                success: false,
                message: 'Capsule not found.'
            });
        }

        // Verify ownership
        if (capsule.owner.toString() !== req.user._id.toString()) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. You do not own this capsule.'
            });
        }

        // Check if capsule is unlocked
        if (!capsule.isUnlocked()) {
            return res.json({
                success: true,
                capsule: {
                    id: capsule._id,
                    title: capsule.title,
                    type: capsule.type,
                    unlockDate: capsule.unlockDate,
                    createdAt: capsule.createdAt,
                    qrCode: capsule.qrCode,
                    isUnlocked: false,
                    timeRemaining: capsule.getTimeRemaining()
                },
                message: 'Capsule is still locked. Please wait until the unlock date.'
            });
        }

        // Capsule is unlocked - decrypt content
        try {
            const { content, verified } = decryptCapsuleContent(
                capsule.encryptedContent,
                capsule.encryptedAESKey,
                capsule.iv,
                capsule.contentHash,
                capsule.signature
            );

            // Log capsule view
            await AuditLog.create({
                user: req.user._id,
                action: 'CAPSULE_VIEW',
                details: `Viewed capsule: ${capsule.title}`,
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                metadata: { capsuleId: capsule._id }
            });

            res.json({
                success: true,
                capsule: {
                    id: capsule._id,
                    title: capsule.title,
                    type: capsule.type,
                    content: content,
                    unlockDate: capsule.unlockDate,
                    createdAt: capsule.createdAt,
                    qrCode: capsule.qrCode,
                    isUnlocked: true,
                    verified: verified
                },
                message: 'Capsule unlocked and decrypted successfully. Digital signature verified.'
            });

        } catch (decryptError) {
            // Decryption or verification failed
            console.error('Decryption error:', decryptError);

            res.status(500).json({
                success: false,
                message: 'Failed to decrypt capsule. Content may have been tampered with.',
                error: decryptError.message
            });
        }

    } catch (error) {
        console.error('Get capsule error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve capsule.',
            error: error.message
        });
    }
});

/**
 * DELETE CAPSULE
 * 
 * SECURITY: Only owner can delete their capsule
 */
router.delete('/:id', authenticate, requirePermission('canDeleteOwnCapsule'), async (req, res) => {
    try {
        const capsule = await Capsule.findById(req.params.id);

        if (!capsule) {
            return res.status(404).json({
                success: false,
                message: 'Capsule not found.'
            });
        }

        // Verify ownership
        if (capsule.owner.toString() !== req.user._id.toString()) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. You do not own this capsule.'
            });
        }

        await Capsule.findByIdAndDelete(req.params.id);

        // Log capsule deletion
        await AuditLog.create({
            user: req.user._id,
            action: 'CAPSULE_DELETE',
            details: `Deleted capsule: ${capsule.title}`,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            metadata: { capsuleId: capsule._id }
        });

        res.json({
            success: true,
            message: 'Capsule deleted successfully.'
        });

    } catch (error) {
        console.error('Delete capsule error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete capsule.',
            error: error.message
        });
    }
});

module.exports = router;
