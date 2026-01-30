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
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const Capsule = require('../models/Capsule');
const AuditLog = require('../models/AuditLog');
const authenticate = require('../middleware/auth');
const { requirePermission, canAccessCapsule } = require('../middleware/rbac');
const { encryptCapsuleContent, decryptCapsuleContent } = require('../utils/crypto');

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, '../uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|webp|mp4|webm|mov|pdf|doc|docx|txt/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);

        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error('Invalid file type. Allowed: images, videos, PDF, DOC, TXT'));
    }
});

/**
 * CREATE TIME CAPSULE
 * 
 * SECURITY:
 * - Content is encrypted with AES-256-CBC
 * - AES key is encrypted with RSA
 * - Digital signature is created for integrity
 * - QR code is generated for sharing
 */
router.post('/create', authenticate, requirePermission('canCreateCapsule'), upload.single('file'), async (req, res) => {
    try {
        const { title, content, unlockDate, type, fileName, fileType } = req.body;

        // Validation
        if (!title || !unlockDate) {
            return res.status(400).json({
                success: false,
                message: 'Title and unlock date are required.'
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

        let contentToEncrypt = content;
        let capsuleType = type || 'text';
        let fileData = null;

        // If file is uploaded, read and encode it
        if (req.file) {
            const fileBuffer = fs.readFileSync(req.file.path);
            const base64File = fileBuffer.toString('base64');

            fileData = {
                fileName: req.file.originalname,
                fileType: req.file.mimetype,
                fileSize: req.file.size,
                fileData: base64File
            };

            // Combine text content and file data
            contentToEncrypt = JSON.stringify({
                message: content || '',
                file: fileData
            });

            capsuleType = 'file';

            // Delete the uploaded file after reading
            fs.unlinkSync(req.file.path);
        } else if (!content) {
            return res.status(400).json({
                success: false,
                message: 'Either content or file is required.'
            });
        }

        // Create temporary capsule to get ID
        const tempCapsule = new Capsule({
            owner: req.user._id,
            title,
            type: capsuleType,
            unlockDate: unlock,
            // Temporary values (will be replaced)
            encryptedContent: 'temp',
            encryptedAESKey: 'temp',
            iv: 'temp',
            contentHash: 'temp',
            signature: 'temp',
            qrCode: 'temp'
        });

        // Add file metadata if file is present
        if (fileData) {
            tempCapsule.fileName = fileData.fileName;
            tempCapsule.fileType = fileData.fileType;
            tempCapsule.fileSize = fileData.fileSize;
        }

        await tempCapsule.save();

        // Encrypt content with capsule ID (using v2 - ECC by default)
        const {
            encryptedContent,
            encryptedAESKey,
            iv,
            contentHash,
            signature,
            qrCode,
            cryptoVersion
        } = await encryptCapsuleContent(contentToEncrypt, tempCapsule._id.toString(), 'v2');

        // Update capsule with encrypted data
        tempCapsule.encryptedContent = encryptedContent;
        tempCapsule.encryptedAESKey = encryptedAESKey;
        tempCapsule.iv = iv;
        tempCapsule.contentHash = contentHash;
        tempCapsule.signature = signature;
        tempCapsule.qrCode = qrCode;
        tempCapsule.cryptoVersion = cryptoVersion; // v2 for ECC

        await tempCapsule.save();

        // Log capsule creation
        await AuditLog.create({
            user: req.user._id,
            action: 'CAPSULE_CREATE',
            details: `Created capsule: ${title}${fileData ? ' (with file)' : ''}`,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            metadata: { capsuleId: tempCapsule._id, hasFile: !!fileData }
        });

        res.status(201).json({
            success: true,
            message: 'Time capsule created successfully.',
            capsule: {
                id: tempCapsule._id,
                title: tempCapsule.title,
                unlockDate: tempCapsule.unlockDate,
                qrCode: tempCapsule.qrCode,
                timeRemaining: tempCapsule.getTimeRemaining(),
                hasFile: !!fileData
            }
        });

    } catch (error) {
        console.error('Create capsule error:', error);

        // Clean up uploaded file if it exists
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }

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
        // Auto-detect version: default to v1 (RSA) if not specified for backward compatibility
        try {
            const { content, verified } = decryptCapsuleContent(
                capsule.encryptedContent,
                capsule.encryptedAESKey,
                capsule.iv,
                capsule.contentHash,
                capsule.signature,
                capsule.cryptoVersion || 'v1' // Use v1 (RSA) for old capsules without version field
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
