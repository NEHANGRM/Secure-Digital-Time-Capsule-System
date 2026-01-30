/**
 * CRYPTO UTILITIES MODULE
 * 
 * This module implements core cryptographic functions for the Time Capsule System:
 * 1. ECC Key Pair Generation (P-256) - for hybrid encryption [NEW: v2]
 * 2. RSA Key Pair Generation (2048-bit) - for backward compatibility [LEGACY: v1]
 * 3. AES-256-CBC Encryption/Decryption - for content encryption
 * 4. Hybrid Encryption - encrypt AES key with ECC/RSA public key
 * 5. SHA-256 Hashing - for content integrity verification
 * 6. Digital Signatures - ECC/RSA signature creation and verification
 * 7. QR Code Generation - Base64 encoded capsule IDs
 * 
 * VERSIONING:
 * - v1: RSA-2048 (legacy, for backward compatibility)
 * - v2: ECC P-256 (new default)
 */

const crypto = require('crypto');
const QRCode = require('qrcode');
const fs = require('fs');
const path = require('path');

// Global key pairs (loaded from file or generated)
let RSA_KEYS = null;  // v1: Legacy RSA keys
let ECC_KEYS = null;  // v2: New ECC keys

// Path to store keys
const KEYS_DIR = path.join(__dirname, '..', 'keys');
const RSA_KEYS_FILE = path.join(KEYS_DIR, 'rsa-keys.json');
const ECC_KEYS_FILE = path.join(KEYS_DIR, 'ecc-keys.json');

/**
 * SECURITY CONCEPT: ECC KEY PAIR GENERATION (WITH PERSISTENCE)
 * 
 * Generates an ECC key pair using P-256 curve for asymmetric encryption.
 * - Public key: Used to derive shared secrets for AES key encryption (can be shared)
 * - Private key: Used to derive shared secrets for AES key decryption (must be kept secret)
 * 
 * IMPORTANT: Keys are saved to file and reused across server restarts.
 * This prevents decryption failures for existing capsules.
 * 
 * ECC P-256 provides equivalent security to RSA-3072 but with much smaller keys.
 */
function generateECCKeyPair() {
    // Try to load existing keys first
    if (fs.existsSync(ECC_KEYS_FILE)) {
        try {
            const keysData = fs.readFileSync(ECC_KEYS_FILE, 'utf8');
            ECC_KEYS = JSON.parse(keysData);
            console.log('✅ ECC Key Pair Loaded from file (existing keys)');
            return ECC_KEYS;
        } catch (error) {
            console.warn('⚠️  Failed to load existing ECC keys, generating new ones:', error.message);
        }
    }

    // Generate new ECC keys if none exist
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1', // P-256 curve
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });

    ECC_KEYS = { publicKey, privateKey };

    // Save keys to file
    try {
        if (!fs.existsSync(KEYS_DIR)) {
            fs.mkdirSync(KEYS_DIR, { recursive: true });
        }
        fs.writeFileSync(ECC_KEYS_FILE, JSON.stringify(ECC_KEYS, null, 2));
        console.log('✅ ECC Key Pair Generated and Saved (P-256)');
    } catch (error) {
        console.error('❌ Failed to save ECC keys:', error.message);
    }

    return ECC_KEYS;
}

/**
 * LEGACY: RSA KEY PAIR GENERATION (FOR BACKWARD COMPATIBILITY)
 * 
 * Generates a 2048-bit RSA key pair for asymmetric encryption.
 * Only used for decrypting old capsules (v1).
 */
function generateRSAKeyPair() {
    // Try to load existing keys first
    if (fs.existsSync(RSA_KEYS_FILE)) {
        try {
            const keysData = fs.readFileSync(RSA_KEYS_FILE, 'utf8');
            RSA_KEYS = JSON.parse(keysData);
            console.log('✅ RSA Key Pair Loaded from file (legacy v1 support)');
            return RSA_KEYS;
        } catch (error) {
            console.warn('⚠️  Failed to load existing RSA keys, generating new ones:', error.message);
        }
    }

    // Generate new keys if none exist
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });

    RSA_KEYS = { publicKey, privateKey };

    // Save keys to file
    try {
        if (!fs.existsSync(KEYS_DIR)) {
            fs.mkdirSync(KEYS_DIR, { recursive: true });
        }
        fs.writeFileSync(RSA_KEYS_FILE, JSON.stringify(RSA_KEYS, null, 2));
        console.log('✅ RSA Key Pair Generated and Saved (2048-bit) - Legacy v1');
    } catch (error) {
        console.error('❌ Failed to save RSA keys:', error.message);
    }

    return RSA_KEYS;
}

/**
 * Get the current ECC public key (v2)
 */
function getECCPublicKey() {
    if (!ECC_KEYS) {
        throw new Error('ECC keys not initialized. Call generateECCKeyPair() first.');
    }
    return ECC_KEYS.publicKey;
}

/**
 * Get the current ECC private key (v2)
 */
function getECCPrivateKey() {
    if (!ECC_KEYS) {
        throw new Error('ECC keys not initialized. Call generateECCKeyPair() first.');
    }
    return ECC_KEYS.privateKey;
}

/**
 * Get the current RSA public key (v1 - legacy)
 */
function getRSAPublicKey() {
    if (!RSA_KEYS) {
        throw new Error('RSA keys not initialized. Call generateRSAKeyPair() first.');
    }
    return RSA_KEYS.publicKey;
}

/**
 * Get the current RSA private key (v1 - legacy)
 */
function getRSAPrivateKey() {
    if (!RSA_KEYS) {
        throw new Error('RSA keys not initialized. Call generateRSAKeyPair() first.');
    }
    return RSA_KEYS.privateKey;
}

/**
 * SECURITY CONCEPT: AES ENCRYPTION (CONFIDENTIALITY)
 * 
 * Encrypts content using AES-256-CBC (Advanced Encryption Standard)
 * - Symmetric encryption: same key for encryption and decryption
 * - 256-bit key: provides strong security
 * - CBC mode: Cipher Block Chaining for added security
 * - Random IV: Initialization Vector ensures same plaintext produces different ciphertext
 * 
 * Returns: { encryptedData, aesKey, iv }
 */
function encryptWithAES(content) {
    // Generate random 256-bit AES key
    const aesKey = crypto.randomBytes(32); // 32 bytes = 256 bits

    // Generate random Initialization Vector
    const iv = crypto.randomBytes(16); // 16 bytes for AES

    // Create cipher
    const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);

    // Encrypt content
    let encrypted = cipher.update(content, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return {
        encryptedData: encrypted,
        aesKey: aesKey.toString('hex'),
        iv: iv.toString('hex')
    };
}

/**
 * SECURITY CONCEPT: AES DECRYPTION
 * 
 * Decrypts AES-encrypted content using the AES key and IV
 */
function decryptWithAES(encryptedData, aesKeyHex, ivHex) {
    const aesKey = Buffer.from(aesKeyHex, 'hex');
    const iv = Buffer.from(ivHex, 'hex');

    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);

    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

/**
 * SECURITY CONCEPT: HYBRID ENCRYPTION WITH ECC (v2)
 * 
 * Combines symmetric (AES) and asymmetric (ECC) encryption:
 * 1. Content is encrypted with AES (fast, efficient for large data)
 * 2. Generate ephemeral ECC key pair for this capsule
 * 3. Use ECDH to derive shared secret with server's ECC public key
 * 4. Use HKDF to derive encryption key from shared secret
 * 5. Encrypt AES key with derived key
 * 
 * This provides forward secrecy - each capsule uses a unique ephemeral key.
 */
function encryptAESKeyWithECC(aesKeyHex) {
    const aesKeyBuffer = Buffer.from(aesKeyHex, 'hex');

    // Generate ephemeral key pair for this capsule
    const ephemeral = crypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    // Create ECDH from ephemeral private key
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.setPrivateKey(crypto.createPrivateKey(ephemeral.privateKey).export({
        type: 'sec1',
        format: 'der'
    }).slice(-32)); // Extract raw 32-byte private key

    // Derive shared secret with server's public key
    const serverPublicKeyObject = crypto.createPublicKey(getECCPublicKey());
    const serverPublicKeyRaw = serverPublicKeyObject.export({ type: 'spki', format: 'der' });
    const sharedSecret = ecdh.computeSecret(serverPublicKeyRaw.slice(-65)); // Extract raw 65-byte public key

    // Use HKDF to derive encryption key from shared secret
    const encryptionKey = crypto.hkdfSync('sha256', sharedSecret, '', '', 32);

    // Encrypt AES key using AES-256-GCM with derived key
    const iv = crypto.randomBytes(12); // 12 bytes for GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
    let encrypted = cipher.update(aesKeyBuffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Return: ephemeral public key + iv + authTag + encrypted AES key
    return JSON.stringify({
        ephemeralPublicKey: ephemeral.publicKey,
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        encryptedKey: encrypted.toString('base64')
    });
}

/**
 * SECURITY CONCEPT: HYBRID DECRYPTION WITH ECC (v2)
 * 
 * Decrypts the AES key using ECC private key and ECDH
 */
function decryptAESKeyWithECC(encryptedDataJson) {
    const { ephemeralPublicKey, iv, authTag, encryptedKey } = JSON.parse(encryptedDataJson);

    // Create ECDH from server's private key
    const ecdh = crypto.createECDH('prime256v1');
    const serverPrivateKeyObject = crypto.createPrivateKey(getECCPrivateKey());
    ecdh.setPrivateKey(serverPrivateKeyObject.export({
        type: 'sec1',
        format: 'der'
    }).slice(-32)); // Extract raw 32-byte private key

    // Derive shared secret with ephemeral public key
    const ephemeralPublicKeyObject = crypto.createPublicKey(ephemeralPublicKey);
    const ephemeralPublicKeyRaw = ephemeralPublicKeyObject.export({ type: 'spki', format: 'der' });
    const sharedSecret = ecdh.computeSecret(ephemeralPublicKeyRaw.slice(-65)); // Extract raw 65-byte public key

    // Use HKDF to derive encryption key from shared secret
    const encryptionKey = crypto.hkdfSync('sha256', sharedSecret, '', '', 32);

    // Decrypt AES key using AES-256-GCM
    const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, Buffer.from(iv, 'base64'));
    decipher.setAuthTag(Buffer.from(authTag, 'base64'));
    let decrypted = decipher.update(Buffer.from(encryptedKey, 'base64'));
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted.toString('hex');
}

/**
 * LEGACY: RSA HYBRID ENCRYPTION (v1 - for backward compatibility)
 */
function encryptAESKeyWithRSA(aesKeyHex) {
    const aesKeyBuffer = Buffer.from(aesKeyHex, 'hex');

    const encryptedKey = crypto.publicEncrypt(
        {
            key: getRSAPublicKey(),
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        aesKeyBuffer
    );

    return encryptedKey.toString('base64');
}

/**
 * LEGACY: RSA HYBRID DECRYPTION (v1 - for backward compatibility)
 */
function decryptAESKeyWithRSA(encryptedKeyBase64) {
    const encryptedKeyBuffer = Buffer.from(encryptedKeyBase64, 'base64');

    const decryptedKey = crypto.privateDecrypt(
        {
            key: getRSAPrivateKey(),
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        encryptedKeyBuffer
    );

    return decryptedKey.toString('hex');
}

/**
 * SECURITY CONCEPT: HASHING (INTEGRITY)
 * 
 * Creates SHA-256 hash of content for integrity verification
 * - One-way function: cannot reverse hash to get original content
 * - Deterministic: same input always produces same hash
 * - Collision-resistant: extremely difficult to find two inputs with same hash
 * 
 * Used to verify content hasn't been tampered with
 */
function hashContent(content) {
    return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * SECURITY CONCEPT: DIGITAL SIGNATURE WITH ECC (v2)
 * 
 * Creates a digital signature using ECC private key
 * - Proves authenticity: only private key holder can create this signature
 * - Ensures integrity: if content changes, signature verification fails
 * - Uses ECDSA (Elliptic Curve Digital Signature Algorithm)
 */
function createDigitalSignatureECC(contentHash) {
    const sign = crypto.createSign('SHA256');
    sign.update(contentHash);
    sign.end();

    const signature = sign.sign(getECCPrivateKey(), 'base64');
    return signature;
}

/**
 * SECURITY CONCEPT: SIGNATURE VERIFICATION WITH ECC (v2)
 * 
 * Verifies digital signature using ECC public key
 */
function verifyDigitalSignatureECC(contentHash, signature) {
    const verify = crypto.createVerify('SHA256');
    verify.update(contentHash);
    verify.end();

    return verify.verify(getECCPublicKey(), signature, 'base64');
}

/**
 * LEGACY: RSA DIGITAL SIGNATURE (v1 - for backward compatibility)
 */
function createDigitalSignatureRSA(contentHash) {
    const sign = crypto.createSign('SHA256');
    sign.update(contentHash);
    sign.end();

    const signature = sign.sign(getRSAPrivateKey(), 'base64');
    return signature;
}

/**
 * LEGACY: RSA SIGNATURE VERIFICATION (v1 - for backward compatibility)
 */
function verifyDigitalSignatureRSA(contentHash, signature) {
    const verify = crypto.createVerify('SHA256');
    verify.update(contentHash);
    verify.end();

    return verify.verify(getRSAPublicKey(), signature, 'base64');
}

/**
 * SECURITY CONCEPT: ENCODING (QR CODE)
 * 
 * Generates QR code for capsule ID (Base64 encoded)
 * - Encoding: Converting data into different format for transmission/storage
 * - QR codes enable easy sharing and scanning of capsule IDs
 * - Not encryption: QR code can be decoded to get original data
 */
async function generateQRCode(data) {
    try {
        // Generate QR code as Data URL (Base64 encoded image)
        const qrCodeDataURL = await QRCode.toDataURL(data, {
            errorCorrectionLevel: 'H',
            type: 'image/png',
            width: 300,
            margin: 2
        });

        return qrCodeDataURL;
    } catch (error) {
        console.error('QR Code generation error:', error);
        throw error;
    }
}

/**
 * COMPLETE ENCRYPTION WORKFLOW (v2 - ECC)
 * 
 * Encrypts content and returns all necessary data for storage
 * Uses ECC P-256 for hybrid encryption (new default)
 */
async function encryptCapsuleContent(content, capsuleId, version = 'v2') {
    // Step 1: Hash the original content (for integrity verification)
    const contentHash = hashContent(content);

    // Step 2: Encrypt content with AES
    const { encryptedData, aesKey, iv } = encryptWithAES(content);

    // Step 3: Encrypt AES key (version-dependent)
    let encryptedAESKey;
    let signature;

    if (version === 'v2') {
        // Use ECC encryption
        encryptedAESKey = encryptAESKeyWithECC(aesKey);
        signature = createDigitalSignatureECC(contentHash);
    } else {
        // Use RSA encryption (v1 - legacy)
        encryptedAESKey = encryptAESKeyWithRSA(aesKey);
        signature = createDigitalSignatureRSA(contentHash);
    }

    // Step 4: Generate QR code
    const qrCode = await generateQRCode(capsuleId);

    return {
        encryptedContent: encryptedData,
        encryptedAESKey,
        iv,
        contentHash,
        signature,
        qrCode,
        cryptoVersion: version
    };
}

/**
 * COMPLETE DECRYPTION WORKFLOW (supports both v1 and v2)
 * 
 * Decrypts content and verifies integrity
 * Auto-detects version and uses appropriate algorithm
 */
function decryptCapsuleContent(encryptedContent, encryptedAESKey, iv, storedHash, signature, version = 'v1') {
    // Step 1: Decrypt AES key (version-dependent)
    let aesKey;
    if (version === 'v2') {
        // Use ECC decryption
        aesKey = decryptAESKeyWithECC(encryptedAESKey);
    } else {
        // Use RSA decryption (v1 - legacy)
        aesKey = decryptAESKeyWithRSA(encryptedAESKey);
    }

    // Step 2: Decrypt content using AES key
    const decryptedContent = decryptWithAES(encryptedContent, aesKey, iv);

    // Step 3: Hash the decrypted content
    const computedHash = hashContent(decryptedContent);

    // Step 4: Verify integrity (hash should match)
    if (computedHash !== storedHash) {
        throw new Error('Content integrity check failed! Content may have been tampered with.');
    }

    // Step 5: Verify digital signature (version-dependent)
    let isSignatureValid;
    if (version === 'v2') {
        isSignatureValid = verifyDigitalSignatureECC(storedHash, signature);
    } else {
        isSignatureValid = verifyDigitalSignatureRSA(storedHash, signature);
    }

    if (!isSignatureValid) {
        throw new Error('Digital signature verification failed! Content authenticity cannot be verified.');
    }

    return {
        content: decryptedContent,
        verified: true
    };
}

module.exports = {
    // Key generation
    generateECCKeyPair,
    generateRSAKeyPair,

    // Key getters
    getECCPublicKey,
    getECCPrivateKey,
    getRSAPublicKey,
    getRSAPrivateKey,

    // AES encryption (same for both versions)
    encryptWithAES,
    decryptWithAES,

    // Hybrid encryption v2 (ECC)
    encryptAESKeyWithECC,
    decryptAESKeyWithECC,

    // Hybrid encryption v1 (RSA - legacy)
    encryptAESKeyWithRSA,
    decryptAESKeyWithRSA,

    // Hashing (same for both versions)
    hashContent,

    // Digital signatures v2 (ECC)
    createDigitalSignatureECC,
    verifyDigitalSignatureECC,

    // Digital signatures v1 (RSA - legacy)
    createDigitalSignatureRSA,
    verifyDigitalSignatureRSA,

    // QR codes (same for both versions)
    generateQRCode,

    // High-level workflows (auto-versioned)
    encryptCapsuleContent,
    decryptCapsuleContent
};
