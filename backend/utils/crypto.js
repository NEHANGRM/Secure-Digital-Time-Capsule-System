/**
 * CRYPTO UTILITIES MODULE
 * 
 * This module implements core cryptographic functions for the Time Capsule System:
 * 1. RSA Key Pair Generation (2048-bit) - for hybrid encryption
 * 2. AES-256-CBC Encryption/Decryption - for content encryption
 * 3. Hybrid Encryption - encrypt AES key with RSA public key
 * 4. SHA-256 Hashing - for content integrity verification
 * 5. Digital Signatures - RSA signature creation and verification
 * 6. QR Code Generation - Base64 encoded capsule IDs
 */

const crypto = require('crypto');
const QRCode = require('qrcode');

// Global RSA key pair (generated on server startup)
let RSA_KEYS = null;

/**
 * SECURITY CONCEPT: RSA KEY PAIR GENERATION
 * 
 * Generates a 2048-bit RSA key pair for asymmetric encryption.
 * - Public key: Used to encrypt AES keys (can be shared)
 * - Private key: Used to decrypt AES keys and create digital signatures (must be kept secret)
 * 
 * This implements the KEY EXCHANGE mechanism for secure key distribution.
 */
function generateRSAKeyPair() {
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
    console.log('✅ RSA Key Pair Generated (2048-bit)');
    return RSA_KEYS;
}

/**
 * Get the current RSA public key
 */
function getPublicKey() {
    if (!RSA_KEYS) {
        throw new Error('RSA keys not initialized. Call generateRSAKeyPair() first.');
    }
    return RSA_KEYS.publicKey;
}

/**
 * Get the current RSA private key
 */
function getPrivateKey() {
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
 * SECURITY CONCEPT: HYBRID ENCRYPTION
 * 
 * Combines symmetric (AES) and asymmetric (RSA) encryption:
 * 1. Content is encrypted with AES (fast, efficient for large data)
 * 2. AES key is encrypted with RSA public key (secure key distribution)
 * 
 * This solves the key distribution problem: how to securely share the AES key?
 * Answer: Encrypt it with RSA public key, only private key holder can decrypt it.
 */
function encryptAESKeyWithRSA(aesKeyHex) {
    const aesKeyBuffer = Buffer.from(aesKeyHex, 'hex');

    const encryptedKey = crypto.publicEncrypt(
        {
            key: getPublicKey(),
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        aesKeyBuffer
    );

    return encryptedKey.toString('base64');
}

/**
 * SECURITY CONCEPT: HYBRID DECRYPTION
 * 
 * Decrypts the AES key using RSA private key
 */
function decryptAESKeyWithRSA(encryptedKeyBase64) {
    const encryptedKeyBuffer = Buffer.from(encryptedKeyBase64, 'base64');

    const decryptedKey = crypto.privateDecrypt(
        {
            key: getPrivateKey(),
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
 * SECURITY CONCEPT: DIGITAL SIGNATURE (AUTHENTICATION + INTEGRITY)
 * 
 * Creates a digital signature using RSA private key
 * - Proves authenticity: only private key holder can create this signature
 * - Ensures integrity: if content changes, signature verification fails
 * 
 * Process:
 * 1. Hash the content (SHA-256)
 * 2. Encrypt the hash with private key = signature
 */
function createDigitalSignature(contentHash) {
    const sign = crypto.createSign('SHA256');
    sign.update(contentHash);
    sign.end();

    const signature = sign.sign(getPrivateKey(), 'base64');
    return signature;
}

/**
 * SECURITY CONCEPT: SIGNATURE VERIFICATION
 * 
 * Verifies digital signature using RSA public key
 * Returns true if signature is valid, false otherwise
 * 
 * Process:
 * 1. Hash the content (SHA-256)
 * 2. Decrypt signature with public key
 * 3. Compare decrypted hash with computed hash
 */
function verifyDigitalSignature(contentHash, signature) {
    const verify = crypto.createVerify('SHA256');
    verify.update(contentHash);
    verify.end();

    return verify.verify(getPublicKey(), signature, 'base64');
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
 * COMPLETE ENCRYPTION WORKFLOW
 * 
 * Encrypts content and returns all necessary data for storage
 */
async function encryptCapsuleContent(content, capsuleId) {
    // Step 1: Hash the original content (for integrity verification)
    const contentHash = hashContent(content);

    // Step 2: Encrypt content with AES
    const { encryptedData, aesKey, iv } = encryptWithAES(content);

    // Step 3: Encrypt AES key with RSA (hybrid encryption)
    const encryptedAESKey = encryptAESKeyWithRSA(aesKey);

    // Step 4: Create digital signature
    const signature = createDigitalSignature(contentHash);

    // Step 5: Generate QR code
    const qrCode = await generateQRCode(capsuleId);

    return {
        encryptedContent: encryptedData,
        encryptedAESKey,
        iv,
        contentHash,
        signature,
        qrCode
    };
}

/**
 * COMPLETE DECRYPTION WORKFLOW
 * 
 * Decrypts content and verifies integrity
 */
function decryptCapsuleContent(encryptedContent, encryptedAESKey, iv, storedHash, signature) {
    // Step 1: Decrypt AES key using RSA private key
    const aesKey = decryptAESKeyWithRSA(encryptedAESKey);

    // Step 2: Decrypt content using AES key
    const decryptedContent = decryptWithAES(encryptedContent, aesKey, iv);

    // Step 3: Hash the decrypted content
    const computedHash = hashContent(decryptedContent);

    // Step 4: Verify integrity (hash should match)
    if (computedHash !== storedHash) {
        throw new Error('Content integrity check failed! Content may have been tampered with.');
    }

    // Step 5: Verify digital signature
    const isSignatureValid = verifyDigitalSignature(storedHash, signature);
    if (!isSignatureValid) {
        throw new Error('Digital signature verification failed! Content authenticity cannot be verified.');
    }

    return {
        content: decryptedContent,
        verified: true
    };
}

module.exports = {
    generateRSAKeyPair,
    getPublicKey,
    getPrivateKey,
    encryptWithAES,
    decryptWithAES,
    encryptAESKeyWithRSA,
    decryptAESKeyWithRSA,
    hashContent,
    createDigitalSignature,
    verifyDigitalSignature,
    generateQRCode,
    encryptCapsuleContent,
    decryptCapsuleContent
};
