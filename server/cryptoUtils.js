const crypto = require('crypto');

class EncryptionService {
    constructor(passphrase, salt = null, userId = null) {
        this.algorithm = 'aes-256-gcm';
        this.keyLength = 32;
        this.ivLength = 16;
        this.saltLength = 32;
        this.tagLength = 16;
        
        // Generate salt if not provided
        if (!salt) {
            this.salt = crypto.randomBytes(this.saltLength);
        } else {
            this.salt = salt instanceof Buffer ? salt : Buffer.from(salt, 'hex');
        }
        
        // Derive key from passphrase and salt
        this.key = crypto.pbkdf2Sync(passphrase, this.salt, 100000, this.keyLength, 'sha512');
        
        // Store user ID for AAD generation
        this.userId = userId;
    }
    
    // Helper method to generate a static AAD
    generateAAD() {
        // Use static AAD that doesn't change between encryption and decryption
        const aad = this.userId
            ? Buffer.from(`${this.userId}-encrypted-todo-app`, 'utf8') // Static AAD with userId
            : Buffer.from('encrypted-todo-app', 'utf8'); // Static fallback AAD
        return aad;
    }
    
    encrypt(text) {
        if (!text) return null;
        
        try {
            const iv = crypto.randomBytes(this.ivLength);
            const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
            
            // Generate the static AAD
            const aad = this.generateAAD();
            cipher.setAAD(aad);
            
            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            const tag = cipher.getAuthTag();
            
            // Return structured data
            return {
                salt: this.salt.toString('hex'),
                iv: iv.toString('hex'),
                tag: tag.toString('hex'),
                encrypted: encrypted
            };
        } catch (error) {
            console.error('Encryption error:', error);
            throw new Error('Failed to encrypt data. Please try again.');
        }
    }
    
    decrypt(encryptedData) {
        if (!encryptedData || !encryptedData.salt || !encryptedData.iv || !encryptedData.tag || !encryptedData.encrypted) {
            throw new Error('Missing required fields for decryption.');
        }
        
        try {
            // Extract components from encrypted data
            const saltBuffer = Buffer.from(encryptedData.salt, 'hex');
            const iv = Buffer.from(encryptedData.iv, 'hex');
            const tag = Buffer.from(encryptedData.tag, 'hex');
            const encrypted = encryptedData.encrypted;
            
            // Create a decipher with the same key derived from the salt
            const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
            
            // Use the same static AAD as during encryption
            const aad = this.generateAAD();
            decipher.setAAD(aad);
            decipher.setAuthTag(tag);
            
            let decrypted = decipher.update(encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            return decrypted;
        } catch (error) {
            console.error('Decryption error:', error);
            throw new Error('Failed to decrypt data. The data may be corrupted or tampered with.');
        }
    }
    
    // Helper method to get the salt (useful for storing/retrieving)
    getSalt() {
        return this.salt.toString('hex');
    }
}

module.exports = EncryptionService;
