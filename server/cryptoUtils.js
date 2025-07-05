const crypto = require('crypto');

class EncryptionService {
  constructor(secret) {
    this.algorithm = 'aes-256-cbc';
    this.key = crypto.createHash('sha256').update(String(secret)).digest();
  }

  encrypt(data) {
    try {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
      let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
      encrypted += cipher.final('hex');
      return iv.toString('hex') + encrypted;
    } catch (error) {
      console.error('Encryption error:', error);
      throw new Error('Encryption failed');
    }
  }

  decrypt(encryptedData) {
    try {
      const iv = Buffer.from(encryptedData.slice(0, 32), 'hex');
      const encryptedText = encryptedData.slice(32);
      const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
      let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return JSON.parse(decrypted);
    } catch (error) {
      console.error('[Decryption Error]:', error);
      throw new Error('Decryption failed');
    }
  }
}

module.exports = EncryptionService;
