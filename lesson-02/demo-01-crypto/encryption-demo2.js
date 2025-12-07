// Encrypt and decrypt data using AES-256-GCM with secure IV and key management
const crypto = require('crypto');

// Infosec best practices:
// - Use secure random key and IV generation
// - Store keys securely (not hardcoded or in source code)
// - Use authenticated encryption (GCM)
// - Handle errors gracefully
// - Zero out sensitive buffers after use (if possible)

const algorithm = 'aes-256-gcm';
const key = crypto.randomBytes(32); // In production, securely store and retrieve this key
const iv = crypto.randomBytes(12); // GCM mode requires a 12-byte IV
const plaintext = 'This is some sensitive data that needs encryption.';

// Encrypt the data
function encrypt(text, key, iv) {
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();
  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

// Decrypt the data
function decrypt(encrypted, key, ivHex, authTagHex) {
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Example usage
try {
  const encryptedData = encrypt(plaintext, key, iv);
  console.log('Encrypted data:', encryptedData.encrypted);
  console.log('IV:', encryptedData.iv);
  console.log('Auth Tag:', encryptedData.authTag);

  // Decrypt to verify
  const decrypted = decrypt(
    encryptedData.encrypted,
    key,
    encryptedData.iv,
    encryptedData.authTag
  );
  console.log('Decrypted data:', decrypted);
} catch (err) {
  console.error('Encryption/Decryption error:', err);
}

// Note: In production, never log or expose keys, and use a secure key management system.
