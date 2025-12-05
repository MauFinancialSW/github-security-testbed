/**
 * Cryptographic Operations Demo
 * =============================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 02 - Security Protocols with Copilot
 *
 * This demonstrates Copilot's understanding of cryptographic best practices.
 * Watch Copilot suggest secure implementations when you type the comments.
 *
 * Key Security Decisions Copilot Makes:
 * - AES-256-GCM (authenticated encryption)
 * - crypto.randomBytes (cryptographically secure)
 * - 12-byte IV (correct for GCM mode)
 * - Authentication tag extraction
 * - IV/tag prepended to ciphertext
 */

const crypto = require('crypto');

// =============================================================================
// DEMO 1.1: AES-256-GCM Encryption with Secure IV Generation
// =============================================================================
// Type this comment and watch Copilot complete:
// Encrypt data using AES-256-GCM with secure IV generation

/**
 * Encrypt plaintext using AES-256-GCM
 * @param {string|Buffer} plaintext - Data to encrypt
 * @param {Buffer} key - 32-byte encryption key
 * @returns {Buffer} - IV + Auth Tag + Ciphertext
 */
function encrypt(plaintext, key) {
  // Generate cryptographically secure IV (12 bytes for GCM)
  const iv = crypto.randomBytes(12);

  // Create cipher with AES-256-GCM (authenticated encryption)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  // Encrypt the plaintext
  let ciphertext = cipher.update(plaintext, 'utf8');
  ciphertext = Buffer.concat([ciphertext, cipher.final()]);

  // Get authentication tag (16 bytes)
  const tag = cipher.getAuthTag();

  // Prepend IV and tag to ciphertext for storage/transmission
  // Format: [IV (12 bytes)][Tag (16 bytes)][Ciphertext]
  return Buffer.concat([iv, tag, ciphertext]);
}

/**
 * Decrypt ciphertext using AES-256-GCM
 * @param {Buffer} encryptedData - IV + Auth Tag + Ciphertext
 * @param {Buffer} key - 32-byte encryption key
 * @returns {string} - Decrypted plaintext
 */
function decrypt(encryptedData, key) {
  // Extract IV (first 12 bytes)
  const iv = encryptedData.subarray(0, 12);

  // Extract authentication tag (next 16 bytes)
  const tag = encryptedData.subarray(12, 28);

  // Extract ciphertext (remainder)
  const ciphertext = encryptedData.subarray(28);

  // Create decipher
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  // Decrypt
  let plaintext = decipher.update(ciphertext);
  plaintext = Buffer.concat([plaintext, decipher.final()]);

  return plaintext.toString('utf8');
}

// =============================================================================
// DEMO 1.2: Password-Based Key Derivation (PCI-DSS Compliant)
// =============================================================================
// Copilot knows compliance requirements for key derivation

/**
 * Derive encryption key from password using PBKDF2
 * PCI-DSS requires minimum 600,000 iterations as of 2023
 * @param {string} password - User password
 * @param {Buffer} salt - Random salt (should be stored with ciphertext)
 * @returns {Promise<Buffer>} - 32-byte derived key
 */
async function deriveKey(password, salt = null) {
  // Generate random salt if not provided
  const keySalt = salt || crypto.randomBytes(32);

  // PBKDF2 with 600,000+ iterations (PCI-DSS compliant)
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(
      password,
      keySalt,
      600000,  // Iteration count - PCI-DSS minimum
      32,      // Key length (256 bits for AES-256)
      'sha512', // Hash function
      (err, derivedKey) => {
        if (err) reject(err);
        resolve({ key: derivedKey, salt: keySalt });
      }
    );
  });
}

// =============================================================================
// DEMO 1.3: Secure Random Token Generation
// =============================================================================

/**
 * Generate cryptographically secure random token
 * Suitable for API keys, session tokens, CSRF tokens
 * @param {number} length - Token length in bytes (default: 32)
 * @returns {string} - Hex-encoded token
 */
function generateSecureToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Generate URL-safe base64 token
 * @param {number} length - Token length in bytes
 * @returns {string} - URL-safe base64 token
 */
function generateUrlSafeToken(length = 32) {
  return crypto.randomBytes(length)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// =============================================================================
// DEMO 1.4: HMAC for Message Authentication
// =============================================================================

/**
 * Create HMAC for message authentication
 * @param {string} message - Message to authenticate
 * @param {Buffer} key - HMAC key
 * @returns {string} - Hex-encoded HMAC
 */
function createHmac(message, key) {
  return crypto
    .createHmac('sha256', key)
    .update(message)
    .digest('hex');
}

/**
 * Verify HMAC using constant-time comparison
 * @param {string} message - Original message
 * @param {string} providedHmac - HMAC to verify
 * @param {Buffer} key - HMAC key
 * @returns {boolean} - True if valid
 */
function verifyHmac(message, providedHmac, key) {
  const expectedHmac = createHmac(message, key);

  // CRITICAL: Use timing-safe comparison to prevent timing attacks
  return crypto.timingSafeEqual(
    Buffer.from(expectedHmac, 'hex'),
    Buffer.from(providedHmac, 'hex')
  );
}

// =============================================================================
// DEMO 1.5: Secure Password Hashing with Argon2
// =============================================================================
// Note: Requires 'argon2' package: npm install argon2

const argon2 = require('argon2');

/**
 * Hash password using Argon2id (recommended for password hashing)
 * @param {string} password - Password to hash
 * @returns {Promise<string>} - Argon2 hash string
 */
async function hashPassword(password) {
  return argon2.hash(password, {
    type: argon2.argon2id,  // Argon2id - resistant to both side-channel and GPU attacks
    memoryCost: 65536,      // 64 MB memory
    timeCost: 3,            // 3 iterations
    parallelism: 4          // 4 parallel threads
  });
}

/**
 * Verify password against Argon2 hash
 * @param {string} hash - Stored Argon2 hash
 * @param {string} password - Password to verify
 * @returns {Promise<boolean>} - True if valid
 */
async function verifyPassword(hash, password) {
  return argon2.verify(hash, password);
}

// =============================================================================
// Usage Examples
// =============================================================================

async function demonstrateCrypto() {
  console.log('=== Cryptographic Operations Demo ===\n');

  // Generate encryption key
  const key = crypto.randomBytes(32);
  console.log('Generated 256-bit key:', key.toString('hex').substring(0, 32) + '...');

  // Encrypt/decrypt
  const message = 'Sensitive data: SSN 123-45-6789';
  const encrypted = encrypt(message, key);
  console.log('\nEncrypted:', encrypted.toString('hex').substring(0, 64) + '...');

  const decrypted = decrypt(encrypted, key);
  console.log('Decrypted:', decrypted);

  // Password-based key derivation
  console.log('\n--- Password-Based Key Derivation ---');
  const { key: derivedKey, salt } = await deriveKey('user-password-123');
  console.log('Derived key from password (PBKDF2, 600K iterations)');
  console.log('Salt:', salt.toString('hex').substring(0, 32) + '...');
  console.log('Key:', derivedKey.toString('hex').substring(0, 32) + '...');

  // Secure tokens
  console.log('\n--- Secure Token Generation ---');
  console.log('API Token:', generateSecureToken());
  console.log('URL-Safe Token:', generateUrlSafeToken());

  // HMAC
  console.log('\n--- HMAC Message Authentication ---');
  const hmacKey = crypto.randomBytes(32);
  const hmac = createHmac('Important message', hmacKey);
  console.log('HMAC:', hmac);
  console.log('Verification:', verifyHmac('Important message', hmac, hmacKey));

  // Password hashing
  console.log('\n--- Argon2 Password Hashing ---');
  const passwordHash = await hashPassword('SecurePassword123!');
  console.log('Hash:', passwordHash.substring(0, 50) + '...');
  console.log('Verify correct:', await verifyPassword(passwordHash, 'SecurePassword123!'));
  console.log('Verify wrong:', await verifyPassword(passwordHash, 'WrongPassword'));
}

// Export for module use
module.exports = {
  encrypt,
  decrypt,
  deriveKey,
  generateSecureToken,
  generateUrlSafeToken,
  createHmac,
  verifyHmac,
  hashPassword,
  verifyPassword
};

// Run demo if executed directly
if (require.main === module) {
  demonstrateCrypto().catch(console.error);
}
