/**
 * AES-256-GCM Encryption Demo
 *
 * This demonstrates secure encryption practices using AES-256-GCM (Galois/Counter Mode),
 * which provides both confidentiality AND authenticity (authenticated encryption).
 *
 * Security Decisions Explained:
 *
 * 1. AES-256-GCM Algorithm Choice:
 *    - AES-256: Industry standard, NIST-approved symmetric encryption
 *    - GCM Mode: Provides BOTH encryption and authentication (prevents tampering)
 *    - Alternative modes like CBC only encrypt, don't authenticate
 *
 * 2. IV (Initialization Vector) Generation:
 *    - Uses crypto.randomBytes(12) for cryptographically secure random generation
 *    - 12 bytes (96 bits) is optimal for GCM mode per NIST SP 800-38D
 *    - NEVER reuse IVs with the same key (breaks GCM security guarantee)
 *    - Math.random() is NOT cryptographically secure - never use it for IVs
 *
 * 3. Authentication Tag:
 *    - GCM produces a 16-byte authentication tag (default)
 *    - Tag is verified during decryption to detect tampering
 *    - If ciphertext is modified, decryption will fail (authenticated encryption)
 *
 * 4. Key Derivation (PBKDF2):
 *    - Derives encryption key from password using PBKDF2-SHA256
 *    - 600,000 iterations meets PCI-DSS v4.0 requirements (Section 3.6.1.1)
 *    - Salt is random, stored with ciphertext, prevents rainbow table attacks
 *    - PBKDF2 is intentionally slow to resist brute-force attacks
 *
 * 5. Data Storage Format:
 *    - Prepends salt, IV, and tag to ciphertext for storage
 *    - Everything except the password can be public (Kerckhoffs's principle)
 *    - Format: [salt(16)][iv(12)][tag(16)][ciphertext(variable)]
 *
 * References:
 * - NIST SP 800-38D (GCM specification)
 * - PCI-DSS v4.0 Section 3.6.1.1 (Key derivation requirements)
 * - OWASP Cryptographic Storage Cheat Sheet
 */

const crypto = require('crypto');

// Constants for cryptographic parameters
const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;        // 256 bits for AES-256
const IV_LENGTH = 12;         // 96 bits, optimal for GCM
const SALT_LENGTH = 16;       // 128 bits for PBKDF2 salt
const TAG_LENGTH = 16;        // 128 bits for GCM authentication tag
const PBKDF2_ITERATIONS = 600000; // PCI-DSS v4.0 requirement
const PBKDF2_DIGEST = 'sha256';

/**
 * Derives a cryptographic key from a password using PBKDF2
 *
 * @param {string} password - User-provided password
 * @param {Buffer} salt - Random salt (generated if not provided)
 * @returns {Object} { key: Buffer, salt: Buffer }
 */
function deriveKey(password, salt = null) {
  // Generate new salt if not provided (for encryption)
  if (!salt) {
    salt = crypto.randomBytes(SALT_LENGTH);
  }

  // PBKDF2 parameters explained:
  // - password: Source key material
  // - salt: Random value to prevent rainbow tables
  // - iterations: 600,000 per PCI-DSS v4.0 (intentionally slow)
  // - keylen: 32 bytes for AES-256
  // - digest: SHA-256 hash function
  const key = crypto.pbkdf2Sync(
    password,
    salt,
    PBKDF2_ITERATIONS,
    KEY_LENGTH,
    PBKDF2_DIGEST
  );

  return { key, salt };
}

/**
 * Encrypts plaintext using AES-256-GCM with password-based key derivation
 *
 * Security features:
 * - AES-256-GCM provides confidentiality + authenticity
 * - Cryptographically secure IV generation (crypto.randomBytes)
 * - PBKDF2 key derivation with 600,000 iterations (PCI-DSS compliant)
 * - Authentication tag prevents tampering
 *
 * @param {string} plaintext - Data to encrypt
 * @param {string} password - Encryption password
 * @returns {Buffer} Encrypted data with prepended salt, IV, and auth tag
 */
function encrypt(plaintext, password) {
  // Step 1: Derive encryption key from password
  const { key, salt } = deriveKey(password);

  // Step 2: Generate cryptographically secure IV
  // CRITICAL: Never reuse IV with same key (breaks GCM security)
  const iv = crypto.randomBytes(IV_LENGTH);

  // Step 3: Create cipher with AES-256-GCM
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  // Step 4: Encrypt the plaintext
  let ciphertext = cipher.update(plaintext, 'utf8');
  ciphertext = Buffer.concat([ciphertext, cipher.final()]);

  // Step 5: Extract authentication tag
  // This tag is verified during decryption to detect tampering
  const tag = cipher.getAuthTag();

  // Step 6: Combine all components for storage
  // Format: [salt(16)][iv(12)][tag(16)][ciphertext(variable)]
  // All components except password can be public (Kerckhoffs's principle)
  return Buffer.concat([salt, iv, tag, ciphertext]);
}

/**
 * Decrypts ciphertext using AES-256-GCM with password-based key derivation
 *
 * Security features:
 * - Verifies authentication tag to detect tampering
 * - Extracts salt, IV, tag from prepended data
 * - Re-derives key using same PBKDF2 parameters
 * - Throws error if authentication fails (tampered data)
 *
 * @param {Buffer} encryptedData - Encrypted data from encrypt()
 * @param {string} password - Decryption password
 * @returns {string} Decrypted plaintext
 * @throws {Error} If authentication fails or password is incorrect
 */
function decrypt(encryptedData, password) {
  // Step 1: Extract components from encrypted data
  // Format: [salt(16)][iv(12)][tag(16)][ciphertext(variable)]
  const salt = encryptedData.subarray(0, SALT_LENGTH);
  const iv = encryptedData.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const tag = encryptedData.subarray(
    SALT_LENGTH + IV_LENGTH,
    SALT_LENGTH + IV_LENGTH + TAG_LENGTH
  );
  const ciphertext = encryptedData.subarray(SALT_LENGTH + IV_LENGTH + TAG_LENGTH);

  // Step 2: Re-derive key from password using extracted salt
  const { key } = deriveKey(password, salt);

  // Step 3: Create decipher with AES-256-GCM
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);

  // Step 4: Set authentication tag for verification
  // If tag doesn't match, decipher.final() will throw error
  decipher.setAuthTag(tag);

  // Step 5: Decrypt the ciphertext
  // Authentication tag is verified during final() call
  let plaintext = decipher.update(ciphertext);
  plaintext = Buffer.concat([plaintext, decipher.final()]);

  return plaintext.toString('utf8');
}

/**
 * Demo execution: Shows encryption and decryption with tampering detection
 */
function demo() {
  console.log('=== AES-256-GCM Encryption Demo ===\n');

  const password = 'MySecureP@ssw0rd!2024';
  const sensitiveData = 'Credit Card: 4532-1234-5678-9010, CVV: 123';

  console.log('Original Data:', sensitiveData);
  console.log('Password:', password.replace(/./g, '*'), '\n');

  // Encrypt the data
  console.log('Encrypting with AES-256-GCM...');
  const encrypted = encrypt(sensitiveData, password);
  console.log('Encrypted (hex):', encrypted.toString('hex'));
  console.log('Encrypted (base64):', encrypted.toString('base64'));
  console.log(`Total Size: ${encrypted.length} bytes (salt: ${SALT_LENGTH}, IV: ${IV_LENGTH}, tag: ${TAG_LENGTH}, ciphertext: ${encrypted.length - SALT_LENGTH - IV_LENGTH - TAG_LENGTH})\n`);

  // Decrypt the data
  console.log('Decrypting...');
  const decrypted = decrypt(encrypted, password);
  console.log('Decrypted Data:', decrypted);
  console.log('Match:', sensitiveData === decrypted ? '✓ Success' : '✗ Failed', '\n');

  // Demonstrate tampering detection
  console.log('=== Tampering Detection Demo ===\n');
  console.log('Attempting to decrypt tampered data...');
  const tampered = Buffer.from(encrypted);
  tampered[tampered.length - 1] ^= 0xFF; // Flip bits in last byte

  try {
    decrypt(tampered, password);
    console.log('✗ SECURITY FAILURE: Tampering not detected!');
  } catch (error) {
    console.log('✓ SUCCESS: Tampering detected!');
    console.log('Error:', error.message, '\n');
  }

  // Demonstrate wrong password
  console.log('=== Wrong Password Demo ===\n');
  console.log('Attempting to decrypt with wrong password...');
  try {
    decrypt(encrypted, 'WrongPassword123');
    console.log('✗ SECURITY FAILURE: Wrong password accepted!');
  } catch (error) {
    console.log('✓ SUCCESS: Wrong password rejected!');
    console.log('Error:', error.message, '\n');
  }

  console.log('=== Security Features Demonstrated ===');
  console.log('✓ AES-256-GCM authenticated encryption');
  console.log('✓ Cryptographically secure IV generation');
  console.log('✓ PBKDF2 key derivation (600,000 iterations, PCI-DSS compliant)');
  console.log('✓ Authentication tag prevents tampering');
  console.log('✓ Salt prevents rainbow table attacks');
}

// Run demo if executed directly
if (require.main === module) {
  demo();
}

// Export functions for use in other modules
module.exports = {
  encrypt,
  decrypt,
  deriveKey,
  PBKDF2_ITERATIONS,
  ALGORITHM
};
