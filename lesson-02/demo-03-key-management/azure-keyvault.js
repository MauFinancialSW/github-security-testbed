/**
 * Azure Key Vault Integration Demo
 * =================================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 02 - Security Protocols with Copilot
 *
 * Copilot Prompt Used:
 * "Integrate with Azure Key Vault for secret management"
 *
 * Security Features:
 * - Managed Identity authentication (no hardcoded credentials)
 * - Automatic secret rotation support
 * - Audit logging integration
 * - Fallback to local development mode
 */

const { DefaultAzureCredential } = require('@azure/identity');
const { SecretClient } = require('@azure/keyvault-secrets');
const { KeyClient } = require('@azure/keyvault-keys');
const { CryptographyClient } = require('@azure/keyvault-keys');

// =============================================================================
// Key Vault Client Setup
// =============================================================================

class AzureKeyVaultManager {
  constructor(vaultUrl) {
    this.vaultUrl = vaultUrl || process.env.AZURE_KEYVAULT_URL;

    if (!this.vaultUrl) {
      throw new Error('Azure Key Vault URL is required. Set AZURE_KEYVAULT_URL environment variable.');
    }

    // Use DefaultAzureCredential for flexible authentication
    // Works with: Managed Identity, Azure CLI, VS Code, Environment variables
    this.credential = new DefaultAzureCredential();

    // Initialize clients
    this.secretClient = new SecretClient(this.vaultUrl, this.credential);
    this.keyClient = new KeyClient(this.vaultUrl, this.credential);
  }

  // ===========================================================================
  // Secret Management
  // ===========================================================================

  /**
   * Store a secret in Key Vault
   * @param {string} name - Secret name
   * @param {string} value - Secret value
   * @param {Object} options - Optional metadata
   * @returns {Promise<Object>} - Secret properties
   */
  async setSecret(name, value, options = {}) {
    const {
      contentType = 'text/plain',
      expiresOn = null,
      notBefore = null,
      tags = {}
    } = options;

    const secretProperties = {
      contentType,
      tags: {
        ...tags,
        managedBy: 'copilot-security-demo',
        createdAt: new Date().toISOString()
      }
    };

    if (expiresOn) secretProperties.expiresOn = expiresOn;
    if (notBefore) secretProperties.notBefore = notBefore;

    const result = await this.secretClient.setSecret(name, value, secretProperties);

    console.log(`Secret '${name}' stored successfully`);
    console.log(`  Version: ${result.properties.version}`);
    console.log(`  Created: ${result.properties.createdOn}`);

    return {
      name: result.name,
      version: result.properties.version,
      createdOn: result.properties.createdOn
    };
  }

  /**
   * Retrieve a secret from Key Vault
   * @param {string} name - Secret name
   * @param {string} version - Optional specific version
   * @returns {Promise<string>} - Secret value
   */
  async getSecret(name, version = null) {
    const options = version ? { version } : {};
    const secret = await this.secretClient.getSecret(name, options);

    // Log access (for audit purposes)
    console.log(`Secret '${name}' accessed at ${new Date().toISOString()}`);

    return secret.value;
  }

  /**
   * List all secrets (names only, not values)
   * @returns {Promise<Array>} - List of secret names and metadata
   */
  async listSecrets() {
    const secrets = [];

    for await (const secretProperties of this.secretClient.listPropertiesOfSecrets()) {
      secrets.push({
        name: secretProperties.name,
        enabled: secretProperties.enabled,
        createdOn: secretProperties.createdOn,
        updatedOn: secretProperties.updatedOn,
        expiresOn: secretProperties.expiresOn,
        tags: secretProperties.tags
      });
    }

    return secrets;
  }

  /**
   * Delete a secret (soft delete)
   * @param {string} name - Secret name
   * @returns {Promise<Object>} - Deletion info
   */
  async deleteSecret(name) {
    const poller = await this.secretClient.beginDeleteSecret(name);
    const deletedSecret = await poller.pollUntilDone();

    console.log(`Secret '${name}' deleted`);
    console.log(`  Scheduled purge date: ${deletedSecret.scheduledPurgeDate}`);

    return {
      name: deletedSecret.name,
      deletedOn: deletedSecret.deletedOn,
      scheduledPurgeDate: deletedSecret.scheduledPurgeDate
    };
  }

  // ===========================================================================
  // Key Management
  // ===========================================================================

  /**
   * Create an RSA key for encryption/signing
   * @param {string} name - Key name
   * @param {Object} options - Key options
   * @returns {Promise<Object>} - Key properties
   */
  async createRsaKey(name, options = {}) {
    const {
      keySize = 2048,
      expiresOn = null,
      keyOps = ['encrypt', 'decrypt', 'sign', 'verify', 'wrapKey', 'unwrapKey']
    } = options;

    const key = await this.keyClient.createRsaKey(name, {
      keySize,
      expiresOn,
      keyOps,
      tags: {
        managedBy: 'copilot-security-demo',
        purpose: 'encryption'
      }
    });

    console.log(`RSA key '${name}' created`);
    console.log(`  Key ID: ${key.id}`);
    console.log(`  Key Size: ${keySize} bits`);

    return {
      name: key.name,
      id: key.id,
      keyType: key.keyType,
      keyOps: key.keyOperations
    };
  }

  /**
   * Create an EC key for signing
   * @param {string} name - Key name
   * @param {string} curve - EC curve (P-256, P-384, P-521)
   * @returns {Promise<Object>} - Key properties
   */
  async createEcKey(name, curve = 'P-256') {
    const key = await this.keyClient.createEcKey(name, {
      curve,
      keyOps: ['sign', 'verify'],
      tags: {
        managedBy: 'copilot-security-demo',
        purpose: 'signing'
      }
    });

    console.log(`EC key '${name}' created with curve ${curve}`);

    return {
      name: key.name,
      id: key.id,
      curve: key.key.crv
    };
  }

  /**
   * Encrypt data using Key Vault key
   * @param {string} keyName - Key to use
   * @param {Buffer} plaintext - Data to encrypt
   * @returns {Promise<Buffer>} - Encrypted data
   */
  async encrypt(keyName, plaintext) {
    const key = await this.keyClient.getKey(keyName);
    const cryptoClient = new CryptographyClient(key, this.credential);

    const result = await cryptoClient.encrypt('RSA-OAEP', plaintext);

    return result.result;
  }

  /**
   * Decrypt data using Key Vault key
   * @param {string} keyName - Key to use
   * @param {Buffer} ciphertext - Data to decrypt
   * @returns {Promise<Buffer>} - Decrypted data
   */
  async decrypt(keyName, ciphertext) {
    const key = await this.keyClient.getKey(keyName);
    const cryptoClient = new CryptographyClient(key, this.credential);

    const result = await cryptoClient.decrypt('RSA-OAEP', ciphertext);

    return result.result;
  }

  /**
   * Sign data using Key Vault key
   * @param {string} keyName - Key to use
   * @param {Buffer} digest - Hash to sign
   * @returns {Promise<Buffer>} - Signature
   */
  async sign(keyName, digest) {
    const key = await this.keyClient.getKey(keyName);
    const cryptoClient = new CryptographyClient(key, this.credential);

    const result = await cryptoClient.sign('RS256', digest);

    return result.result;
  }

  /**
   * Verify signature using Key Vault key
   * @param {string} keyName - Key to use
   * @param {Buffer} digest - Original hash
   * @param {Buffer} signature - Signature to verify
   * @returns {Promise<boolean>} - Verification result
   */
  async verify(keyName, digest, signature) {
    const key = await this.keyClient.getKey(keyName);
    const cryptoClient = new CryptographyClient(key, this.credential);

    const result = await cryptoClient.verify('RS256', digest, signature);

    return result.result;
  }

  // ===========================================================================
  // Secret Rotation
  // ===========================================================================

  /**
   * Rotate a secret (create new version)
   * @param {string} name - Secret name
   * @param {function} generateNewValue - Function to generate new secret value
   * @returns {Promise<Object>} - New secret version info
   */
  async rotateSecret(name, generateNewValue) {
    // Get current secret
    const currentSecret = await this.secretClient.getSecret(name);

    // Generate new value
    const newValue = await generateNewValue(currentSecret.value);

    // Store new version (Key Vault automatically versions)
    const result = await this.setSecret(name, newValue, {
      contentType: currentSecret.properties.contentType,
      tags: {
        ...currentSecret.properties.tags,
        previousVersion: currentSecret.properties.version,
        rotatedAt: new Date().toISOString()
      }
    });

    console.log(`Secret '${name}' rotated`);
    console.log(`  Previous version: ${currentSecret.properties.version}`);
    console.log(`  New version: ${result.version}`);

    return result;
  }

  /**
   * Setup automatic rotation policy
   * @param {string} secretName - Secret to rotate
   * @param {number} rotationIntervalDays - Days between rotations
   * @returns {Promise<Object>} - Rotation policy
   */
  async setRotationPolicy(secretName, rotationIntervalDays = 90) {
    // Note: This is a simplified example
    // Azure Key Vault has built-in rotation policies via Azure Portal/CLI

    const policy = {
      secretName,
      rotationInterval: `P${rotationIntervalDays}D`,
      expiryTime: `P${rotationIntervalDays + 30}D`,
      notifyBeforeExpiry: 'P30D'
    };

    console.log(`Rotation policy for '${secretName}':`);
    console.log(`  Rotate every: ${rotationIntervalDays} days`);
    console.log(`  Notify: 30 days before expiry`);

    return policy;
  }
}

// =============================================================================
// Local Development Fallback
// =============================================================================

class LocalSecretManager {
  constructor() {
    this.secrets = new Map();
    console.warn('Using LOCAL secret manager - NOT FOR PRODUCTION');
  }

  async setSecret(name, value, options = {}) {
    this.secrets.set(name, {
      value,
      version: Date.now().toString(),
      createdOn: new Date(),
      ...options
    });
    return { name, version: Date.now().toString() };
  }

  async getSecret(name) {
    const secret = this.secrets.get(name);
    if (!secret) throw new Error(`Secret '${name}' not found`);
    return secret.value;
  }

  async listSecrets() {
    return Array.from(this.secrets.keys()).map(name => ({
      name,
      enabled: true
    }));
  }

  async deleteSecret(name) {
    this.secrets.delete(name);
    return { name, deletedOn: new Date() };
  }
}

// =============================================================================
// Factory Function
// =============================================================================

/**
 * Create appropriate secret manager based on environment
 * @param {string} vaultUrl - Optional Key Vault URL
 * @returns {AzureKeyVaultManager|LocalSecretManager}
 */
function createSecretManager(vaultUrl = null) {
  const url = vaultUrl || process.env.AZURE_KEYVAULT_URL;

  if (url) {
    return new AzureKeyVaultManager(url);
  }

  if (process.env.NODE_ENV === 'production') {
    throw new Error('AZURE_KEYVAULT_URL is required in production');
  }

  return new LocalSecretManager();
}

// =============================================================================
// Export
// =============================================================================

module.exports = {
  AzureKeyVaultManager,
  LocalSecretManager,
  createSecretManager
};

// =============================================================================
// Demo
// =============================================================================

if (require.main === module) {
  async function demo() {
    console.log('=== Azure Key Vault Demo ===\n');

    try {
      const manager = createSecretManager();

      // Store secrets
      await manager.setSecret('database-password', 'super-secret-password-123');
      await manager.setSecret('api-key', 'sk-live-abcdef123456');

      // Retrieve secret
      const dbPassword = await manager.getSecret('database-password');
      console.log('\nRetrieved database password:', dbPassword.substring(0, 5) + '***');

      // List secrets
      const secrets = await manager.listSecrets();
      console.log('\nStored secrets:', secrets.map(s => s.name));

    } catch (error) {
      console.error('Demo error:', error.message);
    }
  }

  demo();
}
