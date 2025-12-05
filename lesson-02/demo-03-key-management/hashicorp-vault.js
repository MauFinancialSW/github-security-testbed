/**
 * HashiCorp Vault Integration Demo
 * =================================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 02 - Security Protocols with Copilot
 *
 * Copilot Prompt Used:
 * "Integrate with HashiCorp Vault for secrets management"
 *
 * Security Features:
 * - AppRole authentication (machine-to-machine)
 * - Dynamic secrets generation
 * - Token renewal and revocation
 * - Transit engine for encryption-as-a-service
 */

const vault = require('node-vault');
const crypto = require('crypto');

// =============================================================================
// Vault Client Configuration
// =============================================================================

class HashiCorpVaultManager {
  constructor(options = {}) {
    this.options = {
      apiVersion: 'v1',
      endpoint: options.endpoint || process.env.VAULT_ADDR || 'http://127.0.0.1:8200',
      token: options.token || process.env.VAULT_TOKEN,
      ...options
    };

    this.client = vault(this.options);
    this.tokenRenewalInterval = null;
  }

  // ===========================================================================
  // Authentication Methods
  // ===========================================================================

  /**
   * Authenticate using AppRole (recommended for applications)
   * @param {string} roleId - Role ID
   * @param {string} secretId - Secret ID
   * @returns {Promise<Object>} - Auth response with token
   */
  async loginAppRole(roleId, secretId) {
    const result = await this.client.approleLogin({
      role_id: roleId,
      secret_id: secretId
    });

    // Update client with new token
    this.client.token = result.auth.client_token;

    console.log('AppRole authentication successful');
    console.log(`  Token TTL: ${result.auth.lease_duration}s`);
    console.log(`  Renewable: ${result.auth.renewable}`);

    // Setup automatic token renewal if renewable
    if (result.auth.renewable) {
      this.setupTokenRenewal(result.auth.lease_duration);
    }

    return {
      token: result.auth.client_token,
      accessor: result.auth.accessor,
      leaseDuration: result.auth.lease_duration,
      policies: result.auth.policies
    };
  }

  /**
   * Authenticate using Kubernetes service account
   * @param {string} role - Vault role name
   * @param {string} jwt - Kubernetes service account JWT
   * @returns {Promise<Object>} - Auth response
   */
  async loginKubernetes(role, jwt = null) {
    // Read JWT from mounted service account if not provided
    const serviceAccountJwt = jwt || require('fs')
      .readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/token', 'utf8');

    const result = await this.client.kubernetesLogin({
      role,
      jwt: serviceAccountJwt
    });

    this.client.token = result.auth.client_token;

    console.log('Kubernetes authentication successful');

    return {
      token: result.auth.client_token,
      leaseDuration: result.auth.lease_duration
    };
  }

  /**
   * Setup automatic token renewal
   * @param {number} leaseDuration - Token TTL in seconds
   */
  setupTokenRenewal(leaseDuration) {
    // Renew at 75% of lease duration
    const renewalInterval = (leaseDuration * 0.75) * 1000;

    this.tokenRenewalInterval = setInterval(async () => {
      try {
        const result = await this.client.tokenRenewSelf();
        console.log(`Token renewed, new TTL: ${result.auth.lease_duration}s`);
      } catch (error) {
        console.error('Token renewal failed:', error.message);
        clearInterval(this.tokenRenewalInterval);
      }
    }, renewalInterval);

    console.log(`Token renewal scheduled every ${Math.floor(renewalInterval / 1000)}s`);
  }

  // ===========================================================================
  // KV Secrets Engine (v2)
  // ===========================================================================

  /**
   * Write a secret to KV v2 engine
   * @param {string} path - Secret path
   * @param {Object} data - Secret data
   * @param {string} mount - Mount point (default: secret)
   * @returns {Promise<Object>} - Write result
   */
  async writeSecret(path, data, mount = 'secret') {
    const result = await this.client.write(`${mount}/data/${path}`, {
      data: data
    });

    console.log(`Secret written to ${path}`);
    console.log(`  Version: ${result.data.version}`);

    return {
      version: result.data.version,
      createdTime: result.data.created_time
    };
  }

  /**
   * Read a secret from KV v2 engine
   * @param {string} path - Secret path
   * @param {number} version - Optional version number
   * @param {string} mount - Mount point
   * @returns {Promise<Object>} - Secret data
   */
  async readSecret(path, version = null, mount = 'secret') {
    let fullPath = `${mount}/data/${path}`;
    if (version) {
      fullPath += `?version=${version}`;
    }

    const result = await this.client.read(fullPath);

    return {
      data: result.data.data,
      metadata: result.data.metadata
    };
  }

  /**
   * Delete a secret (soft delete)
   * @param {string} path - Secret path
   * @param {number[]} versions - Versions to delete
   * @param {string} mount - Mount point
   */
  async deleteSecret(path, versions = null, mount = 'secret') {
    if (versions) {
      await this.client.write(`${mount}/delete/${path}`, { versions });
    } else {
      await this.client.delete(`${mount}/data/${path}`);
    }

    console.log(`Secret ${path} deleted`);
  }

  /**
   * Undelete a secret version
   * @param {string} path - Secret path
   * @param {number[]} versions - Versions to undelete
   * @param {string} mount - Mount point
   */
  async undeleteSecret(path, versions, mount = 'secret') {
    await this.client.write(`${mount}/undelete/${path}`, { versions });
    console.log(`Secret ${path} versions ${versions.join(', ')} restored`);
  }

  // ===========================================================================
  // Dynamic Secrets (Database)
  // ===========================================================================

  /**
   * Generate dynamic database credentials
   * @param {string} role - Database role name
   * @returns {Promise<Object>} - Temporary credentials
   */
  async getDatabaseCredentials(role) {
    const result = await this.client.read(`database/creds/${role}`);

    console.log(`Dynamic database credentials generated`);
    console.log(`  Username: ${result.data.username}`);
    console.log(`  TTL: ${result.lease_duration}s`);
    console.log(`  Lease ID: ${result.lease_id}`);

    return {
      username: result.data.username,
      password: result.data.password,
      leaseId: result.lease_id,
      leaseDuration: result.lease_duration
    };
  }

  /**
   * Revoke a lease (e.g., database credentials)
   * @param {string} leaseId - Lease ID to revoke
   */
  async revokeLease(leaseId) {
    await this.client.write('sys/leases/revoke', {
      lease_id: leaseId
    });

    console.log(`Lease ${leaseId} revoked`);
  }

  /**
   * Renew a lease
   * @param {string} leaseId - Lease ID to renew
   * @param {number} increment - TTL increment in seconds
   * @returns {Promise<Object>} - Renewal result
   */
  async renewLease(leaseId, increment = 3600) {
    const result = await this.client.write('sys/leases/renew', {
      lease_id: leaseId,
      increment: increment
    });

    return {
      leaseId: result.lease_id,
      leaseDuration: result.lease_duration
    };
  }

  // ===========================================================================
  // Transit Secrets Engine (Encryption-as-a-Service)
  // ===========================================================================

  /**
   * Create an encryption key in Transit engine
   * @param {string} keyName - Key name
   * @param {Object} options - Key options
   */
  async createTransitKey(keyName, options = {}) {
    const {
      type = 'aes256-gcm96',
      exportable = false,
      allowPlaintextBackup = false
    } = options;

    await this.client.write(`transit/keys/${keyName}`, {
      type,
      exportable,
      allow_plaintext_backup: allowPlaintextBackup
    });

    console.log(`Transit key '${keyName}' created (${type})`);
  }

  /**
   * Encrypt data using Transit engine
   * @param {string} keyName - Key to use
   * @param {string} plaintext - Data to encrypt (base64 encoded)
   * @returns {Promise<string>} - Ciphertext
   */
  async transitEncrypt(keyName, plaintext) {
    // Convert to base64 if not already
    const base64Plaintext = Buffer.from(plaintext).toString('base64');

    const result = await this.client.write(`transit/encrypt/${keyName}`, {
      plaintext: base64Plaintext
    });

    return result.data.ciphertext;
  }

  /**
   * Decrypt data using Transit engine
   * @param {string} keyName - Key to use
   * @param {string} ciphertext - Data to decrypt
   * @returns {Promise<string>} - Plaintext
   */
  async transitDecrypt(keyName, ciphertext) {
    const result = await this.client.write(`transit/decrypt/${keyName}`, {
      ciphertext: ciphertext
    });

    return Buffer.from(result.data.plaintext, 'base64').toString('utf8');
  }

  /**
   * Sign data using Transit engine
   * @param {string} keyName - Signing key
   * @param {string} input - Data to sign (base64 encoded)
   * @param {string} hashAlgorithm - Hash algorithm
   * @returns {Promise<string>} - Signature
   */
  async transitSign(keyName, input, hashAlgorithm = 'sha2-256') {
    const base64Input = Buffer.from(input).toString('base64');

    const result = await this.client.write(`transit/sign/${keyName}`, {
      input: base64Input,
      hash_algorithm: hashAlgorithm
    });

    return result.data.signature;
  }

  /**
   * Verify signature using Transit engine
   * @param {string} keyName - Signing key
   * @param {string} input - Original data
   * @param {string} signature - Signature to verify
   * @returns {Promise<boolean>} - Verification result
   */
  async transitVerify(keyName, input, signature) {
    const base64Input = Buffer.from(input).toString('base64');

    const result = await this.client.write(`transit/verify/${keyName}`, {
      input: base64Input,
      signature: signature
    });

    return result.data.valid;
  }

  /**
   * Rotate encryption key
   * @param {string} keyName - Key to rotate
   */
  async rotateTransitKey(keyName) {
    await this.client.write(`transit/keys/${keyName}/rotate`);
    console.log(`Transit key '${keyName}' rotated`);
  }

  // ===========================================================================
  // PKI Secrets Engine
  // ===========================================================================

  /**
   * Generate a certificate from PKI engine
   * @param {string} role - PKI role name
   * @param {string} commonName - Certificate common name
   * @param {Object} options - Certificate options
   * @returns {Promise<Object>} - Certificate and key
   */
  async issueCertificate(role, commonName, options = {}) {
    const {
      ttl = '720h',
      altNames = [],
      ipSans = []
    } = options;

    const result = await this.client.write(`pki/issue/${role}`, {
      common_name: commonName,
      ttl,
      alt_names: altNames.join(','),
      ip_sans: ipSans.join(',')
    });

    console.log(`Certificate issued for ${commonName}`);
    console.log(`  Serial: ${result.data.serial_number}`);
    console.log(`  Expires: ${result.data.expiration}`);

    return {
      certificate: result.data.certificate,
      privateKey: result.data.private_key,
      issuingCa: result.data.issuing_ca,
      caChain: result.data.ca_chain,
      serialNumber: result.data.serial_number,
      expiration: result.data.expiration
    };
  }

  // ===========================================================================
  // Cleanup
  // ===========================================================================

  /**
   * Cleanup resources and revoke token
   */
  async cleanup() {
    if (this.tokenRenewalInterval) {
      clearInterval(this.tokenRenewalInterval);
    }

    try {
      await this.client.tokenRevokeSelf();
      console.log('Token revoked');
    } catch (error) {
      console.error('Token revocation failed:', error.message);
    }
  }
}

// =============================================================================
// Export
// =============================================================================

module.exports = { HashiCorpVaultManager };

// =============================================================================
// Demo
// =============================================================================

if (require.main === module) {
  async function demo() {
    console.log('=== HashiCorp Vault Demo ===\n');

    // Note: This demo requires a running Vault instance
    // Start with: vault server -dev

    if (!process.env.VAULT_TOKEN) {
      console.log('Set VAULT_TOKEN environment variable to run demo');
      console.log('Example: export VAULT_TOKEN=hvs.xxxxx');
      return;
    }

    const manager = new HashiCorpVaultManager();

    try {
      // Write and read secrets
      await manager.writeSecret('myapp/config', {
        database_url: 'postgres://localhost:5432/mydb',
        api_key: 'sk-secret-key-12345'
      });

      const secret = await manager.readSecret('myapp/config');
      console.log('\nRetrieved secret:', secret.data);

      // Transit encryption
      console.log('\n--- Transit Encryption ---');
      await manager.createTransitKey('myapp-key');

      const ciphertext = await manager.transitEncrypt('myapp-key', 'sensitive data');
      console.log('Encrypted:', ciphertext.substring(0, 50) + '...');

      const plaintext = await manager.transitDecrypt('myapp-key', ciphertext);
      console.log('Decrypted:', plaintext);

    } catch (error) {
      console.error('Demo error:', error.message);
    } finally {
      // await manager.cleanup();
    }
  }

  demo();
}
