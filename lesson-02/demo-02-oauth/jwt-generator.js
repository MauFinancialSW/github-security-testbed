/**
 * JWT Token Generator with Secure Defaults
 * =========================================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 02 - Security Protocols with Copilot
 *
 * Copilot Prompt Used:
 * "Generate JWT token with proper claims and RS256 signing"
 *
 * Security Features:
 * - All required claims present (iss, sub, aud, exp, iat)
 * - RS256 algorithm (asymmetric, secure)
 * - Short expiration (15 min for access tokens)
 * - Proper timestamp handling
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// =============================================================================
// Key Management
// =============================================================================

/**
 * Generate RSA key pair for JWT signing
 * @returns {Object} - { publicKey, privateKey }
 */
function generateKeyPair() {
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

  return { publicKey, privateKey };
}

/**
 * Load or generate key pair
 * @param {string} keyDir - Directory for key storage
 * @returns {Object} - { publicKey, privateKey }
 */
function loadOrGenerateKeys(keyDir = './keys') {
  const privateKeyPath = path.join(keyDir, 'private.key');
  const publicKeyPath = path.join(keyDir, 'public.key');

  try {
    const privateKey = fs.readFileSync(privateKeyPath, 'utf8');
    const publicKey = fs.readFileSync(publicKeyPath, 'utf8');
    return { publicKey, privateKey };
  } catch (err) {
    // Keys don't exist, generate new pair
    console.log('Generating new RSA key pair...');
    const { publicKey, privateKey } = generateKeyPair();

    // Create directory if needed
    if (!fs.existsSync(keyDir)) {
      fs.mkdirSync(keyDir, { recursive: true });
    }

    fs.writeFileSync(privateKeyPath, privateKey, { mode: 0o600 });
    fs.writeFileSync(publicKeyPath, publicKey);

    return { publicKey, privateKey };
  }
}

// =============================================================================
// JWT Generation
// =============================================================================

/**
 * Generate JWT access token with proper claims
 * @param {Object} user - User object with id, email, roles
 * @param {Object} options - Token options
 * @returns {string} - Signed JWT token
 */
function generateAccessToken(user, options = {}) {
  const {
    issuer = 'https://auth.example.com',
    audience = 'https://api.example.com',
    expiresIn = '15m',
    privateKey = loadOrGenerateKeys().privateKey
  } = options;

  const payload = {
    // Standard claims
    iss: issuer,                                    // Issuer
    sub: user.id,                                   // Subject (user ID)
    aud: audience,                                  // Audience
    exp: Math.floor(Date.now() / 1000) + parseExpiry(expiresIn),  // Expiration
    iat: Math.floor(Date.now() / 1000),             // Issued at
    nbf: Math.floor(Date.now() / 1000),             // Not before

    // Custom claims
    email: user.email,
    roles: user.roles || ['user'],
    permissions: user.permissions || [],

    // JWT ID for revocation tracking
    jti: crypto.randomUUID()
  };

  return jwt.sign(payload, privateKey, {
    algorithm: 'RS256'  // Asymmetric algorithm - secure
  });
}

/**
 * Generate JWT refresh token
 * @param {Object} user - User object
 * @param {Object} options - Token options
 * @returns {string} - Signed JWT refresh token
 */
function generateRefreshToken(user, options = {}) {
  const {
    issuer = 'https://auth.example.com',
    audience = 'https://auth.example.com/token',
    expiresIn = '7d',
    privateKey = loadOrGenerateKeys().privateKey
  } = options;

  const payload = {
    iss: issuer,
    sub: user.id,
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + parseExpiry(expiresIn),
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
    type: 'refresh'
  };

  return jwt.sign(payload, privateKey, {
    algorithm: 'RS256'
  });
}

/**
 * Generate ID token (OpenID Connect)
 * @param {Object} user - User object with profile info
 * @param {Object} options - Token options
 * @returns {string} - Signed ID token
 */
function generateIdToken(user, options = {}) {
  const {
    issuer = 'https://auth.example.com',
    audience,  // Client ID
    nonce,     // From authorization request
    privateKey = loadOrGenerateKeys().privateKey
  } = options;

  if (!audience) {
    throw new Error('audience (client_id) is required for ID token');
  }

  const payload = {
    iss: issuer,
    sub: user.id,
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + (60 * 60),  // 1 hour
    iat: Math.floor(Date.now() / 1000),
    auth_time: Math.floor(Date.now() / 1000),

    // OpenID Connect claims
    name: user.name,
    email: user.email,
    email_verified: user.emailVerified || false,
    picture: user.picture,

    // Security
    nonce: nonce,
    at_hash: options.accessToken ? generateAtHash(options.accessToken) : undefined
  };

  return jwt.sign(payload, privateKey, {
    algorithm: 'RS256'
  });
}

// =============================================================================
// JWT Verification
// =============================================================================

/**
 * Verify and decode JWT token
 * @param {string} token - JWT token to verify
 * @param {Object} options - Verification options
 * @returns {Object} - Decoded payload
 */
function verifyToken(token, options = {}) {
  const {
    issuer = 'https://auth.example.com',
    audience = 'https://api.example.com',
    publicKey = loadOrGenerateKeys().publicKey,
    algorithms = ['RS256']
  } = options;

  return jwt.verify(token, publicKey, {
    issuer,
    audience,
    algorithms,
    complete: false
  });
}

/**
 * Decode token without verification (for debugging)
 * WARNING: Do not use for authentication!
 * @param {string} token - JWT token
 * @returns {Object} - Decoded header and payload
 */
function decodeToken(token) {
  return jwt.decode(token, { complete: true });
}

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Parse expiry string to seconds
 * @param {string} expiry - e.g., '15m', '1h', '7d'
 * @returns {number} - Seconds
 */
function parseExpiry(expiry) {
  const match = expiry.match(/^(\d+)([smhd])$/);
  if (!match) throw new Error('Invalid expiry format');

  const value = parseInt(match[1]);
  const unit = match[2];

  const multipliers = {
    s: 1,
    m: 60,
    h: 60 * 60,
    d: 24 * 60 * 60
  };

  return value * multipliers[unit];
}

/**
 * Generate at_hash for ID token
 * @param {string} accessToken - Access token
 * @returns {string} - Base64url encoded hash
 */
function generateAtHash(accessToken) {
  const hash = crypto.createHash('sha256').update(accessToken).digest();
  const halfHash = hash.subarray(0, hash.length / 2);
  return halfHash.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Check if token is expired
 * @param {string} token - JWT token
 * @returns {boolean}
 */
function isTokenExpired(token) {
  try {
    const decoded = jwt.decode(token);
    return decoded.exp < Math.floor(Date.now() / 1000);
  } catch {
    return true;
  }
}

// =============================================================================
// Export
// =============================================================================

module.exports = {
  generateKeyPair,
  loadOrGenerateKeys,
  generateAccessToken,
  generateRefreshToken,
  generateIdToken,
  verifyToken,
  decodeToken,
  isTokenExpired
};

// =============================================================================
// Demo
// =============================================================================

if (require.main === module) {
  console.log('=== JWT Token Generator Demo ===\n');

  // Sample user
  const user = {
    id: 'user_123',
    email: 'alice@example.com',
    name: 'Alice Smith',
    roles: ['user', 'admin'],
    permissions: ['read:users', 'write:users']
  };

  // Generate keys
  const { publicKey, privateKey } = generateKeyPair();
  console.log('Generated RSA key pair\n');

  // Generate tokens
  const accessToken = generateAccessToken(user, { privateKey });
  console.log('Access Token:');
  console.log(accessToken);
  console.log();

  const refreshToken = generateRefreshToken(user, { privateKey });
  console.log('Refresh Token:');
  console.log(refreshToken);
  console.log();

  // Verify token
  const decoded = verifyToken(accessToken, { publicKey });
  console.log('Decoded Access Token:');
  console.log(JSON.stringify(decoded, null, 2));
  console.log();

  // Check expiration
  console.log('Token expired:', isTokenExpired(accessToken));
}
