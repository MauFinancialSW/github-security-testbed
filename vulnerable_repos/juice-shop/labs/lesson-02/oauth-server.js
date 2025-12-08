/**
 * OAuth 2.0 Authorization Server with PKCE
 *
 * This implements OAuth 2.0 Authorization Code Flow with PKCE (Proof Key for Code Exchange),
 * the recommended flow for modern applications including SPAs and mobile apps.
 *
 * Security Decisions Explained:
 *
 * 1. PKCE (RFC 7636):
 *    - Prevents authorization code interception attacks
 *    - Client generates code_verifier (43-128 character random string)
 *    - Client sends code_challenge = SHA256(code_verifier) with auth request
 *    - Server validates code_verifier matches code_challenge on token exchange
 *    - Mitigates attacks even if authorization code is intercepted
 *
 * 2. Redirect URI Validation:
 *    - Whitelist of allowed redirect URIs prevents open redirect attacks
 *    - Exact match required (no wildcards) per OAuth 2.0 Security BCP
 *    - Prevents authorization code leakage to attacker domains
 *
 * 3. Authorization Code Expiration:
 *    - 10-minute lifetime limits window for code interception
 *    - OAuth 2.0 Security BCP recommends <10 minutes
 *    - Codes are single-use only (consumed after token exchange)
 *
 * 4. Single-Use Authorization Codes:
 *    - Code is invalidated immediately after token exchange
 *    - Prevents replay attacks if code is intercepted
 *    - Server tracks used codes to reject replays
 *
 * 5. State Parameter:
 *    - Client-generated random value included in auth request
 *    - Returned with authorization code
 *    - Client validates state matches to prevent CSRF attacks
 *
 * 6. JWT Token Generation (RS256):
 *    - Asymmetric signing with RSA private key
 *    - Public key can verify tokens without shared secret
 *    - HS256 (symmetric) would require sharing secret with all services
 *    - Short expiration (15 minutes) limits window if token is compromised
 *
 * References:
 * - RFC 6749 (OAuth 2.0)
 * - RFC 7636 (PKCE)
 * - OAuth 2.0 Security Best Current Practice (draft-ietf-oauth-security-topics)
 * - OWASP OAuth 2.0 Cheat Sheet
 */

const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// Configuration
const PORT = 4000;
const AUTHORIZATION_CODE_TTL = 10 * 60 * 1000; // 10 minutes in milliseconds
const ACCESS_TOKEN_TTL = 15 * 60; // 15 minutes in seconds
const ISSUER = 'https://auth.example.com';
const AUDIENCE = 'https://api.example.com';

// Redirect URI whitelist (security-critical: prevents open redirect attacks)
// In production, load from secure configuration
const ALLOWED_REDIRECT_URIS = [
  'http://localhost:3000/callback',
  'http://localhost:8080/callback',
  'https://app.example.com/callback'
];

// In-memory storage (use Redis/database in production)
const authorizationCodes = new Map(); // code -> { clientId, redirectUri, codeChallenge, expiresAt, used }
const usedCodes = new Set(); // Track used codes to prevent replay

/**
 * RSA key pair for JWT signing (RS256)
 *
 * Security Note: In production:
 * - Store private key in Azure Key Vault / AWS KMS / HashiCorp Vault
 * - Use key rotation with multiple key versions
 * - Never commit private keys to source control
 * - Use environment variables or secrets management
 */
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
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

console.log('=== OAuth 2.0 Authorization Server (PKCE) ===\n');
console.log('Public Key for JWT Verification:');
console.log(publicKey);

/**
 * Validates redirect URI against whitelist
 *
 * Security: Prevents open redirect attacks by requiring exact match
 * OAuth 2.0 Security BCP: No wildcards, no substring matching
 *
 * @param {string} redirectUri - Redirect URI from client
 * @returns {boolean} True if URI is whitelisted
 */
function isValidRedirectUri(redirectUri) {
  return ALLOWED_REDIRECT_URIS.includes(redirectUri);
}

/**
 * Validates PKCE code_challenge format
 *
 * Requirements per RFC 7636:
 * - Base64-URL encoded SHA256 hash
 * - 43 characters (32 bytes base64-url encoded)
 *
 * @param {string} codeChallenge - code_challenge from client
 * @returns {boolean} True if valid format
 */
function isValidCodeChallenge(codeChallenge) {
  // Base64-URL format: [A-Za-z0-9_-]{43}
  return /^[A-Za-z0-9_-]{43}$/.test(codeChallenge);
}

/**
 * Validates PKCE code_verifier against stored code_challenge
 *
 * Per RFC 7636:
 * - code_challenge = BASE64URL(SHA256(code_verifier))
 * - code_verifier must be 43-128 characters [A-Za-z0-9._~-]
 *
 * @param {string} codeVerifier - code_verifier from client
 * @param {string} codeChallenge - stored code_challenge
 * @returns {boolean} True if verifier matches challenge
 */
function verifyPkceChallenge(codeVerifier, codeChallenge) {
  // Validate code_verifier format (43-128 characters)
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(codeVerifier)) {
    return false;
  }

  // Compute SHA256 hash and base64-url encode
  const hash = crypto.createHash('sha256').update(codeVerifier).digest();
  const computedChallenge = hash.toString('base64url'); // base64url removes padding

  return computedChallenge === codeChallenge;
}

/**
 * Generates cryptographically secure authorization code
 *
 * @returns {string} Random authorization code (32 bytes, base64-url encoded)
 */
function generateAuthorizationCode() {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * Generates JWT access token with RS256 signing
 *
 * Security features:
 * - RS256 (asymmetric) allows public key verification
 * - Short expiration (15 min) limits exposure if compromised
 * - Standard claims (iss, sub, aud, exp, iat) per RFC 7519
 *
 * @param {string} userId - User identifier (subject)
 * @param {string} clientId - Client identifier
 * @param {Array} scopes - Granted scopes
 * @returns {string} JWT access token
 */
function generateAccessToken(userId, clientId, scopes = []) {
  const now = Math.floor(Date.now() / 1000);

  const payload = {
    iss: ISSUER,                    // Issuer (authorization server)
    sub: userId,                     // Subject (user identifier)
    aud: AUDIENCE,                   // Audience (resource server)
    exp: now + ACCESS_TOKEN_TTL,     // Expiration (15 minutes)
    iat: now,                        // Issued at
    client_id: clientId,             // Client that requested token
    scope: scopes.join(' ')          // Granted scopes (space-separated)
  };

  return jwt.sign(payload, privateKey, { algorithm: 'RS256' });
}

// Express app setup
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

/**
 * GET /authorize - Authorization endpoint
 *
 * OAuth 2.0 authorization request with PKCE
 *
 * Required parameters:
 * - response_type: Must be "code" for authorization code flow
 * - client_id: Client identifier
 * - redirect_uri: Must be whitelisted
 * - code_challenge: SHA256 hash of code_verifier (PKCE)
 * - code_challenge_method: Must be "S256" (SHA256)
 * - state: Client-generated random value (CSRF protection)
 *
 * Security checks:
 * 1. Validate redirect_uri against whitelist
 * 2. Validate code_challenge format
 * 3. Validate code_challenge_method is S256 (plain is insecure)
 */
app.get('/authorize', (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
    state,
    scope
  } = req.query;

  console.log('\n=== Authorization Request ===');
  console.log('Client ID:', client_id);
  console.log('Redirect URI:', redirect_uri);
  console.log('Code Challenge:', code_challenge);
  console.log('State:', state);

  // Validation 1: Check response_type
  if (response_type !== 'code') {
    return res.status(400).json({
      error: 'unsupported_response_type',
      error_description: 'Only authorization code flow is supported'
    });
  }

  // Validation 2: Validate redirect_uri against whitelist
  if (!isValidRedirectUri(redirect_uri)) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'redirect_uri is not whitelisted'
    });
  }

  // Validation 3: Validate code_challenge_method
  if (code_challenge_method !== 'S256') {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'code_challenge_method must be S256 (plain is insecure)'
    });
  }

  // Validation 4: Validate code_challenge format
  if (!isValidCodeChallenge(code_challenge)) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'code_challenge must be base64url-encoded SHA256 hash'
    });
  }

  // Validation 5: Require state parameter (CSRF protection)
  if (!state || state.length < 16) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'state parameter required (min 16 characters for CSRF protection)'
    });
  }

  // Generate authorization code
  const code = generateAuthorizationCode();
  const expiresAt = Date.now() + AUTHORIZATION_CODE_TTL;

  // Store authorization code with PKCE challenge
  authorizationCodes.set(code, {
    clientId: client_id,
    redirectUri: redirect_uri,
    codeChallenge: code_challenge,
    expiresAt: expiresAt,
    used: false,
    scope: scope || 'read',
    userId: 'user123' // In production, this would be authenticated user ID
  });

  console.log('Generated Code:', code);
  console.log('Expires At:', new Date(expiresAt).toISOString());

  // Redirect back to client with authorization code and state
  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', code);
  redirectUrl.searchParams.set('state', state);

  console.log('Redirecting to:', redirectUrl.toString());

  res.redirect(redirectUrl.toString());
});

/**
 * POST /token - Token endpoint
 *
 * Exchanges authorization code for access token
 *
 * Required parameters:
 * - grant_type: Must be "authorization_code"
 * - code: Authorization code from /authorize
 * - redirect_uri: Must match original request
 * - code_verifier: PKCE verifier (proves client has secret)
 * - client_id: Client identifier
 *
 * Security checks:
 * 1. Validate authorization code exists and not expired
 * 2. Validate code not already used (single-use)
 * 3. Validate redirect_uri matches original request
 * 4. Validate PKCE code_verifier matches code_challenge
 * 5. Mark code as used immediately
 */
app.post('/token', (req, res) => {
  const {
    grant_type,
    code,
    redirect_uri,
    code_verifier,
    client_id
  } = req.body;

  console.log('\n=== Token Request ===');
  console.log('Grant Type:', grant_type);
  console.log('Code:', code);
  console.log('Code Verifier:', code_verifier);

  // Validation 1: Check grant_type
  if (grant_type !== 'authorization_code') {
    return res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: 'Only authorization_code grant is supported'
    });
  }

  // Validation 2: Check authorization code exists
  const authCode = authorizationCodes.get(code);
  if (!authCode) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Authorization code is invalid'
    });
  }

  // Validation 3: Check code not expired
  if (Date.now() > authCode.expiresAt) {
    authorizationCodes.delete(code);
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Authorization code has expired'
    });
  }

  // Validation 4: Check code not already used (single-use enforcement)
  if (authCode.used || usedCodes.has(code)) {
    authorizationCodes.delete(code);
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Authorization code has already been used'
    });
  }

  // Validation 5: Validate client_id matches
  if (authCode.clientId !== client_id) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'client_id does not match'
    });
  }

  // Validation 6: Validate redirect_uri matches original request
  if (authCode.redirectUri !== redirect_uri) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'redirect_uri does not match authorization request'
    });
  }

  // Validation 7: Verify PKCE code_verifier matches code_challenge
  if (!verifyPkceChallenge(code_verifier, authCode.codeChallenge)) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'code_verifier does not match code_challenge (PKCE validation failed)'
    });
  }

  console.log('✓ PKCE validation successful');

  // Mark code as used immediately (single-use enforcement)
  authCode.used = true;
  usedCodes.add(code);
  authorizationCodes.delete(code);

  // Generate access token
  const scopes = authCode.scope.split(' ');
  const accessToken = generateAccessToken(authCode.userId, client_id, scopes);

  console.log('Generated Access Token');
  console.log('User ID:', authCode.userId);
  console.log('Scopes:', scopes);

  // Return tokens
  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_TTL,
    scope: authCode.scope
  });
});

/**
 * GET /.well-known/jwks.json - JSON Web Key Set endpoint
 *
 * Publishes public key for JWT verification
 * Resource servers use this to verify access tokens without shared secret
 */
app.get('/.well-known/jwks.json', (req, res) => {
  res.json({
    keys: [
      {
        kty: 'RSA',
        use: 'sig',
        alg: 'RS256',
        n: publicKey.split('\n').slice(1, -2).join(''), // Extract base64 modulus
        kid: 'key-1'
      }
    ]
  });
});

/**
 * GET /verify - Token verification endpoint (for demo purposes)
 *
 * In production, resource servers would verify tokens locally using public key
 */
app.get('/verify', (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }

  const token = authHeader.substring(7);

  try {
    const decoded = jwt.verify(token, publicKey, {
      algorithms: ['RS256'],
      issuer: ISSUER,
      audience: AUDIENCE
    });

    res.json({
      valid: true,
      claims: decoded
    });
  } catch (error) {
    res.status(401).json({
      valid: false,
      error: error.message
    });
  }
});

// Start server
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n✓ OAuth 2.0 Server running on http://localhost:${PORT}`);
    console.log('\nEndpoints:');
    console.log(`  GET  /authorize - Authorization endpoint (with PKCE)`);
    console.log(`  POST /token - Token exchange endpoint`);
    console.log(`  GET  /verify - Token verification endpoint`);
    console.log(`  GET  /.well-known/jwks.json - Public key endpoint`);
    console.log('\nSecurity Features:');
    console.log('  ✓ PKCE (Proof Key for Code Exchange)');
    console.log('  ✓ Redirect URI whitelist validation');
    console.log('  ✓ 10-minute authorization code expiration');
    console.log('  ✓ Single-use authorization codes');
    console.log('  ✓ State parameter handling (CSRF protection)');
    console.log('  ✓ RS256 JWT signing (asymmetric)');
    console.log('  ✓ 15-minute access token expiration\n');
  });
}

module.exports = {
  app,
  generateAccessToken,
  verifyPkceChallenge,
  isValidRedirectUri,
  ALLOWED_REDIRECT_URIS
};
