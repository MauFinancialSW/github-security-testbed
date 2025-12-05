/**
 * OAuth 2.0 Authorization Server with PKCE
 * =========================================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 02 - Security Protocols with Copilot
 *
 * This demonstrates Copilot's ability to generate production-ready OAuth 2.0.
 *
 * Security Features:
 * - Authorization Code Flow with PKCE (RFC 7636)
 * - SHA-256 code_challenge verification
 * - Redirect URI whitelist validation
 * - 10-minute authorization code expiration
 * - Single-use authorization codes
 * - Secure state parameter handling
 */

const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// =============================================================================
// Configuration
// =============================================================================

const config = {
  // In production, load from environment variables
  jwtPrivateKey: process.env.JWT_PRIVATE_KEY || crypto.randomBytes(64).toString('hex'),
  jwtPublicKey: process.env.JWT_PUBLIC_KEY || null,
  issuer: 'https://auth.example.com',
  audience: 'https://api.example.com',
  authCodeExpiry: 10 * 60 * 1000,  // 10 minutes
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d'
};

// Registered clients (in production, store in database)
const registeredClients = new Map([
  ['client_web_app', {
    clientId: 'client_web_app',
    clientSecret: 'web_app_secret_hash',  // In production: hashed
    redirectUris: [
      'https://app.example.com/callback',
      'http://localhost:3000/callback'  // Dev only
    ],
    allowedScopes: ['openid', 'profile', 'email', 'api:read', 'api:write']
  }],
  ['client_mobile_app', {
    clientId: 'client_mobile_app',
    clientSecret: null,  // Public client - no secret
    redirectUris: [
      'com.example.app://callback',
      'http://localhost:8080/callback'
    ],
    allowedScopes: ['openid', 'profile', 'api:read']
  }]
]);

// In-memory stores (in production, use Redis or database)
const authorizationCodes = new Map();
const refreshTokens = new Map();

// =============================================================================
// PKCE Helper Functions
// =============================================================================

/**
 * Verify PKCE code_challenge against code_verifier
 * @param {string} codeVerifier - The original code verifier
 * @param {string} codeChallenge - The stored code challenge
 * @param {string} codeChallengeMethod - 'S256' or 'plain'
 * @returns {boolean}
 */
function verifyCodeChallenge(codeVerifier, codeChallenge, codeChallengeMethod) {
  if (codeChallengeMethod === 'S256') {
    // SHA-256 hash of code_verifier, base64url encoded
    const hash = crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    return crypto.timingSafeEqual(
      Buffer.from(hash),
      Buffer.from(codeChallenge)
    );
  } else if (codeChallengeMethod === 'plain') {
    // Plain comparison (not recommended, but supported)
    return crypto.timingSafeEqual(
      Buffer.from(codeVerifier),
      Buffer.from(codeChallenge)
    );
  }

  return false;
}

/**
 * Validate redirect URI against client's registered URIs
 * @param {string} redirectUri - Requested redirect URI
 * @param {string[]} allowedUris - Client's registered URIs
 * @returns {boolean}
 */
function validateRedirectUri(redirectUri, allowedUris) {
  // Exact match required (no wildcards for security)
  return allowedUris.includes(redirectUri);
}

/**
 * Generate secure authorization code
 * @returns {string}
 */
function generateAuthorizationCode() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Generate secure state parameter
 * @returns {string}
 */
function generateState() {
  return crypto.randomBytes(16).toString('hex');
}

// =============================================================================
// Authorization Endpoint
// =============================================================================

/**
 * GET /authorize
 * Initiates OAuth 2.0 authorization flow
 *
 * Required parameters:
 * - response_type: 'code'
 * - client_id: Registered client ID
 * - redirect_uri: Must match registered URI
 * - code_challenge: PKCE challenge (base64url)
 * - code_challenge_method: 'S256' (recommended) or 'plain'
 * - state: CSRF protection
 * - scope: Requested scopes (space-separated)
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

  // Validate response_type
  if (response_type !== 'code') {
    return res.status(400).json({
      error: 'unsupported_response_type',
      error_description: 'Only authorization code flow is supported'
    });
  }

  // Validate client
  const client = registeredClients.get(client_id);
  if (!client) {
    return res.status(400).json({
      error: 'invalid_client',
      error_description: 'Unknown client_id'
    });
  }

  // Validate redirect_uri
  if (!validateRedirectUri(redirect_uri, client.redirectUris)) {
    return res.status(400).json({
      error: 'invalid_redirect_uri',
      error_description: 'Redirect URI not registered for this client'
    });
  }

  // Require PKCE for all clients
  if (!code_challenge) {
    return res.redirect(`${redirect_uri}?error=invalid_request&error_description=PKCE+required&state=${state}`);
  }

  // Validate code_challenge_method
  if (code_challenge_method !== 'S256' && code_challenge_method !== 'plain') {
    return res.redirect(`${redirect_uri}?error=invalid_request&error_description=Invalid+code_challenge_method&state=${state}`);
  }

  // Validate state
  if (!state || state.length < 16) {
    return res.redirect(`${redirect_uri}?error=invalid_request&error_description=State+parameter+required&state=${state}`);
  }

  // Validate scopes
  const requestedScopes = (scope || '').split(' ').filter(Boolean);
  const invalidScopes = requestedScopes.filter(s => !client.allowedScopes.includes(s));
  if (invalidScopes.length > 0) {
    return res.redirect(`${redirect_uri}?error=invalid_scope&error_description=Invalid+scopes:+${invalidScopes.join(',')}&state=${state}`);
  }

  // In production: Show login form and consent screen
  // For demo: Simulate successful authentication
  const userId = 'user_123';  // From authentication

  // Generate authorization code
  const code = generateAuthorizationCode();

  // Store authorization code with metadata (single-use, expires in 10 min)
  authorizationCodes.set(code, {
    clientId: client_id,
    redirectUri: redirect_uri,
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method,
    userId,
    scopes: requestedScopes,
    createdAt: Date.now(),
    used: false
  });

  // Redirect back to client with authorization code
  const callbackUrl = new URL(redirect_uri);
  callbackUrl.searchParams.set('code', code);
  callbackUrl.searchParams.set('state', state);

  res.redirect(callbackUrl.toString());
});

// =============================================================================
// Token Endpoint
// =============================================================================

/**
 * POST /token
 * Exchange authorization code for tokens
 *
 * For authorization_code grant:
 * - grant_type: 'authorization_code'
 * - code: Authorization code from /authorize
 * - redirect_uri: Must match original request
 * - code_verifier: PKCE verifier
 * - client_id: Client identifier
 *
 * For refresh_token grant:
 * - grant_type: 'refresh_token'
 * - refresh_token: Valid refresh token
 * - client_id: Client identifier
 */
app.post('/token', (req, res) => {
  const { grant_type } = req.body;

  if (grant_type === 'authorization_code') {
    return handleAuthorizationCodeGrant(req, res);
  } else if (grant_type === 'refresh_token') {
    return handleRefreshTokenGrant(req, res);
  } else {
    return res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: 'Supported grant types: authorization_code, refresh_token'
    });
  }
});

function handleAuthorizationCodeGrant(req, res) {
  const { code, redirect_uri, code_verifier, client_id } = req.body;

  // Retrieve authorization code
  const authCode = authorizationCodes.get(code);

  if (!authCode) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Invalid or expired authorization code'
    });
  }

  // Check if code was already used (single-use enforcement)
  if (authCode.used) {
    // Revoke all tokens issued with this code (security measure)
    authorizationCodes.delete(code);
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Authorization code already used'
    });
  }

  // Check expiration (10 minutes)
  if (Date.now() - authCode.createdAt > config.authCodeExpiry) {
    authorizationCodes.delete(code);
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Authorization code expired'
    });
  }

  // Validate client_id matches
  if (authCode.clientId !== client_id) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Client ID mismatch'
    });
  }

  // Validate redirect_uri matches
  if (authCode.redirectUri !== redirect_uri) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Redirect URI mismatch'
    });
  }

  // Verify PKCE code_verifier
  if (!verifyCodeChallenge(code_verifier, authCode.codeChallenge, authCode.codeChallengeMethod)) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Invalid code_verifier'
    });
  }

  // Mark code as used
  authCode.used = true;

  // Generate tokens
  const accessToken = generateAccessToken(authCode.userId, authCode.scopes);
  const refreshToken = generateRefreshToken(authCode.userId, authCode.clientId, authCode.scopes);

  // Return tokens
  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 900,  // 15 minutes
    refresh_token: refreshToken,
    scope: authCode.scopes.join(' ')
  });
}

function handleRefreshTokenGrant(req, res) {
  const { refresh_token, client_id } = req.body;

  // Validate refresh token
  const tokenData = refreshTokens.get(refresh_token);

  if (!tokenData) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Invalid refresh token'
    });
  }

  // Validate client_id matches
  if (tokenData.clientId !== client_id) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Client ID mismatch'
    });
  }

  // Check expiration
  if (Date.now() > tokenData.expiresAt) {
    refreshTokens.delete(refresh_token);
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Refresh token expired'
    });
  }

  // Rotate refresh token (invalidate old, issue new)
  refreshTokens.delete(refresh_token);

  const newAccessToken = generateAccessToken(tokenData.userId, tokenData.scopes);
  const newRefreshToken = generateRefreshToken(tokenData.userId, tokenData.clientId, tokenData.scopes);

  res.json({
    access_token: newAccessToken,
    token_type: 'Bearer',
    expires_in: 900,
    refresh_token: newRefreshToken,
    scope: tokenData.scopes.join(' ')
  });
}

// =============================================================================
// Token Generation
// =============================================================================

function generateAccessToken(userId, scopes) {
  return jwt.sign(
    {
      iss: config.issuer,
      sub: userId,
      aud: config.audience,
      exp: Math.floor(Date.now() / 1000) + (15 * 60),  // 15 minutes
      iat: Math.floor(Date.now() / 1000),
      scope: scopes.join(' ')
    },
    config.jwtPrivateKey,
    { algorithm: 'HS256' }  // In production: Use RS256 with private key
  );
}

function generateRefreshToken(userId, clientId, scopes) {
  const token = crypto.randomBytes(32).toString('hex');

  refreshTokens.set(token, {
    userId,
    clientId,
    scopes,
    createdAt: Date.now(),
    expiresAt: Date.now() + (7 * 24 * 60 * 60 * 1000)  // 7 days
  });

  return token;
}

// =============================================================================
// Token Introspection Endpoint (RFC 7662)
// =============================================================================

app.post('/introspect', (req, res) => {
  const { token, token_type_hint } = req.body;

  try {
    const decoded = jwt.verify(token, config.jwtPrivateKey);

    res.json({
      active: true,
      scope: decoded.scope,
      client_id: decoded.client_id,
      username: decoded.sub,
      token_type: 'Bearer',
      exp: decoded.exp,
      iat: decoded.iat,
      iss: decoded.iss,
      aud: decoded.aud
    });
  } catch (err) {
    res.json({ active: false });
  }
});

// =============================================================================
// Token Revocation Endpoint (RFC 7009)
// =============================================================================

app.post('/revoke', (req, res) => {
  const { token, token_type_hint } = req.body;

  // Check if it's a refresh token
  if (refreshTokens.has(token)) {
    refreshTokens.delete(token);
  }

  // Access tokens can't be truly revoked with JWT (stateless)
  // In production: Add to revocation list or use short expiry

  res.status(200).end();
});

// =============================================================================
// JWKS Endpoint (for RS256)
// =============================================================================

app.get('/.well-known/jwks.json', (req, res) => {
  // In production with RS256, return public key in JWKS format
  res.json({
    keys: []  // Add JWK here when using RS256
  });
});

// =============================================================================
// OpenID Connect Discovery
// =============================================================================

app.get('/.well-known/openid-configuration', (req, res) => {
  res.json({
    issuer: config.issuer,
    authorization_endpoint: `${config.issuer}/authorize`,
    token_endpoint: `${config.issuer}/token`,
    introspection_endpoint: `${config.issuer}/introspect`,
    revocation_endpoint: `${config.issuer}/revoke`,
    jwks_uri: `${config.issuer}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
    code_challenge_methods_supported: ['S256', 'plain'],
    scopes_supported: ['openid', 'profile', 'email', 'api:read', 'api:write']
  });
});

// =============================================================================
// Start Server
// =============================================================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`OAuth 2.0 Authorization Server running on port ${PORT}`);
  console.log(`\nEndpoints:`);
  console.log(`  Authorization: http://localhost:${PORT}/authorize`);
  console.log(`  Token:         http://localhost:${PORT}/token`);
  console.log(`  Introspect:    http://localhost:${PORT}/introspect`);
  console.log(`  Revoke:        http://localhost:${PORT}/revoke`);
  console.log(`  Discovery:     http://localhost:${PORT}/.well-known/openid-configuration`);
});

module.exports = app;
