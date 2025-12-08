const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Configuration
const PORT = 3000;
const AUTHORIZATION_CODE_EXPIRATION = 10 * 60 * 1000; // 10 minutes

// Whitelist of allowed redirect URIs
const ALLOWED_REDIRECT_URIS = [
  'http://localhost:3001/callback',
  'http://localhost:3001/oauth/callback',
  'https://example.com/callback'
];

// In-memory storage (use database in production)
const authorizationCodes = new Map();
const usedCodes = new Set();
const clients = new Map([
  ['client-123', {
    clientId: 'client-123',
    clientSecret: 'secret-456',
    allowedRedirectUris: ALLOWED_REDIRECT_URIS
  }]
]);

// Utility: Generate random string
function generateRandomString(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

// Utility: SHA-256 hash
function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('base64url');
}

// Utility: Validate redirect URI
function isValidRedirectUri(clientId, redirectUri) {
  const client = clients.get(clientId);
  if (!client) return false;
  return client.allowedRedirectUris.includes(redirectUri);
}

// Utility: Clean expired codes
function cleanExpiredCodes() {
  const now = Date.now();
  for (const [code, data] of authorizationCodes.entries()) {
    if (now > data.expiresAt) {
      authorizationCodes.delete(code);
      usedCodes.delete(code);
    }
  }
}

// Periodically clean expired codes
setInterval(cleanExpiredCodes, 60000); // Every minute

/**
 * Authorization Endpoint
 * GET /authorize
 *
 * Query Parameters:
 * - response_type: Must be "code"
 * - client_id: Client identifier
 * - redirect_uri: Callback URI (must be whitelisted)
 * - state: CSRF protection token
 * - code_challenge: SHA-256 hash of code_verifier (PKCE)
 * - code_challenge_method: Must be "S256"
 * - scope: Requested permissions (optional)
 */
app.get('/authorize', (req, res) => {
  try {
    const {
      response_type,
      client_id,
      redirect_uri,
      state,
      code_challenge,
      code_challenge_method,
      scope
    } = req.query;

    // Validate required parameters
    if (!response_type || response_type !== 'code') {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'response_type must be "code"'
      });
    }

    if (!client_id) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'client_id is required'
      });
    }

    if (!clients.has(client_id)) {
      return res.status(400).json({
        error: 'invalid_client',
        error_description: 'Unknown client'
      });
    }

    if (!redirect_uri) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'redirect_uri is required'
      });
    }

    // Validate redirect URI against whitelist
    if (!isValidRedirectUri(client_id, redirect_uri)) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'redirect_uri not allowed for this client'
      });
    }

    if (!state) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'state parameter is required for CSRF protection'
      });
    }

    // Validate PKCE parameters
    if (!code_challenge) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'code_challenge is required (PKCE)'
      });
    }

    if (!code_challenge_method || code_challenge_method !== 'S256') {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'code_challenge_method must be "S256"'
      });
    }

    // In a real implementation, you would:
    // 1. Display a login page
    // 2. Authenticate the user
    // 3. Show consent screen
    // 4. Generate code after user approval

    // For this demo, we'll auto-approve and generate the code
    const authCode = generateRandomString(32);
    const expiresAt = Date.now() + AUTHORIZATION_CODE_EXPIRATION;

    // Store authorization code with metadata
    authorizationCodes.set(authCode, {
      clientId: client_id,
      redirectUri: redirect_uri,
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method,
      scope: scope || 'read',
      expiresAt: expiresAt,
      createdAt: Date.now(),
      userId: 'user-123' // In real app, this would be the authenticated user
    });

    // Redirect back to client with authorization code and state
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.append('code', authCode);
    redirectUrl.searchParams.append('state', state);

    res.redirect(redirectUrl.toString());

  } catch (error) {
    console.error('Authorization error:', error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'Internal server error'
    });
  }
});

/**
 * Token Endpoint
 * POST /token
 *
 * Body Parameters:
 * - grant_type: Must be "authorization_code"
 * - code: Authorization code from /authorize
 * - redirect_uri: Must match the original redirect_uri
 * - client_id: Client identifier
 * - client_secret: Client secret
 * - code_verifier: Original random string (PKCE)
 */
app.post('/token', (req, res) => {
  try {
    const {
      grant_type,
      code,
      redirect_uri,
      client_id,
      client_secret,
      code_verifier
    } = req.body;

    // Validate grant_type
    if (!grant_type || grant_type !== 'authorization_code') {
      return res.status(400).json({
        error: 'unsupported_grant_type',
        error_description: 'grant_type must be "authorization_code"'
      });
    }

    // Validate required parameters
    if (!code) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'code is required'
      });
    }

    if (!client_id || !client_secret) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'client_id and client_secret are required'
      });
    }

    if (!redirect_uri) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'redirect_uri is required'
      });
    }

    if (!code_verifier) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'code_verifier is required (PKCE)'
      });
    }

    // Validate client credentials
    const client = clients.get(client_id);
    if (!client || client.clientSecret !== client_secret) {
      return res.status(401).json({
        error: 'invalid_client',
        error_description: 'Invalid client credentials'
      });
    }

    // Check if code has been used (prevents replay attacks)
    if (usedCodes.has(code)) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Authorization code has already been used'
      });
    }

    // Retrieve authorization code data
    const authData = authorizationCodes.get(code);
    if (!authData) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid or expired authorization code'
      });
    }

    // Check expiration (10 minutes)
    if (Date.now() > authData.expiresAt) {
      authorizationCodes.delete(code);
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Authorization code has expired'
      });
    }

    // Validate client_id matches
    if (authData.clientId !== client_id) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'client_id mismatch'
      });
    }

    // Validate redirect_uri matches
    if (authData.redirectUri !== redirect_uri) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'redirect_uri mismatch'
      });
    }

    // Validate PKCE code_verifier
    const computedChallenge = sha256(code_verifier);
    if (computedChallenge !== authData.codeChallenge) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid code_verifier (PKCE validation failed)'
      });
    }

    // Mark code as used (single-use enforcement)
    usedCodes.add(code);
    authorizationCodes.delete(code);

    // Generate access token and refresh token
    const accessToken = generateRandomString(32);
    const refreshToken = generateRandomString(32);

    // Return successful token response
    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: refreshToken,
      scope: authData.scope,
      user_id: authData.userId
    });

  } catch (error) {
    console.error('Token error:', error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'Internal server error'
    });
  }
});

/**
 * Introspection Endpoint (optional but useful for debugging)
 * GET /debug/codes
 */
app.get('/debug/codes', (req, res) => {
  const codes = Array.from(authorizationCodes.entries()).map(([code, data]) => ({
    code,
    clientId: data.clientId,
    expiresAt: new Date(data.expiresAt).toISOString(),
    isExpired: Date.now() > data.expiresAt,
    used: usedCodes.has(code)
  }));

  res.json({
    activeCodes: codes,
    totalUsedCodes: usedCodes.size
  });
});

/**
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    activeCodes: authorizationCodes.size,
    usedCodes: usedCodes.size
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`OAuth 2.0 Authorization Server running on http://localhost:${PORT}`);
  console.log(`\nEndpoints:`);
  console.log(`  Authorization: GET  http://localhost:${PORT}/authorize`);
  console.log(`  Token:         POST http://localhost:${PORT}/token`);
  console.log(`  Debug:         GET  http://localhost:${PORT}/debug/codes`);
  console.log(`  Health:        GET  http://localhost:${PORT}/health`);
  console.log(`\nSecurity Features:`);
  console.log(`  ✓ PKCE with SHA-256`);
  console.log(`  ✓ Redirect URI whitelist validation`);
  console.log(`  ✓ 10-minute code expiration`);
  console.log(`  ✓ Single-use authorization codes`);
  console.log(`  ✓ State parameter validation`);
});

module.exports = app;
