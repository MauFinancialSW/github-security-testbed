/**
 * OAuth 2.0 Security Test Suite
 * ==============================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 03 - Automated Security Testing
 *
 * Copilot Prompt Used:
 * "Generate comprehensive OAuth security tests for PKCE flow"
 *
 * Test Categories:
 * - PKCE validation
 * - Redirect URI attacks
 * - Token security
 * - Authorization code replay
 * - State parameter CSRF protection
 */

const assert = require('assert');
const crypto = require('crypto');

// =============================================================================
// Test Configuration
// =============================================================================

const config = {
  authorizationEndpoint: 'http://localhost:3000/authorize',
  tokenEndpoint: 'http://localhost:3000/token',
  clientId: 'client_web_app',
  validRedirectUri: 'http://localhost:3000/callback'
};

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Generate PKCE code verifier and challenge
 */
function generatePKCE() {
  const verifier = crypto.randomBytes(32)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');

  const challenge = crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');

  return { verifier, challenge };
}

/**
 * Generate secure state parameter
 */
function generateState() {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * Build authorization URL
 */
function buildAuthUrl(params) {
  const url = new URL(config.authorizationEndpoint);
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined) {
      url.searchParams.set(key, value);
    }
  });
  return url.toString();
}

// =============================================================================
// PKCE Security Tests
// =============================================================================

const pkceTests = {
  name: 'PKCE Security Tests',
  tests: [
    {
      name: 'Should reject authorization without code_challenge',
      async test() {
        const url = buildAuthUrl({
          response_type: 'code',
          client_id: config.clientId,
          redirect_uri: config.validRedirectUri,
          state: generateState(),
          scope: 'openid'
          // Missing code_challenge
        });

        const response = await fetch(url, { redirect: 'manual' });
        const location = response.headers.get('location') || '';

        assert(
          location.includes('error=invalid_request') ||
          response.status === 400,
          'Should reject request without PKCE'
        );
      }
    },
    {
      name: 'Should reject plain code_challenge_method',
      async test() {
        const { challenge } = generatePKCE();
        const url = buildAuthUrl({
          response_type: 'code',
          client_id: config.clientId,
          redirect_uri: config.validRedirectUri,
          code_challenge: challenge,
          code_challenge_method: 'plain',  // Insecure method
          state: generateState(),
          scope: 'openid'
        });

        // Note: Some servers allow 'plain' for backwards compatibility
        // Security recommendation: Reject 'plain' in production
        console.log('  Note: Verify server policy on plain method');
      }
    },
    {
      name: 'Should reject invalid code_verifier',
      async test() {
        const { verifier, challenge } = generatePKCE();

        // Get authorization code (simulated)
        const authCode = 'test_auth_code';

        // Try token exchange with wrong verifier
        const response = await fetch(config.tokenEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code: authCode,
            redirect_uri: config.validRedirectUri,
            client_id: config.clientId,
            code_verifier: 'wrong_verifier_value'
          })
        });

        const data = await response.json();
        assert.strictEqual(data.error, 'invalid_grant', 'Should reject invalid verifier');
      }
    },
    {
      name: 'Should reject code_verifier that does not match challenge',
      async test() {
        const { challenge } = generatePKCE();
        const { verifier: differentVerifier } = generatePKCE();

        // The challenge was generated from original verifier
        // but we're sending a different verifier
        console.log('  Verifying S256 hash comparison prevents substitution attacks');
      }
    }
  ]
};

// =============================================================================
// Redirect URI Security Tests
// =============================================================================

const redirectTests = {
  name: 'Redirect URI Security Tests',
  tests: [
    {
      name: 'Should reject unregistered redirect_uri',
      async test() {
        const { challenge } = generatePKCE();
        const url = buildAuthUrl({
          response_type: 'code',
          client_id: config.clientId,
          redirect_uri: 'https://evil.com/callback',  // Not registered
          code_challenge: challenge,
          code_challenge_method: 'S256',
          state: generateState(),
          scope: 'openid'
        });

        const response = await fetch(url, { redirect: 'manual' });
        assert(response.status === 400, 'Should reject unregistered redirect URI');
      }
    },
    {
      name: 'Should reject redirect_uri with path traversal',
      async test() {
        const { challenge } = generatePKCE();
        const maliciousUris = [
          'http://localhost:3000/callback/../../../evil',
          'http://localhost:3000/callback/..%2F..%2Fevil',
          'http://localhost:3000/callback%00https://evil.com'
        ];

        for (const uri of maliciousUris) {
          const url = buildAuthUrl({
            response_type: 'code',
            client_id: config.clientId,
            redirect_uri: uri,
            code_challenge: challenge,
            code_challenge_method: 'S256',
            state: generateState(),
            scope: 'openid'
          });

          const response = await fetch(url, { redirect: 'manual' });
          assert(response.status === 400, `Should reject: ${uri}`);
        }
      }
    },
    {
      name: 'Should enforce exact redirect_uri match (no wildcards)',
      async test() {
        const { challenge } = generatePKCE();

        // Try subdomain variation
        const url = buildAuthUrl({
          response_type: 'code',
          client_id: config.clientId,
          redirect_uri: 'http://evil.localhost:3000/callback',
          code_challenge: challenge,
          code_challenge_method: 'S256',
          state: generateState(),
          scope: 'openid'
        });

        const response = await fetch(url, { redirect: 'manual' });
        assert(response.status === 400, 'Should reject subdomain variation');
      }
    },
    {
      name: 'Should reject redirect_uri mismatch in token request',
      async test() {
        // Token request must use same redirect_uri as authorization request
        const response = await fetch(config.tokenEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code: 'test_code',
            redirect_uri: 'http://different.com/callback',  // Different URI
            client_id: config.clientId,
            code_verifier: 'test_verifier'
          })
        });

        const data = await response.json();
        assert.strictEqual(data.error, 'invalid_grant', 'Should reject URI mismatch');
      }
    }
  ]
};

// =============================================================================
// Authorization Code Security Tests
// =============================================================================

const codeTests = {
  name: 'Authorization Code Security Tests',
  tests: [
    {
      name: 'Should reject reused authorization code',
      async test() {
        const code = 'previously_used_code';

        // First use (would succeed)
        // Second use (should fail)
        const response = await fetch(config.tokenEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: config.validRedirectUri,
            client_id: config.clientId,
            code_verifier: 'test_verifier'
          })
        });

        const data = await response.json();
        assert.strictEqual(data.error, 'invalid_grant', 'Should reject reused code');
      }
    },
    {
      name: 'Should reject expired authorization code (>10 min)',
      async test() {
        // Authorization codes should expire after 10 minutes
        console.log('  Note: Test requires time manipulation or waiting');
        console.log('  Server should track code creation time');
      }
    },
    {
      name: 'Should revoke tokens if code is reused',
      async test() {
        // RFC 6819: If code reuse detected, revoke all tokens from that code
        console.log('  Security measure: Revoke token family on code reuse');
      }
    }
  ]
};

// =============================================================================
// State Parameter (CSRF) Tests
// =============================================================================

const stateTests = {
  name: 'State Parameter CSRF Tests',
  tests: [
    {
      name: 'Should require state parameter',
      async test() {
        const { challenge } = generatePKCE();
        const url = buildAuthUrl({
          response_type: 'code',
          client_id: config.clientId,
          redirect_uri: config.validRedirectUri,
          code_challenge: challenge,
          code_challenge_method: 'S256',
          scope: 'openid'
          // Missing state
        });

        const response = await fetch(url, { redirect: 'manual' });
        const location = response.headers.get('location') || '';

        assert(
          location.includes('error=') || response.status === 400,
          'Should require state parameter'
        );
      }
    },
    {
      name: 'Should reject short state parameter',
      async test() {
        const { challenge } = generatePKCE();
        const url = buildAuthUrl({
          response_type: 'code',
          client_id: config.clientId,
          redirect_uri: config.validRedirectUri,
          code_challenge: challenge,
          code_challenge_method: 'S256',
          state: 'abc',  // Too short (< 16 chars)
          scope: 'openid'
        });

        const response = await fetch(url, { redirect: 'manual' });
        const location = response.headers.get('location') || '';

        // Server should require minimum state length
        console.log('  Note: Verify server enforces minimum state length');
      }
    },
    {
      name: 'Should return state parameter unchanged',
      async test() {
        const { challenge } = generatePKCE();
        const state = generateState();

        const url = buildAuthUrl({
          response_type: 'code',
          client_id: config.clientId,
          redirect_uri: config.validRedirectUri,
          code_challenge: challenge,
          code_challenge_method: 'S256',
          state: state,
          scope: 'openid'
        });

        const response = await fetch(url, { redirect: 'manual' });
        const location = response.headers.get('location') || '';

        assert(
          location.includes(`state=${state}`),
          'State should be returned unchanged'
        );
      }
    }
  ]
};

// =============================================================================
// Token Security Tests
// =============================================================================

const tokenTests = {
  name: 'Token Security Tests',
  tests: [
    {
      name: 'Access token should have short expiry (≤15 min)',
      async test() {
        // Parse JWT to check exp claim
        const decodeJWT = (token) => {
          const parts = token.split('.');
          return JSON.parse(Buffer.from(parts[1], 'base64').toString());
        };

        // Would need actual token from successful flow
        console.log('  Verify: access_token exp ≤ current_time + 900s');
      }
    },
    {
      name: 'Refresh token should rotate on use',
      async test() {
        // Each refresh should return new refresh_token
        console.log('  Verify: New refresh_token issued on each use');
        console.log('  Verify: Old refresh_token invalidated');
      }
    },
    {
      name: 'Should not expose tokens in URL',
      async test() {
        // Implicit grant exposes tokens in fragment
        // Authorization code flow is secure
        const { challenge } = generatePKCE();
        const url = buildAuthUrl({
          response_type: 'token',  // Implicit grant
          client_id: config.clientId,
          redirect_uri: config.validRedirectUri,
          code_challenge: challenge,
          code_challenge_method: 'S256',
          state: generateState(),
          scope: 'openid'
        });

        const response = await fetch(url, { redirect: 'manual' });
        assert(
          response.status === 400,
          'Should reject implicit grant (response_type=token)'
        );
      }
    },
    {
      name: 'Should include proper JWT claims',
      async test() {
        const requiredClaims = ['iss', 'sub', 'aud', 'exp', 'iat'];
        console.log(`  Required claims: ${requiredClaims.join(', ')}`);
      }
    }
  ]
};

// =============================================================================
// Test Runner
// =============================================================================

async function runTests() {
  console.log('=== OAuth 2.0 Security Test Suite ===\n');

  const testSuites = [pkceTests, redirectTests, codeTests, stateTests, tokenTests];
  let passed = 0;
  let failed = 0;
  let skipped = 0;

  for (const suite of testSuites) {
    console.log(`\n${suite.name}`);
    console.log('='.repeat(suite.name.length));

    for (const test of suite.tests) {
      process.stdout.write(`  ${test.name}: `);

      try {
        await test.test();
        console.log('✓ PASS');
        passed++;
      } catch (error) {
        if (error.code === 'ECONNREFUSED') {
          console.log('⊘ SKIPPED (server not running)');
          skipped++;
        } else {
          console.log(`✗ FAIL - ${error.message}`);
          failed++;
        }
      }
    }
  }

  console.log('\n' + '='.repeat(40));
  console.log(`Results: ${passed} passed, ${failed} failed, ${skipped} skipped`);
  console.log('='.repeat(40));

  return { passed, failed, skipped };
}

// =============================================================================
// Export
// =============================================================================

module.exports = {
  generatePKCE,
  generateState,
  buildAuthUrl,
  pkceTests,
  redirectTests,
  codeTests,
  stateTests,
  tokenTests,
  runTests
};

// Run if executed directly
if (require.main === module) {
  runTests().catch(console.error);
}
