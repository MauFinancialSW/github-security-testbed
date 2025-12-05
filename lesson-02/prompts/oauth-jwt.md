# OAuth 2.0 and JWT Prompts

## Course: GitHub Copilot for Cybersecurity Specialists
## Lesson: 02 - Security Protocols with Copilot

---

## OAuth 2.0 with PKCE

### Authorization Server Prompt
```
Create OAuth 2.0 authorization server with PKCE support using Express
```

### Expected Security Features
- Authorization code flow (not implicit)
- PKCE with S256 code_challenge_method
- Redirect URI whitelist validation (exact match)
- 10-minute authorization code expiration
- Single-use authorization codes
- State parameter for CSRF protection

### PKCE Verification Prompt
```
Verify PKCE code_challenge against code_verifier using SHA-256
```

### Expected Implementation
```javascript
function verifyCodeChallenge(codeVerifier, codeChallenge) {
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
}
```

---

## JWT Token Generation

### Basic Prompt
```
Generate JWT token with proper claims and RS256 signing
```

### Required Claims
| Claim | Description | Example |
|-------|-------------|---------|
| iss | Issuer | https://auth.example.com |
| sub | Subject (user ID) | user_123 |
| aud | Audience | https://api.example.com |
| exp | Expiration | Current time + 15 min |
| iat | Issued at | Current timestamp |
| jti | JWT ID | UUID for revocation |

### Algorithm Selection
```
// SECURE: Use asymmetric algorithms
RS256, RS384, RS512  // RSA
ES256, ES384, ES512  // ECDSA
PS256, PS384, PS512  // RSA-PSS

// AVOID in most cases:
HS256  // Requires shared secret
none   // Never use - allows bypass
```

---

## JWT Verification

### Secure Verification Prompt
```
Verify JWT with issuer, audience, and algorithm validation
```

### Critical Checks
1. Validate `alg` header matches expected algorithm
2. Verify `iss` claim matches known issuer
3. Verify `aud` claim includes our service
4. Check `exp` > current time
5. Check `nbf` <= current time (if present)

### Prevent Algorithm Confusion
```javascript
jwt.verify(token, publicKey, {
  algorithms: ['RS256'],  // Explicitly specify allowed algorithms
  issuer: 'https://auth.example.com',
  audience: 'https://api.example.com'
});
```

---

## Token Refresh Flow

### Prompt
```
Implement secure refresh token rotation with family tracking
```

### Security Requirements
- Store refresh tokens hashed in database
- Implement token rotation (new refresh token each use)
- Track token families for revocation
- Shorter expiry for access tokens (15 min)
- Longer expiry for refresh tokens (7 days)

---

## OpenID Connect ID Token

### Prompt
```
Generate OpenID Connect ID token with required claims
```

### Additional OIDC Claims
- `auth_time`: Time of authentication
- `nonce`: Replay prevention (from authorization request)
- `at_hash`: Access token hash (for implicit/hybrid flows)
- Profile claims: `name`, `email`, `email_verified`, `picture`

---

## Teaching Points

1. **Never Trust Client-Side Token Validation**: Always verify on server.

2. **Algorithm Pinning**: Specify allowed algorithms explicitly to prevent algorithm confusion attacks.

3. **Short-Lived Access Tokens**: 15 minutes is standard; use refresh tokens for longevity.

4. **PKCE for All Clients**: Not just public clients - use PKCE even for confidential clients.

5. **Token Binding**: Consider binding tokens to client fingerprints in high-security scenarios.
