# Cryptographic Implementation Prompts

## Course: GitHub Copilot for Cybersecurity Specialists
## Lesson: 02 - Security Protocols with Copilot

---

## AES-256-GCM Encryption

### Basic Prompt
```
Encrypt data using AES-256-GCM with secure IV generation
```

### Expected Copilot Behavior
- Uses `crypto.randomBytes(12)` for IV (correct size for GCM)
- Selects `aes-256-gcm` algorithm (authenticated encryption)
- Extracts and stores authentication tag
- Combines IV + tag + ciphertext for transmission

### Why This Is Secure
- GCM provides both confidentiality AND authenticity
- Random IV prevents ciphertext analysis across messages
- 12-byte IV is optimal for GCM performance and security
- Authentication tag prevents tampering

---

## Password-Based Key Derivation

### Basic Prompt
```
Derive encryption key from password using PBKDF2 with PCI-DSS compliance
```

### Expected Parameters
- Iterations: 600,000+ (PCI-DSS 2023 requirement)
- Hash: SHA-512
- Key length: 32 bytes (256 bits for AES-256)
- Salt: 32 bytes random

### Follow-up Prompts
```
Add Argon2id for password hashing with OWASP recommended parameters
```

---

## Secure Token Generation

### Basic Prompt
```
Generate cryptographically secure token for API authentication
```

### Expected Implementation
- Uses `crypto.randomBytes()` (not Math.random!)
- Minimum 32 bytes of entropy
- URL-safe base64 encoding option

---

## HMAC Authentication

### Basic Prompt
```
Create and verify HMAC for message authentication with timing-safe comparison
```

### Critical Security Point
- Must use `crypto.timingSafeEqual()` for comparison
- Prevents timing attacks on signature verification

---

## Teaching Points

1. **Always Ask About Algorithm Choice**: Copilot might suggest older algorithms. Request specific secure algorithms.

2. **Check IV/Nonce Handling**: Ensure random generation, never reuse with same key.

3. **Verify Tag Handling**: For authenticated encryption, ensure tag is properly extracted and verified.

4. **Compliance Requirements**: Specify compliance standards (PCI-DSS, NIST) for appropriate parameters.
