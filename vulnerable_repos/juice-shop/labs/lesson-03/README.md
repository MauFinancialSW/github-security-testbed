# Lesson 03: Automated Security Testing - Lab Files

This directory contains educational lab files demonstrating automated security testing techniques with GitHub Copilot, including OAuth security testing and fuzzing.

**Duration:** 40 minutes

## Contents

### OAuth Authentication Server (Python)

**auth_server.py**
- Complete OAuth 2.0 authentication server implementation
- Features: JWT tokens, refresh tokens, authorization codes, scope-based access
- **Intentional vulnerabilities** for security testing practice:
  1. Weak JWT secret (hardcoded and predictable)
  2. Missing rate limiting (brute force vulnerability)
  3. Authorization code replay vulnerability
  4. Insufficient refresh token rotation
  5. Missing PKCE validation

**test_auth_server.py**
- Comprehensive pytest security test suite (~40 tests)
- Validates authentication flows, token handling, scope enforcement
- Demonstrates how to test for security vulnerabilities
- Includes tests that will catch the intentional vulnerabilities

**requirements.txt**
- Python dependencies for OAuth server and tests

### JSON Parser Fuzzing (C)

**api_validator.c**
- JSON parser for API request validation
- **Intentional vulnerability**: No recursion depth limit (stack overflow)
- Used to demonstrate vulnerability discovery through fuzzing

**fuzz_json_parser.c**
- libFuzzer harness targeting the JSON parser
- Implements LLVMFuzzerTestOneInput entry point
- Designed to discover the recursion depth vulnerability

**build_fuzzer.sh**
- Compilation script with sanitizers (AddressSanitizer, UndefinedBehaviorSanitizer)
- Builds the fuzzer with proper instrumentation

**corpus/**
- Directory containing 10 seed JSON files for fuzzing
- Includes: empty objects/arrays, nested objects, large arrays, special characters, edge cases

## Quick Start

### 1. OAuth Security Testing

```bash
# Install Python dependencies
pip install -r requirements.txt

# Run the OAuth server (demo mode)
python auth_server.py

# Run the security test suite
pytest test_auth_server.py -v

# Run with coverage reporting
pytest test_auth_server.py -v --cov=auth_server --cov-report=term-missing

# Run specific test categories
pytest test_auth_server.py::TestAuthentication -v
pytest test_auth_server.py::TestSecurityVulnerabilities -v
```

### 2. Fuzzing the JSON Parser

```bash
# Make build script executable
chmod +x build_fuzzer.sh

# Build the fuzzer
./build_fuzzer.sh

# Run fuzzing (basic)
./fuzz_json_parser corpus/

# Run fuzzing with options
./fuzz_json_parser -max_len=10000 -timeout=60 corpus/

# Run with multiple workers (parallel fuzzing)
./fuzz_json_parser -jobs=4 -workers=4 corpus/

# Run with custom sanitizer options
ASAN_OPTIONS=detect_leaks=1:symbolize=1 ./fuzz_json_parser corpus/
```

## Understanding the Vulnerabilities

### OAuth Server Vulnerabilities

1. **Weak JWT Secret** (`auth_server.py:70`)
   - Hardcoded secret: `"super_secret_key_123"`
   - Allows token forgery if secret is discovered
   - Test: `test_jwt_secret_strength` (will fail)

2. **No Rate Limiting** (`auth_server.py:94-100`)
   - Unlimited authentication attempts
   - Enables brute force attacks
   - Test: `test_brute_force_protection` (documents vulnerability)

3. **Authorization Code Replay** (`auth_server.py:156-180`)
   - Race condition in code validation
   - Code marked as 'used' but not atomically checked
   - Test: `test_authorization_code_single_use`

4. **Weak Token Rotation** (`auth_server.py:260-285`)
   - Old refresh tokens not immediately invalidated
   - Creates window for token reuse
   - Test: `test_refresh_token_rotation`

### JSON Parser Vulnerability

**Stack Overflow from Deep Nesting** (`api_validator.c:192-235`)
- No maximum recursion depth enforced
- Deeply nested JSON causes stack overflow
- Example: `{"a":{"b":{"c":{...}}}}`  (100+ levels)
- Fuzzing will discover this automatically

## Expected Fuzzing Results

When you run the fuzzer, it should discover the stack overflow vulnerability:

```
INFO: Seed: 12345
INFO: -max_len is not set; libFuzzer will guess a good value based on the corpus.
#0	READ units: 10
#100	INITED cov: 87 ft: 45 corp: 8/234b exec/s: 0 rss: 32Mb
#1000	NEW    cov: 92 ft: 52 corp: 12/567b lim: 16 exec/s: 0 rss: 33Mb
...
==12345==ERROR: AddressSanitizer: stack-overflow
    #0 parse_object api_validator.c:192
    #1 parse_value api_validator.c:245
    #2 parse_object api_validator.c:207
    #3 parse_value api_validator.c:245
    ... [50+ stack frames showing recursion] ...
```

The crash will be saved to a file for analysis.

## Using with GitHub Copilot

These files are designed to demonstrate Copilot's capabilities for security testing:

### Prompt Examples

**Generate additional tests:**
```
Add tests for concurrent token refresh attacks where multiple requests
try to use the same refresh token simultaneously
```

**Fix vulnerabilities:**
```
Fix the JWT secret vulnerability by generating a cryptographically
secure random secret on server startup
```

**Enhance fuzzing:**
```
Create a JSON dictionary file for libFuzzer to improve mutation
of JSON-specific tokens like quotes, braces, and colons
```

**Add security features:**
```
Implement rate limiting using a token bucket algorithm that allows
5 failed login attempts per minute per IP address
```

## Integration with GitHub Advanced Security

### CodeQL Scanning

These files can be scanned with CodeQL:

```yaml
# .github/workflows/codeql.yml
- uses: github/codeql-action/analyze@v2
  with:
    languages: python, cpp
```

CodeQL will detect:
- Hardcoded secrets in `auth_server.py`
- Potential stack overflow in `api_validator.c`
- Missing input validation

### Dependabot

The `requirements.txt` file enables Dependabot to:
- Monitor PyJWT for security updates
- Alert on vulnerable pytest versions
- Keep dependencies current

### Secret Scanning

GitHub will flag the hardcoded JWT secret as a potential leak.

## Learning Objectives

By working with these files, you will:

1. **Understand security testing patterns**
   - Writing comprehensive test suites
   - Testing both positive and negative cases
   - Validating security properties

2. **Learn fuzzing fundamentals**
   - libFuzzer integration
   - Sanitizer usage
   - Corpus management
   - Crash analysis

3. **Practice vulnerability discovery**
   - Identifying common security flaws
   - Understanding attack vectors
   - Validating fixes

4. **Use AI-assisted security testing**
   - Generating tests with Copilot
   - Refining test coverage
   - Fixing discovered issues

## Additional Resources

- **Demo Runbook**: See `demos/lesson-03-demo-runbook-final.md` for full lesson
- **OWASP Juice Shop**: Main application with more security examples
- **libFuzzer Documentation**: https://llvm.org/docs/LibFuzzer.html
- **OAuth 2.0 Specification**: https://oauth.net/2/
- **pytest Documentation**: https://docs.pytest.org/

## Notes

- These files contain **intentional vulnerabilities** for educational purposes
- Do NOT use this OAuth implementation in production
- The vulnerabilities are designed to be discovered through testing and fuzzing
- All code is heavily commented to explain security concepts

## Troubleshooting

**Fuzzer won't compile:**
- Ensure clang is installed: `clang --version`
- On Linux: `sudo apt-get install clang`
- On macOS: `brew install llvm`

**Python tests failing:**
- Install dependencies: `pip install -r requirements.txt`
- Use Python 3.8 or later: `python --version`

**Fuzzer finds no crashes:**
- Increase max length: `-max_len=100000`
- Run longer: Remove timeout or increase it
- The deep nesting vulnerability requires significant nesting (50+ levels)

**Performance issues:**
- Reduce workers: `-jobs=1 -workers=1`
- Limit memory: `-rss_limit_mb=2048`
- Use smaller corpus initially

---

**Created for MS Press GitHub Copilot for Cybersecurity Professionals Course**
