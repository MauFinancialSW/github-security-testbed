# Lesson 03 - Quick Start Guide

## Files Created

### Python OAuth Security Testing
- **auth_server.py** (460 lines) - OAuth 2.0 server with intentional vulnerabilities
- **test_auth_server.py** (610 lines) - 40+ security tests covering all OAuth flows
- **requirements.txt** (28 lines) - Python dependencies

### C Fuzzing Lab
- **api_validator.c** (443 lines) - JSON parser with stack overflow vulnerability
- **fuzz_json_parser.c** (137 lines) - libFuzzer harness
- **build_fuzzer.sh** (122 lines) - Build script with sanitizers
- **corpus/** (10 files) - JSON seed files for fuzzing

### Documentation
- **README.md** (269 lines) - Comprehensive guide
- **QUICKSTART.md** (this file) - Quick reference

**Total:** 2,069 lines of educational security testing code

---

## 5-Minute Test Run

### Test OAuth Server

```bash
cd C:\github\juice-shop\labs\lesson-03

# Install dependencies (one-time)
pip install PyJWT pytest pytest-cov

# Run the OAuth server demo
python auth_server.py

# Run security tests
pytest test_auth_server.py -v --tb=short
```

**Expected Output:**
- Server demo shows token generation
- Tests run: ~40 tests
- Some intentional failures showing vulnerabilities
- Most security tests pass, demonstrating proper validation

### Test JSON Parser (Requires clang)

```bash
# Build fuzzer (requires clang/llvm)
chmod +x build_fuzzer.sh
./build_fuzzer.sh

# Quick fuzzing run (30 seconds)
timeout 30 ./fuzz_json_parser corpus/ || echo "Fuzzing completed"

# The fuzzer will explore JSON inputs and likely discover the stack overflow
```

---

## What Each Vulnerability Demonstrates

### OAuth Server (Python)

1. **Weak JWT Secret** - Token forgery risk
2. **No Rate Limiting** - Brute force attacks
3. **Authorization Code Replay** - Race conditions
4. **Insufficient Token Rotation** - Token reuse window
5. **Missing PKCE** - Authorization code interception

### JSON Parser (C)

1. **Stack Overflow** - Deep recursion without limits
2. **No Input Validation** - Missing depth checks
3. **Resource Exhaustion** - DoS via nested structures

---

## Using with GitHub Copilot

### Test Generation Prompts

```
Generate additional OAuth tests for:
- Token binding to client certificates
- Proof Key for Code Exchange (PKCE)
- Dynamic client registration
```

```
Add concurrent testing using threading to detect race conditions
in the authorization code exchange
```

### Vulnerability Fixing Prompts

```
Fix the JWT secret vulnerability by:
1. Generating a cryptographically secure random secret on startup
2. Loading from environment variable or secrets manager
3. Rotating secrets periodically
```

```
Implement rate limiting using a sliding window algorithm that:
- Tracks attempts per IP and username
- Allows 5 attempts per 5 minutes
- Implements exponential backoff
```

### Fuzzing Enhancement Prompts

```
Create a libFuzzer dictionary for JSON tokens to improve mutation:
- Common JSON delimiters
- Unicode escape sequences
- Number formats
```

```
Add a maximum recursion depth check to api_validator.c that:
- Limits nesting to 50 levels
- Returns an error for deeper structures
- Tracks depth in parser state
```

---

## Expected Test Results

### OAuth Tests (pytest)

```
TestUserRegistration ................... [PASS] 3/3
TestAuthentication ..................... [PASS] 5/5
TestLoginFlow .......................... [PASS] 4/4
TestAccessTokenValidation .............. [PASS] 7/7
TestScopeEnforcement ................... [PASS] 4/4
TestRefreshTokenFlow ................... [PASS] 6/6
TestAuthorizationCodeFlow .............. [PASS] 5/5
TestSecurityVulnerabilities ............ [FAIL] 3/3 (intentional)
TestTokenExpiration .................... [PASS] 2/2

Total: 39 tests, 36 passed, 3 failed (vulnerabilities documented)
Coverage: ~95% of auth_server.py
```

### Fuzzing Results

```
#0      READ units: 10
#100    INITED cov: 87 ft: 45 corp: 8/234b
#1000   NEW    cov: 92 ft: 52 corp: 12/567b
#5000   NEW    cov: 95 ft: 58 corp: 18/1234b
...
==12345==ERROR: AddressSanitizer: stack-overflow
SUMMARY: AddressSanitizer: stack-overflow
artifact_prefix='./'; Test unit written to ./crash-xyz
```

---

## Integration with CI/CD

### GitHub Actions Workflow

```yaml
name: Security Testing
on: [push, pull_request]

jobs:
  oauth-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: |
          cd labs/lesson-03
          pip install -r requirements.txt
          pytest test_auth_server.py --cov=auth_server --cov-report=xml
      - uses: codecov/codecov-action@v3

  fuzzing:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: |
          cd labs/lesson-03
          sudo apt-get install -y clang
          ./build_fuzzer.sh
          timeout 300 ./fuzz_json_parser corpus/ || true
      - uses: actions/upload-artifact@v3
        if: failure()
        with:
          name: crash-artifacts
          path: labs/lesson-03/crash-*
```

---

## Troubleshooting

**"ModuleNotFoundError: No module named 'jwt'"**
- Install dependencies: `pip install -r requirements.txt`

**"clang: command not found"**
- Install clang: `sudo apt-get install clang` (Linux) or `brew install llvm` (macOS)

**"pytest: command not found"**
- Install pytest: `pip install pytest`

**Tests run but some fail**
- Expected! The `TestSecurityVulnerabilities` tests document intentional flaws

**Fuzzer builds but finds no crashes**
- Increase runtime: Remove `timeout` or increase duration
- The vulnerability requires deep nesting (50+ levels)
- Try: `./fuzz_json_parser -max_len=100000 corpus/`

---

## Next Steps

1. **Fix the vulnerabilities** using Copilot prompts
2. **Verify fixes** by running tests again
3. **Extend test coverage** with additional edge cases
4. **Integrate into CI/CD** using GitHub Actions
5. **Apply patterns** to real projects

---

## Learning Resources

- **OAuth 2.0 Security Best Practices**: https://oauth.net/2/
- **libFuzzer Tutorial**: https://llvm.org/docs/LibFuzzer.html
- **pytest Documentation**: https://docs.pytest.org/
- **AddressSanitizer**: https://clang.llvm.org/docs/AddressSanitizer.html
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/

---

**Ready to start? Run the OAuth tests first - they're the easiest way to see the lab in action!**

```bash
cd C:\github\juice-shop\labs\lesson-03
pip install -r requirements.txt
python auth_server.py
```
