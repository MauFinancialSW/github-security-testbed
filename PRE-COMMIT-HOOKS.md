# Git Pre-Commit Hooks for Security Scanning

This repository uses automated pre-commit hooks to scan for security vulnerabilities, exposed secrets, API keys, passwords, and other sensitive data before code is committed.

## What Gets Scanned

The pre-commit hooks perform the following security checks:

- **Semgrep**: Scans for hardcoded secrets, API keys, passwords, and security anti-patterns
- **TruffleHog**: Detects high-entropy strings and known secret patterns
- **GitLeaks**: Additional secret detection with pattern matching
- **Built-in Checks**: Detects private keys, AWS credentials, large files, and trailing whitespace

## Installation

### Prerequisites

Install the required tools:

```bash
# Install pre-commit framework
pip install pre-commit

# Install Semgrep
pip install semgrep

# Install TruffleHog (requires Go)
go install github.com/trufflesecurity/trufflehog/v3@latest

# Install GitLeaks (alternative: download binary from releases)
go install github.com/gitleaks/gitleaks/v8@latest

# Or use package managers:
# macOS
brew install pre-commit semgrep trufflehog gitleaks

# Ubuntu/Debian
pip install pre-commit semgrep
# Download TruffleHog and GitLeaks binaries separately
```

### Setup Pre-Commit Hooks

1. **Install the hooks** in your local repository:

```bash
cd /path/to/github-security-testbed
pre-commit install
```

2. **Verify installation**:

```bash
pre-commit --version
```

You should see output like: `pre-commit 3.x.x`

3. **(Optional) Run against all files** to test:

```bash
pre-commit run --all-files
```

## Usage

### Automatic Scanning

Once installed, the hooks run automatically on every `git commit`:

```bash
git add myfile.js
git commit -m "Add new feature"
# Pre-commit hooks will run automatically
```

### Manual Scanning

Run hooks manually without committing:

```bash
# Scan all files
pre-commit run --all-files

# Scan specific files
pre-commit run --files src/auth.js src/config.js

# Run specific hook only
pre-commit run semgrep --all-files
pre-commit run trufflehog --all-files
```

### Bypassing Hooks (Use with Caution)

If you need to bypass hooks temporarily (not recommended for security-sensitive changes):

```bash
git commit --no-verify -m "Emergency fix"
```

## What Happens When Secrets Are Detected

If a secret or security issue is found:

1. **Commit is blocked** - Your commit will fail
2. **Results are displayed** - You'll see which files and lines contain issues
3. **Fix the issues** - Remove or properly secure the detected secrets
4. **Retry commit** - After fixing, try committing again

Example output:
```
Semgrep Security Scan........................................Failed
- hook id: semgrep
- exit code: 1

src/config.js
  severity:error rule:generic.secrets.gitleaks.generic-api-key
    Found hardcoded API key
    Line 12: const API_KEY = "sk_live_51234567890abcdef"
```

## Configuration

The hook configuration is in `.pre-commit-config.yaml`. You can customize:

- **Semgrep rules**: Modify `args` under the Semgrep hook
- **File exclusions**: Update `exclude` patterns
- **Hook versions**: Update `rev` values to newer versions

Example customization:
```yaml
- id: semgrep
  args:
    - --config=p/secrets
    - --config=p/owasp-top-ten  # Add more rulesets
    - --error
```

## Troubleshooting

### Hook fails to install
```bash
# Update pre-commit
pip install --upgrade pre-commit

# Reinstall hooks
pre-commit uninstall
pre-commit install
```

### Semgrep not found
```bash
# Ensure Semgrep is in PATH
which semgrep
pip install --upgrade semgrep
```

### TruffleHog/GitLeaks not found
```bash
# Check installation
which trufflehog
which gitleaks

# Add Go bin to PATH if needed
export PATH=$PATH:$(go env GOPATH)/bin
```

### Slow hook execution
```bash
# Update to latest hook versions
pre-commit autoupdate

# Or disable specific slow hooks
# (comment out in .pre-commit-config.yaml)
```

## Best Practices

1. **Never commit secrets** - Use environment variables or secret management tools
2. **Use .gitignore** - Exclude files with sensitive data (`.env`, `secrets.json`)
3. **Regular updates** - Keep hooks updated: `pre-commit autoupdate`
4. **Team adoption** - Ensure all developers install hooks
5. **CI/CD integration** - Run same checks in CI pipeline (see `.github/workflows/`)

## Resources

- [Pre-commit Documentation](https://pre-commit.com/)
- [Semgrep Rules](https://semgrep.dev/r)
- [TruffleHog GitHub](https://github.com/trufflesecurity/trufflehog)
- [GitLeaks Documentation](https://github.com/gitleaks/gitleaks)

## Support

For issues with the hooks:
1. Check this documentation
2. Run `pre-commit run --all-files --verbose` for detailed output
3. Review `.pre-commit-config.yaml` configuration
4. Open an issue in this repository
