# Plan: Fix XSS Vulnerabilities in UserProfile Component

**TL;DR:** Systematically remediate 10 distinct XSS vulnerabilities by applying established patterns from the secure-react-app: sanitize all HTML with DOMPurify, validate all URLs, encode all text output via React's JSX, replace `dangerouslySetInnerHTML` with sanitized alternatives, remove unsafe DOM manipulation, eliminate `eval()`, and add comprehensive security headers/CSP.

## Implementation Steps

### 1. Install and Configure DOMPurify
- Install DOMPurify library (`npm install dompurify`)
- Create reusable sanitization utility functions following secure-react-app patterns
- Configure strict sanitization config:
  - ALLOWED_TAGS whitelist: `['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li']`
  - FORBID_TAGS blacklist: `['script', 'style', 'iframe', 'form', 'input']`
  - FORBID_ATTR blacklist: `['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus']`
  - ALLOW_DATA_ATTR: `false`
- Create different sanitization levels for different content types (rich HTML for bio, plain text for comments)

### 2. Replace All dangerouslySetInnerHTML Uses (Vulnerabilities 1, 4, 6, 9)
**Vulnerability 1 - Bio rendering in `renderBio()`:**
- Apply DOMPurify.sanitize() to bio before passing to dangerouslySetInnerHTML
- Use useMemo to memoize sanitization for performance

**Vulnerability 4 - Comments rendering in `renderComments()`:**
- Change comments to plaintext (no HTML allowed)
- Remove dangerouslySetInnerHTML entirely
- Let React auto-escape the text content
- Sanitize comment input BEFORE storing (not just before rendering)

**Vulnerability 6 - Error message rendering:**
- Remove dangerouslySetInnerHTML from error display
- Use regular React text rendering (auto-escaped)
- Keep error message as plain text only

**Vulnerability 9 - Dynamic button rendering:**
- Remove renderDynamicButton() entirely OR
- If button action needed, sanitize to safe text content only
- Never pass user input to onclick or other event handlers via dangerouslySetInnerHTML

### 3. Remove Unsafe DOM Manipulation (Vulnerability 2)
- Delete the useEffect hook that assigns innerHTML directly to bioRef
- Replace with React state management
- Let React handle all DOM updates declaratively

### 4. Add URL Validation (Vulnerability 3)
- Implement `isValidUrl()` helper function:
  - Use native URL constructor to validate format
  - Whitelist only `http:` and `https:` protocols
  - Block `javascript:`, `data:`, and malformed URLs
- Call validation in renderWebsiteLink() before rendering `<a>` tag
- Show error message if URL is invalid

### 5. Remove eval() and document.write (Vulnerabilities 7, 8)
**Vulnerability 7 - calculateAge() function:**
- Replace `eval(calculation)` with simple arithmetic: `return 2024 - birthYear`
- Never use eval() with user input

**Vulnerability 8 - renderDynamicContent() function:**
- Remove renderDynamicContent() entirely
- Never use document.write() with user content
- Use React state and JSX for dynamic content instead

### 6. Sanitize URL Parameters (Vulnerability 5)
- In the useEffect that reads URL search params:
  - Apply DOMPurify.sanitize() to searchParam before storing
  - Use ALLOWED_TAGS: [] to strip all HTML
  - Store sanitized value in state
- Never directly inject URL parameters into innerHTML

### 7. Implement CSS Validation (Vulnerability 10)
- Create regex whitelist for CSS color values:
  - Pattern: `^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$|^rgb\(\d{1,3},\s*\d{1,3},\s*\d{1,3}\)$`
- Validate backgroundColor input against regex
- Default to safe fallback `#ffffff` if validation fails
- Prevent CSS injection via background-image or other tricks

### 8. Add Security Headers and CSP
- Install helmet.js middleware for server
- Configure Content-Security-Policy headers:
  - `script-src: ['self']` (no inline scripts)
  - `object-src: ['none']` (no plugins)
  - `frame-src: ['none']` (no iframe embedding)
  - Other standard security headers (X-Content-Type-Options: nosniff, X-Frame-Options: DENY, etc.)
- Apply helmet middleware to all responses

### 9. Add rel Attribute to External Links (Reverse Tabnabbing Prevention)
- Update all `<a>` tags with `target="_blank"` to include:
  - `rel="noopener noreferrer"`
- In renderWebsiteLink(): `<a href={website} target="_blank" rel="noopener noreferrer">`

### 10. Create Comprehensive Security Test Suite
- Test each vulnerability class independently:
  - Script tag injection (various encodings)
  - Event handler injection (onerror, onload, onclick, onmouseover, etc.)
  - JavaScript URL protocol bypass (javascript:, jAvAsCrIpT:, with null bytes)
  - SVG-based XSS injection
  - Style-based XSS (background-image with data URI)
  - DOM-based XSS from URL parameters
  - Stored XSS in comments
- Follow secure-react-app test patterns using @testing-library/react
- Run tests in CI/CD pipeline before merge
- Verify no regressions in functionality after fixes

## Vulnerability-to-Fix Mapping

| Vulnerability | Category | Fix | Priority |
|---|---|---|---|
| 1 - dangerouslySetInnerHTML bio | DOM XSS | Apply DOMPurify sanitization | CRITICAL |
| 2 - innerHTML via useEffect | DOM XSS | Remove useEffect, use React rendering | CRITICAL |
| 3 - javascript: href | DOM XSS | Add URL validation with isValidUrl() | CRITICAL |
| 4 - Stored XSS comments | Stored XSS | Remove HTML, plain text only | CRITICAL |
| 5 - URL search parameter | Reflected XSS | Sanitize URL params before state | HIGH |
| 6 - Error message reflection | Reflected XSS | Remove dangerouslySetInnerHTML, auto-escape | HIGH |
| 7 - eval() code injection | Code Injection | Replace with direct arithmetic | CRITICAL |
| 8 - document.write | DOM XSS | Remove entirely, use React state | HIGH |
| 9 - Event handler injection | DOM XSS | Remove dynamic onclick via dangerouslySetInnerHTML | HIGH |
| 10 - CSS injection | CSS Injection | Add regex whitelist validation | MEDIUM |

## Further Considerations

### Testing Approach
- Follow secure-react-app test patterns with @testing-library/react
- Test each vulnerability class independently (script injection, event handler, protocol bypass, etc.)
- Run tests in CI/CD pipeline before merge
- Use @testing-library/react utilities: render(), screen, userEvent
- Test both successful injection attempts (should be blocked) and normal use cases (should work)

### Incremental Deployment
1. Fix CRITICAL vulnerabilities first (1, 2, 3, 4, 7)
2. Validate each fix with security tests before proceeding
3. Deploy to staging for QA before production
4. Communicate changes to users (especially regarding comment HTML stripping)
5. Monitor for issues before moving to next vulnerability class

### Backward Compatibility
- DOMPurify will strip dangerous HTML from existing bios
- Comments stored as plain text will no longer support HTML formatting
- Consider data migration strategy:
  - Option A: Re-sanitize on load (one-time operation)
  - Option B: Batch-clean database records before deployment
  - Option C: Notify users that HTML is no longer supported and suggest re-entering content
- Preserve all valid data (DOMPurify removes tags but keeps text content)

### Dependencies to Add
```json
{
  "dompurify": "^3.0.6",
  "helmet": "^7.1.0"
}
```

### Performance Considerations
- Use React.useMemo() for expensive sanitization operations
- Sanitize once on input, not repeatedly on output
- Consider debouncing user input for large textareas

### Security Headers to Implement (Helmet.js)
```
Content-Security-Policy: script-src 'self'; object-src 'none'; frame-src 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Strict-Transport-Security: max-age=31536000; includeSubDomains
Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()
```

## Next Steps
1. Review and refine this plan with stakeholders
2. Create feature branch for XSS remediation work
3. Implement fixes in priority order (CRITICAL vulnerabilities first)
4. Write and run security tests as you go
5. Get security review before merging
6. Deploy to staging for QA validation
7. Monitor production for issues post-deployment
