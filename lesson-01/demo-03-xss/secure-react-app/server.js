/**
 * Express Server with Security Headers
 * =====================================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 01 - Vulnerability Detection
 *
 * This server demonstrates Content Security Policy (CSP) and other
 * security headers to provide defense-in-depth against XSS attacks.
 *
 * Key Security Features:
 * 1. Content Security Policy (CSP)
 * 2. X-Content-Type-Options
 * 3. X-Frame-Options
 * 4. X-XSS-Protection (legacy)
 * 5. Referrer-Policy
 * 6. Permissions-Policy
 */

const express = require('express');
const helmet = require('helmet');
const path = require('path');

const app = express();

// =============================================================================
// SECURITY: Configure Helmet with strict CSP
// =============================================================================
//
// Copilot Chat Prompt:
// "Generate Content Security Policy headers for a React application.
//  Include script-src, style-src, img-src directives. Block inline
//  JavaScript execution. Explain each directive."
//
app.use(
  helmet({
    // Content Security Policy - Primary XSS defense
    contentSecurityPolicy: {
      directives: {
        // Default policy for unspecified resource types
        defaultSrc: ["'self'"],

        // JavaScript execution sources
        // 'self' = same origin only
        // 'unsafe-inline' removed for security (use nonces in production)
        scriptSrc: [
          "'self'",
          // In production, use nonces instead of 'unsafe-inline':
          // "'nonce-{random}'",
        ],

        // Stylesheet sources
        styleSrc: [
          "'self'",
          "'unsafe-inline'",  // Required for styled-components/emotion
          "https://fonts.googleapis.com"
        ],

        // Image sources
        imgSrc: [
          "'self'",
          "data:",  // Allow data: URLs for inline images
          "https:",  // Allow HTTPS images
        ],

        // Font sources
        fontSrc: [
          "'self'",
          "https://fonts.gstatic.com"
        ],

        // AJAX/fetch/WebSocket connections
        connectSrc: [
          "'self'",
          "https://api.example.com"  // Your API domain
        ],

        // Frame sources (embedded content)
        frameSrc: ["'none'"],  // Block all iframes

        // Object/embed sources
        objectSrc: ["'none'"],  // Block plugins

        // Media sources (audio/video)
        mediaSrc: ["'self'"],

        // Form action destinations
        formAction: ["'self'"],

        // Frame ancestors (who can embed this page)
        frameAncestors: ["'none'"],  // Prevent clickjacking

        // Base URI restriction
        baseUri: ["'self'"],

        // Upgrade insecure requests
        upgradeInsecureRequests: [],

        // Block mixed content
        blockAllMixedContent: [],

        // Report violations (configure reporting endpoint)
        // reportUri: '/csp-violation-report',
      },
      // Report-only mode for testing (doesn't block, just reports)
      reportOnly: false,
    },

    // Prevent MIME type sniffing
    xContentTypeOptions: true,  // X-Content-Type-Options: nosniff

    // Clickjacking protection
    frameguard: {
      action: 'deny'  // X-Frame-Options: DENY
    },

    // Legacy XSS protection (for older browsers)
    xssFilter: true,  // X-XSS-Protection: 1; mode=block

    // Referrer policy
    referrerPolicy: {
      policy: 'strict-origin-when-cross-origin'
    },

    // HSTS (HTTP Strict Transport Security)
    hsts: {
      maxAge: 31536000,  // 1 year
      includeSubDomains: true,
      preload: true
    },

    // Don't advertise powered-by
    hidePoweredBy: true,

    // DNS prefetch control
    dnsPrefetchControl: {
      allow: false
    },

    // IE no-open
    ieNoOpen: true,

    // Permitted cross-domain policies
    permittedCrossDomainPolicies: {
      permittedPolicies: 'none'
    }
  })
);

// =============================================================================
// Additional Security Headers (Permissions-Policy)
// =============================================================================
app.use((req, res, next) => {
  // Permissions-Policy (formerly Feature-Policy)
  // Restrict access to browser features
  res.setHeader(
    'Permissions-Policy',
    [
      'accelerometer=()',
      'camera=()',
      'geolocation=()',
      'gyroscope=()',
      'magnetometer=()',
      'microphone=()',
      'payment=()',
      'usb=()',
      'interest-cohort=()'  // Opt out of FLoC
    ].join(', ')
  );

  // Cross-Origin policies
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');

  next();
});

// =============================================================================
// CSP Violation Reporting Endpoint
// =============================================================================
app.use(express.json({ type: 'application/csp-report' }));

app.post('/csp-violation-report', (req, res) => {
  const violation = req.body['csp-report'];

  if (violation) {
    console.warn('CSP Violation:', {
      documentUri: violation['document-uri'],
      blockedUri: violation['blocked-uri'],
      violatedDirective: violation['violated-directive'],
      originalPolicy: violation['original-policy'],
      timestamp: new Date().toISOString()
    });

    // In production, send to logging/monitoring service
  }

  res.status(204).end();
});

// =============================================================================
// Serve Static React Build
// =============================================================================
app.use(express.static(path.join(__dirname, 'build'), {
  // Additional static file security
  setHeaders: (res, filePath) => {
    // Cache control for static assets
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    } else if (filePath.match(/\.(js|css|png|jpg|gif|ico|woff|woff2)$/)) {
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    }
  }
}));

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'build', 'index.html'));
});

// =============================================================================
// Security Information Endpoint
// =============================================================================
app.get('/security-headers', (req, res) => {
  res.json({
    message: 'Security headers are configured',
    headers: {
      'Content-Security-Policy': 'Configured via Helmet',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'Configured (various features disabled)'
    },
    documentation: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Secure server running on port ${PORT}`);
  console.log('Security headers configured:');
  console.log('  - Content-Security-Policy');
  console.log('  - X-Content-Type-Options');
  console.log('  - X-Frame-Options');
  console.log('  - Strict-Transport-Security');
  console.log('  - Referrer-Policy');
  console.log('  - Permissions-Policy');
});

module.exports = app;

/**
 * CSP Directive Reference:
 * ========================
 *
 * default-src: Fallback for unspecified directives
 * script-src:  JavaScript sources
 * style-src:   CSS sources
 * img-src:     Image sources
 * font-src:    Font file sources
 * connect-src: AJAX, WebSocket, EventSource
 * frame-src:   iframe sources
 * object-src:  Plugin sources (<object>, <embed>)
 * media-src:   Audio/video sources
 * form-action: Form submission destinations
 * base-uri:    <base> element URLs
 * frame-ancestors: Who can embed this page (clickjacking prevention)
 *
 * Source Keywords:
 * 'self':           Same origin
 * 'none':           Block all
 * 'unsafe-inline':  Allow inline scripts/styles (avoid if possible)
 * 'unsafe-eval':    Allow eval() (avoid)
 * 'nonce-{value}':  Allow specific inline scripts with nonce
 * 'sha256-{hash}':  Allow specific inline scripts by hash
 */
