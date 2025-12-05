/**
 * Security Middleware Collection
 * ================================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 04 - Security Code Review, Threat Modeling, Auditing
 *
 * Comprehensive security middleware for Express applications.
 */

const crypto = require('crypto');
const { URL } = require('url');

// =============================================================================
// Request ID Middleware
// =============================================================================

/**
 * Add unique request ID for tracing and audit logs
 */
function requestId(req, res, next) {
  req.requestId = crypto.randomUUID();
  res.set('X-Request-ID', req.requestId);
  next();
}

// =============================================================================
// Security Headers Middleware
// =============================================================================

/**
 * Set comprehensive security headers
 */
function securityHeaders(options = {}) {
  const {
    cspDirectives = {},
    hstsMaxAge = 31536000,
    hstsIncludeSubDomains = true,
    hstsPreload = true
  } = options;

  const defaultCsp = {
    'default-src': ["'self'"],
    'script-src': ["'self'"],
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", 'data:', 'https:'],
    'font-src': ["'self'"],
    'connect-src': ["'self'"],
    'frame-ancestors': ["'none'"],
    'form-action': ["'self'"],
    'base-uri': ["'self'"],
    'object-src': ["'none'"]
  };

  const csp = { ...defaultCsp, ...cspDirectives };
  const cspString = Object.entries(csp)
    .map(([key, values]) => `${key} ${values.join(' ')}`)
    .join('; ');

  return (req, res, next) => {
    // Prevent MIME sniffing
    res.set('X-Content-Type-Options', 'nosniff');

    // Prevent clickjacking
    res.set('X-Frame-Options', 'DENY');

    // XSS Protection (legacy, but still useful)
    res.set('X-XSS-Protection', '1; mode=block');

    // Content Security Policy
    res.set('Content-Security-Policy', cspString);

    // HSTS (only in production)
    if (process.env.NODE_ENV === 'production') {
      let hsts = `max-age=${hstsMaxAge}`;
      if (hstsIncludeSubDomains) hsts += '; includeSubDomains';
      if (hstsPreload) hsts += '; preload';
      res.set('Strict-Transport-Security', hsts);
    }

    // Prevent caching of sensitive responses
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');

    // Referrer Policy
    res.set('Referrer-Policy', 'strict-origin-when-cross-origin');

    // Permissions Policy
    res.set('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');

    next();
  };
}

// =============================================================================
// CORS Middleware
// =============================================================================

/**
 * Secure CORS configuration
 */
function secureCors(options = {}) {
  const {
    allowedOrigins = [],
    allowCredentials = false,
    maxAge = 600  // 10 minutes
  } = options;

  return (req, res, next) => {
    const origin = req.get('Origin');

    if (origin && allowedOrigins.includes(origin)) {
      res.set('Access-Control-Allow-Origin', origin);
      res.set('Vary', 'Origin');

      if (allowCredentials) {
        res.set('Access-Control-Allow-Credentials', 'true');
      }

      if (req.method === 'OPTIONS') {
        res.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        res.set('Access-Control-Max-Age', maxAge.toString());
        return res.status(204).end();
      }
    }

    next();
  };
}

// =============================================================================
// Rate Limiting Middleware
// =============================================================================

/**
 * Advanced rate limiting with sliding window
 */
class RateLimiter {
  constructor(options = {}) {
    this.windowMs = options.windowMs || 60000;  // 1 minute
    this.maxRequests = options.maxRequests || 100;
    this.keyGenerator = options.keyGenerator || ((req) => req.ip);
    this.onLimit = options.onLimit || null;
    this.skipSuccessfulRequests = options.skipSuccessfulRequests || false;
    this.skipFailedRequests = options.skipFailedRequests || false;

    this.clients = new Map();

    // Cleanup old entries periodically
    setInterval(() => this.cleanup(), this.windowMs);
  }

  cleanup() {
    const now = Date.now();
    for (const [key, data] of this.clients.entries()) {
      data.requests = data.requests.filter(time => now - time < this.windowMs);
      if (data.requests.length === 0) {
        this.clients.delete(key);
      }
    }
  }

  middleware() {
    return (req, res, next) => {
      const key = this.keyGenerator(req);
      const now = Date.now();

      let clientData = this.clients.get(key);
      if (!clientData) {
        clientData = { requests: [], blocked: false };
        this.clients.set(key, clientData);
      }

      // Clean old requests from this client
      clientData.requests = clientData.requests.filter(time => now - time < this.windowMs);

      // Check limit
      if (clientData.requests.length >= this.maxRequests) {
        if (this.onLimit) {
          this.onLimit(req, res, key);
        }

        res.set('Retry-After', Math.ceil(this.windowMs / 1000));
        res.set('X-RateLimit-Limit', this.maxRequests.toString());
        res.set('X-RateLimit-Remaining', '0');
        res.set('X-RateLimit-Reset', Math.ceil((clientData.requests[0] + this.windowMs) / 1000).toString());

        return res.status(429).json({
          error: 'Too many requests',
          retryAfter: Math.ceil(this.windowMs / 1000)
        });
      }

      // Record request
      clientData.requests.push(now);

      // Set rate limit headers
      res.set('X-RateLimit-Limit', this.maxRequests.toString());
      res.set('X-RateLimit-Remaining', (this.maxRequests - clientData.requests.length).toString());

      // Handle skip options
      res.on('finish', () => {
        if (this.skipSuccessfulRequests && res.statusCode < 400) {
          clientData.requests.pop();
        }
        if (this.skipFailedRequests && res.statusCode >= 400) {
          clientData.requests.pop();
        }
      });

      next();
    };
  }
}

// =============================================================================
// Input Sanitization Middleware
// =============================================================================

/**
 * Sanitize request body, query, and params
 */
function sanitizeInput(options = {}) {
  const {
    stripHtml = true,
    trimStrings = true,
    removeNullBytes = true,
    maxStringLength = 10000
  } = options;

  function sanitizeValue(value) {
    if (typeof value !== 'string') return value;

    let result = value;

    if (removeNullBytes) {
      result = result.replace(/\0/g, '');
    }

    if (stripHtml) {
      result = result.replace(/<[^>]*>/g, '');
    }

    if (trimStrings) {
      result = result.trim();
    }

    if (result.length > maxStringLength) {
      result = result.substring(0, maxStringLength);
    }

    return result;
  }

  function sanitizeObject(obj) {
    if (Array.isArray(obj)) {
      return obj.map(sanitizeValue);
    }

    if (obj && typeof obj === 'object') {
      const sanitized = {};
      for (const [key, value] of Object.entries(obj)) {
        sanitized[sanitizeValue(key)] = typeof value === 'object'
          ? sanitizeObject(value)
          : sanitizeValue(value);
      }
      return sanitized;
    }

    return sanitizeValue(obj);
  }

  return (req, res, next) => {
    if (req.body) req.body = sanitizeObject(req.body);
    if (req.query) req.query = sanitizeObject(req.query);
    if (req.params) req.params = sanitizeObject(req.params);

    next();
  };
}

// =============================================================================
// CSRF Protection Middleware
// =============================================================================

/**
 * CSRF token generation and validation
 */
class CsrfProtection {
  constructor(options = {}) {
    this.secret = options.secret || crypto.randomBytes(32).toString('hex');
    this.tokenLength = options.tokenLength || 32;
    this.cookieName = options.cookieName || '_csrf';
    this.headerName = options.headerName || 'x-csrf-token';
  }

  generateToken(req) {
    const salt = crypto.randomBytes(8).toString('hex');
    const token = crypto.createHmac('sha256', this.secret)
      .update(salt + req.session?.id || req.ip)
      .digest('hex');

    return `${salt}.${token}`;
  }

  validateToken(req, token) {
    if (!token || !token.includes('.')) return false;

    const [salt, hash] = token.split('.');
    const expected = crypto.createHmac('sha256', this.secret)
      .update(salt + req.session?.id || req.ip)
      .digest('hex');

    return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(expected));
  }

  middleware() {
    return (req, res, next) => {
      // Generate token and attach to request
      req.csrfToken = () => this.generateToken(req);

      // Skip validation for safe methods
      if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
      }

      // Get token from header or body
      const token = req.get(this.headerName) ||
                   req.body?._csrf ||
                   req.query?._csrf;

      if (!this.validateToken(req, token)) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
      }

      next();
    };
  }
}

// =============================================================================
// IP Filtering Middleware
// =============================================================================

/**
 * IP whitelist/blacklist filtering
 */
function ipFilter(options = {}) {
  const {
    whitelist = [],
    blacklist = [],
    mode = 'blacklist'  // 'whitelist' or 'blacklist'
  } = options;

  function normalizeIp(ip) {
    // Handle IPv6-mapped IPv4 addresses
    if (ip.startsWith('::ffff:')) {
      return ip.substring(7);
    }
    return ip;
  }

  function matchesCidr(ip, cidr) {
    // Simplified CIDR matching (production should use proper library)
    if (!cidr.includes('/')) {
      return ip === cidr;
    }

    const [range, bits] = cidr.split('/');
    // Full implementation would compare binary representations
    return ip.startsWith(range.split('.').slice(0, 3).join('.'));
  }

  return (req, res, next) => {
    const ip = normalizeIp(req.ip);

    // Check blacklist
    if (blacklist.some(blocked => matchesCidr(ip, blocked))) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Check whitelist (if in whitelist mode)
    if (mode === 'whitelist') {
      if (!whitelist.some(allowed => matchesCidr(ip, allowed))) {
        return res.status(403).json({ error: 'Access denied' });
      }
    }

    next();
  };
}

// =============================================================================
// Request Logging Middleware
// =============================================================================

/**
 * Security-focused request logging
 */
function securityLogger(options = {}) {
  const {
    logBody = false,
    maskFields = ['password', 'token', 'secret', 'authorization'],
    logger = console
  } = options;

  function maskSensitive(obj) {
    if (!obj || typeof obj !== 'object') return obj;

    const masked = {};
    for (const [key, value] of Object.entries(obj)) {
      if (maskFields.some(field => key.toLowerCase().includes(field))) {
        masked[key] = '[REDACTED]';
      } else if (typeof value === 'object') {
        masked[key] = maskSensitive(value);
      } else {
        masked[key] = value;
      }
    }
    return masked;
  }

  return (req, res, next) => {
    const startTime = Date.now();

    res.on('finish', () => {
      const logEntry = {
        timestamp: new Date().toISOString(),
        requestId: req.requestId,
        method: req.method,
        path: req.path,
        query: maskSensitive(req.query),
        statusCode: res.statusCode,
        duration: Date.now() - startTime,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId: req.user?.id
      };

      if (logBody && req.body) {
        logEntry.body = maskSensitive(req.body);
      }

      // Log security-relevant events at appropriate level
      if (res.statusCode >= 500) {
        logger.error(JSON.stringify(logEntry));
      } else if (res.statusCode >= 400) {
        logger.warn(JSON.stringify(logEntry));
      } else {
        logger.info(JSON.stringify(logEntry));
      }
    });

    next();
  };
}

// =============================================================================
// Export
// =============================================================================

module.exports = {
  requestId,
  securityHeaders,
  secureCors,
  RateLimiter,
  sanitizeInput,
  CsrfProtection,
  ipFilter,
  securityLogger
};
