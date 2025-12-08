/**
 * DELIBERATELY VULNERABLE AUTHENTICATION MIDDLEWARE
 *
 * This middleware contains INTENTIONAL security vulnerabilities for educational purposes.
 *
 * Vulnerabilities:
 * - CWE-327: JWT algorithm confusion (doesn't restrict algorithms)
 * - CWE-613: Missing token expiration check
 * - CWE-639: Trusts JWT payload for authorization without database validation
 */

const jwt = require('jsonwebtoken');

// Import the hardcoded secret from server.js
const JWT_SECRET = 'super-secret-key-12345';

/**
 * Authentication middleware - validates JWT token
 * VULNERABILITY: Doesn't restrict JWT algorithms, allowing HS256/RS256 confusion
 */
function authenticate(req, res, next) {
  try {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({
        success: false,
        error: 'No authorization header provided'
      });
    }

    // Extract bearer token
    const token = authHeader.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'No token provided'
      });
    }

    // VULNERABILITY 1: JWT verification doesn't restrict algorithms (CWE-327)
    // vuln-code-snippet start algorithmConfusion
    const decoded = jwt.verify(token, JWT_SECRET);
    // Should specify: { algorithms: ['HS256'] }
    // Without this, an attacker can use RS256 with the public key as HMAC secret
    // vuln-code-snippet end algorithmConfusion

    // VULNERABILITY 2: No expiration check (CWE-613)
    // vuln-code-snippet start noExpirationCheck
    // Even if token has 'exp' claim, we're not checking if it's expired
    // Tokens can be used forever!
    if (!decoded.exp) {
      console.warn('WARNING: Token has no expiration!');
      // We log it but don't reject it - vulnerability!
    }
    // vuln-code-snippet end noExpirationCheck

    // VULNERABILITY 3: Trust JWT payload without database validation (CWE-639)
    // vuln-code-snippet start trustJWTPayload
    // We're trusting the role in the JWT without checking the database
    // An attacker can create their own JWT with role='admin'
    req.user = {
      userId: decoded.userId,
      username: decoded.username,
      role: decoded.role  // This should be validated against the database!
    };
    // vuln-code-snippet end trustJWTPayload

    next();

  } catch (error) {
    // VULNERABILITY 4: Information disclosure in error messages (CWE-209)
    // vuln-code-snippet start jwtErrorDisclosure
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        error: 'Invalid token',
        details: error.message,  // Leaks JWT internals!
        tokenProvided: req.headers.authorization  // Leaks the actual token!
      });
    }
    // vuln-code-snippet end jwtErrorDisclosure

    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        error: 'Token expired',
        expiredAt: error.expiredAt,
        details: error.message
      });
    }

    return res.status(401).json({
      success: false,
      error: 'Authentication failed',
      details: error.message,
      stack: error.stack  // Major information disclosure!
    });
  }
}

/**
 * Admin authorization middleware - checks if user has admin role
 * VULNERABILITY: Trusts the role from JWT payload without database validation
 */
function requireAdmin(req, res, next) {
  // VULNERABILITY 5: Authorization bypass (CWE-639)
  // vuln-code-snippet start adminBypass
  if (req.user.role !== 'admin') {
    return res.status(403).json({
      success: false,
      error: 'Access denied. Admin role required.',
      yourRole: req.user.role,  // Information disclosure
      requiredRole: 'admin'     // Information disclosure
    });
  }
  // This check is insufficient because req.user.role comes from the JWT
  // which the attacker controls. We should verify against the database!
  // vuln-code-snippet end adminBypass

  next();
}

/**
 * SECURE IMPLEMENTATION EXAMPLE (commented out)
 *
 * This is how the middleware SHOULD be implemented:
 */
/*
async function authenticateSecure(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const token = authHeader.substring(7);

    // FIX 1: Restrict allowed algorithms
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],  // Only allow HMAC with SHA-256
      maxAge: '1h'            // Enforce maximum token age
    });

    // FIX 2: Validate against database
    const user = await db.collection('users').findOne({
      _id: decoded.userId
    });

    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // FIX 3: Use database role, not JWT role
    req.user = {
      userId: user._id,
      username: user.username,
      role: user.role  // From database, not JWT!
    };

    next();

  } catch (error) {
    // FIX 4: Generic error message (no information disclosure)
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

async function requireAdminSecure(req, res, next) {
  // FIX 5: Verify role from database
  const user = await db.collection('users').findOne({
    _id: req.user.userId
  });

  if (!user || user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  next();
}
*/

module.exports = {
  authenticate,
  requireAdmin
};
