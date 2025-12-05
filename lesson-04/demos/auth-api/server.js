/**
 * Authentication API - Security Code Review Demo
 * ================================================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 04 - Security Code Review, Threat Modeling, Auditing
 *
 * This API demonstrates security best practices for authentication.
 * Use with Copilot for code review and security analysis.
 *
 * Security Features:
 * - Rate limiting with exponential backoff
 * - Account lockout protection
 * - Secure session management
 * - Input validation and sanitization
 * - Comprehensive audit logging
 */

const express = require('express');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();

// =============================================================================
// Security Middleware
// =============================================================================

app.use(helmet());
app.use(express.json({ limit: '10kb' }));  // Prevent large payload attacks

// Rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,  // 5 attempts per window
  message: { error: 'Too many login attempts. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res, next, options) => {
    auditLog('RATE_LIMIT', req.ip, { path: req.path });
    res.status(429).json(options.message);
  }
});

// =============================================================================
// In-Memory Storage (Use database in production)
// =============================================================================

const users = new Map();
const sessions = new Map();
const loginAttempts = new Map();
const auditLogs = [];

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Audit logging for security events
 */
function auditLog(event, actor, details = {}) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    event,
    actor,
    details,
    requestId: crypto.randomUUID()
  };

  auditLogs.push(logEntry);
  console.log(`[AUDIT] ${JSON.stringify(logEntry)}`);

  return logEntry;
}

/**
 * Hash password with salt using Argon2 parameters
 * (Simplified - use argon2 package in production)
 */
async function hashPassword(password) {
  const salt = crypto.randomBytes(32);
  const hash = crypto.pbkdf2Sync(password, salt, 600000, 64, 'sha512');

  return {
    hash: hash.toString('hex'),
    salt: salt.toString('hex')
  };
}

/**
 * Verify password against stored hash
 */
async function verifyPassword(password, storedHash, storedSalt) {
  const salt = Buffer.from(storedSalt, 'hex');
  const hash = crypto.pbkdf2Sync(password, salt, 600000, 64, 'sha512');

  return crypto.timingSafeEqual(
    Buffer.from(hash.toString('hex')),
    Buffer.from(storedHash)
  );
}

/**
 * Generate secure session token
 */
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Check account lockout status
 */
function isAccountLocked(userId) {
  const attempts = loginAttempts.get(userId);
  if (!attempts) return false;

  // Lock after 5 failed attempts
  if (attempts.count >= 5) {
    const lockDuration = Math.min(Math.pow(2, attempts.count - 5) * 60000, 3600000);  // Max 1 hour
    const lockExpiry = attempts.lastAttempt + lockDuration;

    if (Date.now() < lockExpiry) {
      return {
        locked: true,
        remainingMs: lockExpiry - Date.now()
      };
    } else {
      // Lock expired, reset
      loginAttempts.delete(userId);
      return false;
    }
  }

  return false;
}

/**
 * Record failed login attempt
 */
function recordFailedAttempt(userId) {
  const attempts = loginAttempts.get(userId) || { count: 0, lastAttempt: 0 };
  attempts.count++;
  attempts.lastAttempt = Date.now();
  loginAttempts.set(userId, attempts);

  return attempts;
}

/**
 * Clear failed attempts on successful login
 */
function clearFailedAttempts(userId) {
  loginAttempts.delete(userId);
}

// =============================================================================
// Input Validation
// =============================================================================

const registerValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email required'),
  body('password')
    .isLength({ min: 12 })
    .withMessage('Password must be at least 12 characters')
    .matches(/[A-Z]/)
    .withMessage('Password must contain uppercase letter')
    .matches(/[a-z]/)
    .withMessage('Password must contain lowercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain number')
    .matches(/[^A-Za-z0-9]/)
    .withMessage('Password must contain special character'),
  body('name')
    .trim()
    .isLength({ min: 1, max: 100 })
    .escape()
    .withMessage('Name is required (max 100 chars)')
];

const loginValidation = [
  body('email')
    .isEmail()
    .normalizeEmail(),
  body('password')
    .isLength({ min: 1 })
];

// =============================================================================
// Routes
// =============================================================================

/**
 * User Registration
 * POST /register
 */
app.post('/register', registerValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    auditLog('REGISTER_VALIDATION_FAILED', req.ip, { errors: errors.array() });
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password, name } = req.body;

  // Check if user exists
  if (users.has(email)) {
    // Don't reveal if email exists (timing-safe response)
    auditLog('REGISTER_EMAIL_EXISTS', req.ip, { email: email.substring(0, 3) + '***' });
    // Simulate processing time to prevent timing attacks
    await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 100));
    return res.status(201).json({ message: 'Registration successful. Check email for verification.' });
  }

  // Hash password
  const { hash, salt } = await hashPassword(password);

  // Store user
  const userId = crypto.randomUUID();
  users.set(email, {
    id: userId,
    email,
    name,
    passwordHash: hash,
    passwordSalt: salt,
    createdAt: new Date().toISOString(),
    emailVerified: false,
    mfaEnabled: false
  });

  auditLog('USER_REGISTERED', email, { userId });

  res.status(201).json({
    message: 'Registration successful. Check email for verification.',
    userId
  });
});

/**
 * User Login
 * POST /login
 */
app.post('/login', loginLimiter, loginValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const { email, password } = req.body;
  const user = users.get(email);

  // Check lockout first
  if (user) {
    const lockStatus = isAccountLocked(user.id);
    if (lockStatus.locked) {
      auditLog('LOGIN_ACCOUNT_LOCKED', req.ip, { email: email.substring(0, 3) + '***' });
      return res.status(429).json({
        error: 'Account temporarily locked',
        retryAfter: Math.ceil(lockStatus.remainingMs / 1000)
      });
    }
  }

  // Verify credentials (constant time)
  let valid = false;
  if (user) {
    valid = await verifyPassword(password, user.passwordHash, user.passwordSalt);
  } else {
    // Simulate verification to prevent timing attacks
    await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 100));
  }

  if (!valid) {
    if (user) {
      const attempts = recordFailedAttempt(user.id);
      auditLog('LOGIN_FAILED', req.ip, {
        email: email.substring(0, 3) + '***',
        attemptCount: attempts.count
      });
    } else {
      auditLog('LOGIN_INVALID_EMAIL', req.ip, {});
    }
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Clear failed attempts
  clearFailedAttempts(user.id);

  // Create session
  const sessionToken = generateSessionToken();
  const session = {
    userId: user.id,
    email: user.email,
    createdAt: Date.now(),
    expiresAt: Date.now() + (15 * 60 * 1000),  // 15 minutes
    userAgent: req.get('User-Agent'),
    ipAddress: req.ip
  };

  sessions.set(sessionToken, session);

  auditLog('LOGIN_SUCCESS', user.email, {
    userId: user.id,
    sessionCreated: true
  });

  res.json({
    message: 'Login successful',
    token: sessionToken,
    expiresIn: 900
  });
});

/**
 * Session Validation Middleware
 */
function requireAuth(req, res, next) {
  const authHeader = req.get('Authorization');

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const token = authHeader.substring(7);
  const session = sessions.get(token);

  if (!session) {
    auditLog('INVALID_SESSION', req.ip, {});
    return res.status(401).json({ error: 'Invalid session' });
  }

  if (Date.now() > session.expiresAt) {
    sessions.delete(token);
    auditLog('SESSION_EXPIRED', req.ip, { userId: session.userId });
    return res.status(401).json({ error: 'Session expired' });
  }

  // Validate session binding (IP and User-Agent)
  if (session.ipAddress !== req.ip) {
    auditLog('SESSION_IP_MISMATCH', req.ip, {
      userId: session.userId,
      originalIp: session.ipAddress
    });
    // Could choose to invalidate or just warn
  }

  req.session = session;
  req.user = users.get(session.email);
  next();
}

/**
 * Get Current User
 * GET /me
 */
app.get('/me', requireAuth, (req, res) => {
  res.json({
    id: req.user.id,
    email: req.user.email,
    name: req.user.name,
    emailVerified: req.user.emailVerified,
    mfaEnabled: req.user.mfaEnabled
  });
});

/**
 * Logout
 * POST /logout
 */
app.post('/logout', requireAuth, (req, res) => {
  const authHeader = req.get('Authorization');
  const token = authHeader.substring(7);

  sessions.delete(token);
  auditLog('LOGOUT', req.user.email, { userId: req.user.id });

  res.json({ message: 'Logged out successfully' });
});

/**
 * Logout All Sessions
 * POST /logout-all
 */
app.post('/logout-all', requireAuth, (req, res) => {
  const userId = req.user.id;
  let count = 0;

  for (const [token, session] of sessions.entries()) {
    if (session.userId === userId) {
      sessions.delete(token);
      count++;
    }
  }

  auditLog('LOGOUT_ALL', req.user.email, { sessionsRevoked: count });

  res.json({ message: `Logged out from ${count} sessions` });
});

/**
 * Change Password
 * POST /change-password
 */
app.post('/change-password', requireAuth, [
  body('currentPassword').isLength({ min: 1 }),
  body('newPassword')
    .isLength({ min: 12 })
    .matches(/[A-Z]/)
    .matches(/[a-z]/)
    .matches(/[0-9]/)
    .matches(/[^A-Za-z0-9]/)
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { currentPassword, newPassword } = req.body;
  const user = req.user;

  // Verify current password
  const valid = await verifyPassword(currentPassword, user.passwordHash, user.passwordSalt);
  if (!valid) {
    auditLog('PASSWORD_CHANGE_FAILED', user.email, { reason: 'invalid_current' });
    return res.status(401).json({ error: 'Current password is incorrect' });
  }

  // Hash new password
  const { hash, salt } = await hashPassword(newPassword);
  user.passwordHash = hash;
  user.passwordSalt = salt;

  // Invalidate all other sessions
  for (const [token, session] of sessions.entries()) {
    if (session.userId === user.id && token !== req.get('Authorization').substring(7)) {
      sessions.delete(token);
    }
  }

  auditLog('PASSWORD_CHANGED', user.email, { userId: user.id });

  res.json({ message: 'Password changed successfully' });
});

/**
 * Get Audit Logs (Admin only - simplified)
 * GET /audit-logs
 */
app.get('/audit-logs', requireAuth, (req, res) => {
  // In production: Check for admin role
  const recentLogs = auditLogs.slice(-100);
  res.json(recentLogs);
});

// =============================================================================
// Error Handling
// =============================================================================

app.use((err, req, res, next) => {
  auditLog('SERVER_ERROR', req.ip, {
    error: err.message,
    path: req.path
  });

  res.status(500).json({ error: 'Internal server error' });
});

// =============================================================================
// Server
// =============================================================================

const PORT = process.env.PORT || 3000;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Auth API running on port ${PORT}`);
  });
}

module.exports = app;
