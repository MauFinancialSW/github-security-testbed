const crypto = require('crypto');

class AuthError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'AuthError';
    this.code = code;
  }
}

const accessTokens = new Map();
const refreshTokens = new Map();
const failedLogins = new Map();

function randomToken() {
  return crypto.randomBytes(32).toString('hex');
}

function normalizeScope(scope) {
  if (!scope) {
    return [];
  }
  if (Array.isArray(scope)) {
    return scope;
  }
  return String(scope)
    .split(/\s+/)
    .filter(Boolean);
}

function issueAccessToken({ userId, scope = [], expiresInSeconds = 900 }) {
  const token = randomToken();
  const exp = Date.now() + expiresInSeconds * 1000;
  accessTokens.set(token, {
    userId,
    scope: normalizeScope(scope),
    exp,
    revoked: false
  });
  return { token, exp };
}

function invalidateAccessToken(token) {
  const entry = accessTokens.get(token);
  if (entry) {
    entry.revoked = true;
  }
}

function validateAccessToken(token, requiredScope) {
  const entry = accessTokens.get(token);
  if (!entry || entry.revoked) {
    throw new AuthError('token_revoked', 'Access token has been revoked or is unknown');
  }
  if (entry.exp <= Date.now()) {
    entry.revoked = true;
    throw new AuthError('token_expired', 'Access token has expired');
  }
  if (requiredScope && !entry.scope.includes(requiredScope)) {
    throw new AuthError('insufficient_scope', 'Access token lacks required scope');
  }
  return entry;
}

function createRefreshToken(userId) {
  const token = randomToken();
  refreshTokens.set(token, {
    userId,
    active: true,
    createdAt: Date.now()
  });
  return token;
}

function rotateRefreshToken(oldToken) {
  const entry = refreshTokens.get(oldToken);
  if (!entry || !entry.active) {
    throw new AuthError('invalid_grant', 'Refresh token is invalid or has already been rotated');
  }

  entry.active = false;
  const newToken = randomToken();
  refreshTokens.set(newToken, {
    userId: entry.userId,
    active: true,
    rotatedFrom: oldToken,
    createdAt: Date.now()
  });
  return newToken;
}

function validateRefreshToken(token) {
  const entry = refreshTokens.get(token);
  if (!entry || !entry.active) {
    throw new AuthError('invalid_grant', 'Refresh token is invalid or inactive');
  }
  return entry;
}

function recordFailedLogin(subject, { limit = 5, windowMs = 60_000, lockoutMs = 300_000 } = {}) {
  const now = Date.now();
  const entry = failedLogins.get(subject) || {
    count: 0,
    firstFailure: now,
    lockedUntil: 0
  };

  if (entry.lockedUntil > now) {
    failedLogins.set(subject, entry);
    return { ...entry };
  }

  if (now - entry.firstFailure > windowMs) {
    entry.count = 0;
    entry.firstFailure = now;
    entry.lockedUntil = 0;
  }

  entry.count += 1;
  if (entry.count >= limit) {
    entry.lockedUntil = now + lockoutMs;
  }

  failedLogins.set(subject, entry);
  return { ...entry };
}

function isLockedOut(subject) {
  const entry = failedLogins.get(subject);
  if (!entry) {
    return false;
  }
  if (entry.lockedUntil <= Date.now()) {
    if (entry.lockedUntil > 0) {
      failedLogins.set(subject, {
        count: 0,
        firstFailure: Date.now(),
        lockedUntil: 0
      });
    }
    return false;
  }
  return true;
}

function resetFailedLogins(subject) {
  if (subject) {
    failedLogins.delete(subject);
  } else {
    failedLogins.clear();
  }
}

function resetAuthState() {
  accessTokens.clear();
  refreshTokens.clear();
  failedLogins.clear();
}

module.exports = {
  AuthError,
  issueAccessToken,
  invalidateAccessToken,
  validateAccessToken,
  createRefreshToken,
  rotateRefreshToken,
  validateRefreshToken,
  recordFailedLogin,
  isLockedOut,
  resetFailedLogins,
  resetAuthState
};
