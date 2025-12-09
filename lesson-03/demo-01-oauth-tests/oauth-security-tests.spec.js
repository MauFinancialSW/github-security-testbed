const {
  AuthError,
  issueAccessToken,
  validateAccessToken,
  createRefreshToken,
  rotateRefreshToken,
  validateRefreshToken,
  recordFailedLogin,
  isLockedOut,
  resetAuthState
} = require('./src/auth');

function expectAuthError(executable, code) {
  try {
    executable();
  } catch (error) {
    expect(error).toBeInstanceOf(AuthError);
    expect(error.code).toBe(code);
    return;
  }
  throw new Error('Expected AuthError to be thrown');
}

beforeEach(() => {
  resetAuthState();
  jest.useRealTimers();
});

describe('Expired Access Tokens', () => {
  test('rejects tokens that have passed their expiry', () => {
    const { token } = issueAccessToken({
      userId: 'user-123',
      scope: ['openid'],
      expiresInSeconds: -5
    });

    expectAuthError(() => validateAccessToken(token, 'openid'), 'token_expired');
  });
});

describe('Refresh Token Abuse', () => {
  test('rotates refresh tokens and deactivates the old token', () => {
    const originalToken = createRefreshToken('user-123');
    const rotatedToken = rotateRefreshToken(originalToken);

    expect(rotatedToken).not.toBe(originalToken);
    expect(() => validateRefreshToken(rotatedToken)).not.toThrow();

    expectAuthError(() => validateRefreshToken(originalToken), 'invalid_grant');
  });

  test('rejects reuse attempts with inactive refresh tokens', () => {
    const originalToken = createRefreshToken('user-abc');
    rotateRefreshToken(originalToken);

    expectAuthError(() => rotateRefreshToken(originalToken), 'invalid_grant');
  });
});

describe('Brute Force Logins', () => {
  test('locks out clients after repeated failures within the risk window', () => {
    jest.useFakeTimers();
    const baseTime = new Date('2025-01-01T00:00:00Z');
    jest.setSystemTime(baseTime);

    for (let attempt = 0; attempt < 5; attempt += 1) {
      recordFailedLogin('client-app');
    }

    expect(isLockedOut('client-app')).toBe(true);

    // Advance beyond the lockout duration to ensure the lock eventually clears.
    jest.setSystemTime(new Date(baseTime.getTime() + 5 * 60 * 1000 + 1000));
    expect(isLockedOut('client-app')).toBe(false);
  });
});

describe('Scope Misuse', () => {
  test('rejects tokens that are missing the required scope', () => {
    const { token } = issueAccessToken({
      userId: 'auditor-1',
      scope: ['openid', 'profile'],
      expiresInSeconds: 300
    });

    expectAuthError(() => validateAccessToken(token, 'admin'), 'insufficient_scope');
  });
});
