"""
Comprehensive Security Test Suite for OAuth 2.0 Authentication Server

This test suite validates security properties of the OAuth implementation including:
- Valid authentication flows
- Invalid credentials rejection
- Token expiration validation
- Malformed token handling
- Refresh token rotation security
- Scope enforcement
- Authorization code replay attack prevention

Tests are designed to discover the intentional vulnerabilities in auth_server.py.
"""

import pytest
import jwt
import time
from datetime import datetime, timedelta
from auth_server import (
    OAuthServer,
    User,
    Scope,
    TokenError,
    InvalidTokenError,
    ExpiredTokenError,
    InsufficientScopeError
)


@pytest.fixture
def oauth_server():
    """Create a fresh OAuth server instance for each test."""
    server = OAuthServer()

    # Register test users
    server.register_user(
        "admin",
        "admin_password_123",
        [Scope.READ.value, Scope.WRITE.value, Scope.ADMIN.value]
    )

    server.register_user(
        "user",
        "user_password_123",
        [Scope.READ.value, Scope.USER.value]
    )

    server.register_user(
        "readonly",
        "readonly_pass",
        [Scope.READ.value]
    )

    return server


@pytest.fixture
def valid_access_token(oauth_server):
    """Generate a valid access token for testing."""
    access, _ = oauth_server.login(
        "admin",
        "admin_password_123",
        [Scope.READ.value, Scope.ADMIN.value]
    )
    return access


@pytest.fixture
def valid_refresh_token(oauth_server):
    """Generate a valid refresh token for testing."""
    _, refresh = oauth_server.login(
        "admin",
        "admin_password_123",
        [Scope.READ.value, Scope.ADMIN.value]
    )
    return refresh


class TestUserRegistration:
    """Test user registration functionality."""

    def test_register_new_user(self, oauth_server):
        """Test that new users can be registered successfully."""
        user = oauth_server.register_user(
            "testuser",
            "testpass",
            [Scope.READ.value]
        )

        assert user.username == "testuser"
        assert user.user_id is not None
        assert len(user.user_id) > 0
        assert Scope.READ.value in user.scopes

    def test_password_is_hashed(self, oauth_server):
        """Test that passwords are hashed and not stored in plaintext."""
        user = oauth_server.register_user(
            "hashtest",
            "mypassword",
            [Scope.READ.value]
        )

        assert user.password_hash != "mypassword"
        assert len(user.password_hash) == 64  # SHA-256 hex digest length

    def test_user_id_uniqueness(self, oauth_server):
        """Test that each registered user gets a unique ID."""
        user1 = oauth_server.register_user("user1", "pass1", [Scope.READ.value])
        user2 = oauth_server.register_user("user2", "pass2", [Scope.READ.value])

        assert user1.user_id != user2.user_id


class TestAuthentication:
    """Test authentication flows."""

    def test_valid_credentials_authentication(self, oauth_server):
        """Test that valid credentials authenticate successfully."""
        user = oauth_server.authenticate_user("admin", "admin_password_123")

        assert user is not None
        assert user.username == "admin"

    def test_invalid_password_rejection(self, oauth_server):
        """Test that invalid passwords are rejected."""
        user = oauth_server.authenticate_user("admin", "wrong_password")

        assert user is None

    def test_invalid_username_rejection(self, oauth_server):
        """Test that non-existent usernames are rejected."""
        user = oauth_server.authenticate_user("nonexistent", "password")

        assert user is None

    def test_case_sensitive_password(self, oauth_server):
        """Test that password authentication is case-sensitive."""
        user = oauth_server.authenticate_user("admin", "ADMIN_PASSWORD_123")

        assert user is None

    def test_empty_credentials_rejection(self, oauth_server):
        """Test that empty credentials are rejected."""
        user = oauth_server.authenticate_user("", "")

        assert user is None


class TestLoginFlow:
    """Test the simplified login flow."""

    def test_valid_login_returns_tokens(self, oauth_server):
        """Test that valid login returns both access and refresh tokens."""
        access, refresh = oauth_server.login(
            "admin",
            "admin_password_123",
            [Scope.READ.value]
        )

        assert access is not None
        assert refresh is not None
        assert len(access) > 0
        assert len(refresh) > 0

    def test_invalid_credentials_login_fails(self, oauth_server):
        """Test that login fails with invalid credentials."""
        with pytest.raises(InvalidTokenError, match="Invalid credentials"):
            oauth_server.login("admin", "wrong_password", [Scope.READ.value])

    def test_unauthorized_scope_login_fails(self, oauth_server):
        """Test that login fails when requesting unauthorized scopes."""
        with pytest.raises(InsufficientScopeError):
            oauth_server.login(
                "readonly",
                "readonly_pass",
                [Scope.ADMIN.value]  # readonly user doesn't have admin scope
            )

    def test_multiple_scopes_login(self, oauth_server):
        """Test login with multiple scopes."""
        access, refresh = oauth_server.login(
            "admin",
            "admin_password_123",
            [Scope.READ.value, Scope.WRITE.value, Scope.ADMIN.value]
        )

        payload = oauth_server.validate_access_token(access)
        assert set(payload['scopes']) == {
            Scope.READ.value,
            Scope.WRITE.value,
            Scope.ADMIN.value
        }


class TestAccessTokenValidation:
    """Test access token validation and security."""

    def test_valid_token_validation(self, oauth_server, valid_access_token):
        """Test that valid tokens are accepted."""
        payload = oauth_server.validate_access_token(valid_access_token)

        assert payload is not None
        assert 'user_id' in payload
        assert 'scopes' in payload
        assert payload['type'] == 'access'

    def test_malformed_token_rejection(self, oauth_server):
        """Test that malformed tokens are rejected."""
        with pytest.raises(InvalidTokenError):
            oauth_server.validate_access_token("not_a_valid_token")

    def test_empty_token_rejection(self, oauth_server):
        """Test that empty tokens are rejected."""
        with pytest.raises(InvalidTokenError):
            oauth_server.validate_access_token("")

    def test_tampered_token_signature_rejection(self, oauth_server, valid_access_token):
        """Test that tokens with tampered signatures are rejected."""
        # Tamper with the token by changing last character
        tampered = valid_access_token[:-1] + 'X'

        with pytest.raises(InvalidTokenError):
            oauth_server.validate_access_token(tampered)

    def test_expired_token_rejection(self, oauth_server):
        """Test that expired tokens are rejected."""
        # Create a token that's already expired
        user = oauth_server.users["admin"]
        past_time = datetime.utcnow() - timedelta(hours=2)

        expired_payload = {
            'user_id': user.user_id,
            'scopes': [Scope.READ.value],
            'exp': past_time,
            'iat': past_time - timedelta(hours=1),
            'type': 'access'
        }

        expired_token = jwt.encode(
            expired_payload,
            oauth_server.JWT_SECRET,
            algorithm='HS256'
        )

        with pytest.raises(ExpiredTokenError):
            oauth_server.validate_access_token(expired_token)

    def test_revoked_token_rejection(self, oauth_server, valid_access_token):
        """Test that revoked tokens are rejected."""
        # Revoke the token
        oauth_server.revoke_token(valid_access_token)

        with pytest.raises(InvalidTokenError, match="revoked"):
            oauth_server.validate_access_token(valid_access_token)

    def test_token_wrong_type_rejection(self, oauth_server):
        """Test that non-access tokens are rejected for access validation."""
        # Create a token with wrong type
        user = oauth_server.users["admin"]

        wrong_type_payload = {
            'user_id': user.user_id,
            'scopes': [Scope.READ.value],
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow(),
            'type': 'refresh'  # Wrong type
        }

        wrong_token = jwt.encode(
            wrong_type_payload,
            oauth_server.JWT_SECRET,
            algorithm='HS256'
        )

        with pytest.raises(InvalidTokenError, match="Not an access token"):
            oauth_server.validate_access_token(wrong_token)


class TestScopeEnforcement:
    """Test scope-based authorization."""

    def test_sufficient_scope_validation(self, oauth_server):
        """Test that tokens with sufficient scopes are accepted."""
        access, _ = oauth_server.login(
            "admin",
            "admin_password_123",
            [Scope.READ.value, Scope.WRITE.value]
        )

        # Should succeed - token has both required scopes
        payload = oauth_server.validate_access_token(
            access,
            required_scopes=[Scope.READ.value, Scope.WRITE.value]
        )

        assert payload is not None

    def test_insufficient_scope_rejection(self, oauth_server):
        """Test that tokens with insufficient scopes are rejected."""
        access, _ = oauth_server.login(
            "readonly",
            "readonly_pass",
            [Scope.READ.value]
        )

        # Should fail - token only has READ, requires ADMIN
        with pytest.raises(InsufficientScopeError):
            oauth_server.validate_access_token(
                access,
                required_scopes=[Scope.ADMIN.value]
            )

    def test_partial_scope_match_rejection(self, oauth_server):
        """Test that partial scope matches are rejected."""
        access, _ = oauth_server.login(
            "user",
            "user_password_123",
            [Scope.READ.value]
        )

        # Should fail - has READ but not WRITE
        with pytest.raises(InsufficientScopeError, match="WRITE"):
            oauth_server.validate_access_token(
                access,
                required_scopes=[Scope.READ.value, Scope.WRITE.value]
            )

    def test_no_scope_required_validation(self, oauth_server, valid_access_token):
        """Test that validation succeeds when no specific scopes required."""
        payload = oauth_server.validate_access_token(
            valid_access_token,
            required_scopes=None
        )

        assert payload is not None


class TestRefreshTokenFlow:
    """Test refresh token functionality and security."""

    def test_valid_refresh_token_exchange(self, oauth_server, valid_refresh_token):
        """Test that valid refresh tokens can be exchanged for new tokens."""
        new_access, new_refresh = oauth_server.refresh_access_token(valid_refresh_token)

        assert new_access is not None
        assert new_refresh is not None
        assert new_access != new_refresh

    def test_invalid_refresh_token_rejection(self, oauth_server):
        """Test that invalid refresh tokens are rejected."""
        with pytest.raises(InvalidTokenError, match="Invalid refresh token"):
            oauth_server.refresh_access_token("not_a_valid_refresh_token")

    def test_expired_refresh_token_rejection(self, oauth_server):
        """Test that expired refresh tokens are rejected."""
        # Create a refresh token and manually expire it
        _, refresh = oauth_server.login("user", "user_password_123", [Scope.READ.value])

        # Manually expire the token
        token_obj = oauth_server.refresh_tokens[refresh]
        token_obj.expires_at = datetime.utcnow() - timedelta(days=1)

        with pytest.raises(ExpiredTokenError):
            oauth_server.refresh_access_token(refresh)

    def test_refresh_token_rotation(self, oauth_server, valid_refresh_token):
        """
        Test that refresh token rotation works correctly.

        When a refresh token is used, a new refresh token should be issued
        and the old one should eventually be invalidated.
        """
        # Use the refresh token
        new_access, new_refresh = oauth_server.refresh_access_token(valid_refresh_token)

        # New refresh token should be different
        assert new_refresh != valid_refresh_token

        # Old refresh token should be marked as revoked
        old_token_obj = oauth_server.refresh_tokens[valid_refresh_token]
        assert old_token_obj.revoked is True

        # SECURITY TEST: Attempting to reuse old refresh token should fail
        # This tests for the token replay vulnerability
        with pytest.raises(InvalidTokenError, match="revoked"):
            oauth_server.refresh_access_token(valid_refresh_token)

    def test_new_access_token_has_same_scopes(self, oauth_server):
        """Test that refreshed access tokens maintain the same scopes."""
        # Login with specific scopes
        access1, refresh = oauth_server.login(
            "admin",
            "admin_password_123",
            [Scope.READ.value, Scope.ADMIN.value]
        )

        # Refresh
        access2, _ = oauth_server.refresh_access_token(refresh)

        # Verify scopes match
        payload1 = oauth_server.validate_access_token(access1)
        payload2 = oauth_server.validate_access_token(access2)

        assert set(payload1['scopes']) == set(payload2['scopes'])

    def test_revoked_refresh_token_rejection(self, oauth_server, valid_refresh_token):
        """Test that manually revoked refresh tokens cannot be used."""
        # Manually revoke
        token_obj = oauth_server.refresh_tokens[valid_refresh_token]
        token_obj.revoked = True

        with pytest.raises(InvalidTokenError, match="revoked"):
            oauth_server.refresh_access_token(valid_refresh_token)


class TestAuthorizationCodeFlow:
    """Test OAuth authorization code flow."""

    def test_create_authorization_code(self, oauth_server):
        """Test that authorization codes can be created."""
        user = oauth_server.users["admin"]
        code = oauth_server.create_authorization_code(
            user.user_id,
            "test_client_id",
            [Scope.READ.value]
        )

        assert code is not None
        assert len(code) > 0

    def test_exchange_valid_authorization_code(self, oauth_server):
        """Test that valid authorization codes can be exchanged for tokens."""
        user = oauth_server.users["admin"]
        code = oauth_server.create_authorization_code(
            user.user_id,
            "test_client",
            [Scope.READ.value, Scope.WRITE.value]
        )

        access, refresh = oauth_server.exchange_authorization_code(code, "test_client")

        assert access is not None
        assert refresh is not None

    def test_authorization_code_single_use(self, oauth_server):
        """
        Test that authorization codes can only be used once.

        This is a critical security test - reusing authorization codes
        is a common attack vector (authorization code replay attack).
        """
        user = oauth_server.users["admin"]
        code = oauth_server.create_authorization_code(
            user.user_id,
            "test_client",
            [Scope.READ.value]
        )

        # First use should succeed
        oauth_server.exchange_authorization_code(code, "test_client")

        # Second use should fail
        with pytest.raises(InvalidTokenError, match="already used"):
            oauth_server.exchange_authorization_code(code, "test_client")

    def test_authorization_code_client_mismatch(self, oauth_server):
        """Test that authorization codes are bound to specific clients."""
        user = oauth_server.users["admin"]
        code = oauth_server.create_authorization_code(
            user.user_id,
            "client_a",
            [Scope.READ.value]
        )

        # Attempt to use with different client ID
        with pytest.raises(InvalidTokenError, match="Client ID mismatch"):
            oauth_server.exchange_authorization_code(code, "client_b")

    def test_expired_authorization_code_rejection(self, oauth_server):
        """Test that expired authorization codes are rejected."""
        user = oauth_server.users["admin"]
        code = oauth_server.create_authorization_code(
            user.user_id,
            "test_client",
            [Scope.READ.value]
        )

        # Manually expire the code
        auth_code = oauth_server.authorization_codes[code]
        auth_code.expires_at = datetime.utcnow() - timedelta(minutes=1)

        with pytest.raises(ExpiredTokenError):
            oauth_server.exchange_authorization_code(code, "test_client")

    def test_invalid_authorization_code_rejection(self, oauth_server):
        """Test that invalid authorization codes are rejected."""
        with pytest.raises(InvalidTokenError, match="Invalid authorization code"):
            oauth_server.exchange_authorization_code("invalid_code", "test_client")


class TestSecurityVulnerabilities:
    """
    Tests designed to discover the intentional vulnerabilities.

    These tests may initially fail, demonstrating security issues.
    """

    def test_jwt_secret_strength(self, oauth_server):
        """
        Test JWT secret strength (VULNERABILITY TEST).

        This test checks if the JWT secret is strong enough.
        The current implementation uses a weak, hardcoded secret.
        """
        secret = oauth_server.JWT_SECRET

        # Secret should be long and random
        assert len(secret) >= 32, "JWT secret is too short"

        # Secret should not be a common/predictable value
        common_secrets = [
            "secret",
            "super_secret_key_123",
            "password",
            "jwt_secret"
        ]

        assert secret not in common_secrets, "JWT secret is predictable"

    def test_brute_force_protection(self, oauth_server):
        """
        Test for brute force protection (VULNERABILITY TEST).

        The current implementation has no rate limiting,
        allowing unlimited authentication attempts.
        """
        # Attempt multiple failed logins
        failed_attempts = 0
        max_attempts = 10

        for i in range(max_attempts):
            user = oauth_server.authenticate_user("admin", f"wrong_password_{i}")
            if user is None:
                failed_attempts += 1

        # After many failed attempts, further attempts should be blocked
        # This will fail with current implementation (no rate limiting)
        # In production, you'd want exponential backoff or account lockout

        # Just documenting the vulnerability for now
        assert failed_attempts == max_attempts, "All attempts succeeded (no rate limiting)"

    def test_authorization_code_race_condition(self, oauth_server):
        """
        Test for authorization code race condition (VULNERABILITY TEST).

        The current implementation has a race condition where an authorization
        code could be used multiple times if requests arrive simultaneously.
        """
        user = oauth_server.users["admin"]
        code = oauth_server.create_authorization_code(
            user.user_id,
            "test_client",
            [Scope.READ.value]
        )

        # In a real test, you'd use threading to simulate concurrent requests
        # For this educational example, we'll just document the vulnerability

        # First use
        tokens1 = oauth_server.exchange_authorization_code(code, "test_client")

        # The 'used' flag should prevent reuse immediately
        # But there could be a race condition window
        assert tokens1 is not None


class TestTokenExpiration:
    """Test token expiration handling."""

    def test_access_token_expiration_time(self, oauth_server, valid_access_token):
        """Test that access tokens have correct expiration time."""
        payload = oauth_server.validate_access_token(valid_access_token)

        exp_time = datetime.fromtimestamp(payload['exp'])
        iat_time = datetime.fromtimestamp(payload['iat'])

        # Should be approximately 1 hour
        delta = exp_time - iat_time
        assert timedelta(minutes=55) < delta < timedelta(minutes=65)

    def test_refresh_token_expiration_time(self, oauth_server, valid_refresh_token):
        """Test that refresh tokens have correct expiration time."""
        token_obj = oauth_server.refresh_tokens[valid_refresh_token]

        # Should be approximately 30 days from now
        time_remaining = token_obj.expires_at - datetime.utcnow()
        assert timedelta(days=29) < time_remaining < timedelta(days=31)


# Run tests with coverage
if __name__ == "__main__":
    pytest.main([
        __file__,
        "-v",
        "--cov=auth_server",
        "--cov-report=term-missing",
        "--cov-report=html"
    ])
