"""
OAuth 2.0 Authentication Server Implementation
Educational demonstration with intentional vulnerabilities for security testing.

Features:
- Token generation (JWT signing)
- Token validation (signature verification)
- Token expiration enforcement
- Refresh token rotation
- Scope-based authorization
- Authorization code flow

Intentional Vulnerabilities:
1. Weak JWT secret (hardcoded and predictable)
2. Missing rate limiting on token endpoint (brute force vulnerability)
3. Authorization code replay vulnerability (codes not invalidated after use)
4. Insufficient refresh token rotation (old tokens not immediately invalidated)
5. Missing PKCE validation in authorization code flow
"""

import jwt
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class TokenError(Exception):
    """Base exception for token-related errors."""
    pass


class InvalidTokenError(TokenError):
    """Raised when a token is invalid or malformed."""
    pass


class ExpiredTokenError(TokenError):
    """Raised when a token has expired."""
    pass


class InsufficientScopeError(TokenError):
    """Raised when a token lacks required scopes."""
    pass


class Scope(Enum):
    """Available OAuth scopes."""
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    USER = "user"


@dataclass
class User:
    """User model."""
    username: str
    password_hash: str
    user_id: str
    scopes: List[str] = field(default_factory=list)


@dataclass
class AuthorizationCode:
    """Authorization code for OAuth flow."""
    code: str
    user_id: str
    client_id: str
    scopes: List[str]
    created_at: datetime
    expires_at: datetime
    used: bool = False  # VULNERABILITY: Not properly enforced


@dataclass
class RefreshToken:
    """Refresh token for obtaining new access tokens."""
    token: str
    user_id: str
    scopes: List[str]
    expires_at: datetime
    revoked: bool = False


class OAuthServer:
    """
    OAuth 2.0 Authentication Server

    This implementation demonstrates OAuth flows with intentional vulnerabilities
    for security testing and educational purposes.
    """

    # VULNERABILITY 1: Weak, hardcoded JWT secret
    JWT_SECRET = "super_secret_key_123"

    # Token expiration times
    ACCESS_TOKEN_EXPIRY = timedelta(hours=1)
    REFRESH_TOKEN_EXPIRY = timedelta(days=30)
    AUTH_CODE_EXPIRY = timedelta(minutes=10)

    def __init__(self):
        """Initialize OAuth server with in-memory storage."""
        self.users: Dict[str, User] = {}
        self.authorization_codes: Dict[str, AuthorizationCode] = {}
        self.refresh_tokens: Dict[str, RefreshToken] = {}
        self.revoked_tokens: set = set()  # Track revoked tokens

    def register_user(self, username: str, password: str, scopes: List[str]) -> User:
        """
        Register a new user.

        Args:
            username: User's username
            password: User's password (will be hashed)
            scopes: List of authorized scopes for this user

        Returns:
            Created User object
        """
        user_id = secrets.token_urlsafe(16)
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        user = User(
            username=username,
            password_hash=password_hash,
            user_id=user_id,
            scopes=scopes
        )

        self.users[username] = user
        return user

    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate user with credentials.

        Args:
            username: User's username
            password: User's password

        Returns:
            User object if authentication successful, None otherwise
        """
        # VULNERABILITY 2: No rate limiting (allows brute force attacks)
        user = self.users.get(username)
        if not user:
            return None

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if password_hash == user.password_hash:
            return user

        return None

    def create_authorization_code(
        self,
        user_id: str,
        client_id: str,
        scopes: List[str]
    ) -> str:
        """
        Create authorization code for OAuth flow.

        Args:
            user_id: User identifier
            client_id: Client application identifier
            scopes: Requested scopes

        Returns:
            Authorization code string
        """
        code = secrets.token_urlsafe(32)
        now = datetime.utcnow()

        auth_code = AuthorizationCode(
            code=code,
            user_id=user_id,
            client_id=client_id,
            scopes=scopes,
            created_at=now,
            expires_at=now + self.AUTH_CODE_EXPIRY,
            used=False
        )

        self.authorization_codes[code] = auth_code
        return code

    def exchange_authorization_code(
        self,
        code: str,
        client_id: str
    ) -> Tuple[str, str]:
        """
        Exchange authorization code for access and refresh tokens.

        Args:
            code: Authorization code
            client_id: Client application identifier

        Returns:
            Tuple of (access_token, refresh_token)

        Raises:
            InvalidTokenError: If code is invalid or mismatched
            ExpiredTokenError: If code has expired
        """
        auth_code = self.authorization_codes.get(code)

        if not auth_code:
            raise InvalidTokenError("Invalid authorization code")

        # VULNERABILITY 3: Code replay vulnerability - 'used' flag not properly enforced
        # The check exists but there's a race condition window
        if auth_code.used:
            # Should revoke all tokens issued with this code, but doesn't
            raise InvalidTokenError("Authorization code already used")

        if auth_code.client_id != client_id:
            raise InvalidTokenError("Client ID mismatch")

        if datetime.utcnow() > auth_code.expires_at:
            raise ExpiredTokenError("Authorization code expired")

        # Mark as used (but with race condition window)
        auth_code.used = True

        # Generate tokens
        access_token = self._create_access_token(
            auth_code.user_id,
            auth_code.scopes
        )
        refresh_token = self._create_refresh_token(
            auth_code.user_id,
            auth_code.scopes
        )

        return access_token, refresh_token

    def _create_access_token(self, user_id: str, scopes: List[str]) -> str:
        """
        Create JWT access token.

        Args:
            user_id: User identifier
            scopes: List of scopes

        Returns:
            JWT token string
        """
        now = datetime.utcnow()
        payload = {
            'user_id': user_id,
            'scopes': scopes,
            'exp': now + self.ACCESS_TOKEN_EXPIRY,
            'iat': now,
            'type': 'access'
        }

        # VULNERABILITY 1: Using weak secret
        token = jwt.encode(payload, self.JWT_SECRET, algorithm='HS256')
        return token

    def _create_refresh_token(self, user_id: str, scopes: List[str]) -> str:
        """
        Create refresh token.

        Args:
            user_id: User identifier
            scopes: List of scopes

        Returns:
            Refresh token string
        """
        token = secrets.token_urlsafe(32)

        refresh_token = RefreshToken(
            token=token,
            user_id=user_id,
            scopes=scopes,
            expires_at=datetime.utcnow() + self.REFRESH_TOKEN_EXPIRY,
            revoked=False
        )

        self.refresh_tokens[token] = refresh_token
        return token

    def validate_access_token(self, token: str, required_scopes: List[str] = None) -> Dict:
        """
        Validate access token and check scopes.

        Args:
            token: JWT access token
            required_scopes: Optional list of required scopes

        Returns:
            Decoded token payload

        Raises:
            InvalidTokenError: If token is invalid or revoked
            ExpiredTokenError: If token has expired
            InsufficientScopeError: If token lacks required scopes
        """
        try:
            # Decode and verify token
            payload = jwt.decode(
                token,
                self.JWT_SECRET,
                algorithms=['HS256']
            )
        except jwt.ExpiredSignatureError:
            raise ExpiredTokenError("Access token expired")
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(f"Invalid token: {str(e)}")

        # Check if token type is access
        if payload.get('type') != 'access':
            raise InvalidTokenError("Not an access token")

        # Check if token is revoked
        if token in self.revoked_tokens:
            raise InvalidTokenError("Token has been revoked")

        # Validate scopes if required
        if required_scopes:
            token_scopes = set(payload.get('scopes', []))
            required_set = set(required_scopes)

            if not required_set.issubset(token_scopes):
                missing = required_set - token_scopes
                raise InsufficientScopeError(
                    f"Missing required scopes: {', '.join(missing)}"
                )

        return payload

    def refresh_access_token(self, refresh_token: str) -> Tuple[str, str]:
        """
        Use refresh token to obtain new access and refresh tokens.

        Args:
            refresh_token: Current refresh token

        Returns:
            Tuple of (new_access_token, new_refresh_token)

        Raises:
            InvalidTokenError: If refresh token is invalid or revoked
            ExpiredTokenError: If refresh token has expired
        """
        token_obj = self.refresh_tokens.get(refresh_token)

        if not token_obj:
            raise InvalidTokenError("Invalid refresh token")

        if token_obj.revoked:
            raise InvalidTokenError("Refresh token has been revoked")

        if datetime.utcnow() > token_obj.expires_at:
            raise ExpiredTokenError("Refresh token expired")

        # VULNERABILITY 4: Insufficient token rotation
        # Old refresh token should be immediately invalidated, but there's a delay
        # This creates a window where both old and new tokens work

        # Create new tokens
        new_access = self._create_access_token(
            token_obj.user_id,
            token_obj.scopes
        )
        new_refresh = self._create_refresh_token(
            token_obj.user_id,
            token_obj.scopes
        )

        # Revoke old token (but not immediately effective - vulnerability)
        token_obj.revoked = True

        return new_access, new_refresh

    def revoke_token(self, token: str):
        """
        Revoke an access token.

        Args:
            token: Token to revoke
        """
        self.revoked_tokens.add(token)

    def login(self, username: str, password: str, scopes: List[str]) -> Tuple[str, str]:
        """
        Simplified login flow for testing.

        Args:
            username: User's username
            password: User's password
            scopes: Requested scopes

        Returns:
            Tuple of (access_token, refresh_token)

        Raises:
            InvalidTokenError: If authentication fails
        """
        user = self.authenticate_user(username, password)
        if not user:
            raise InvalidTokenError("Invalid credentials")

        # Check if user has requested scopes
        user_scopes_set = set(user.scopes)
        requested_set = set(scopes)

        if not requested_set.issubset(user_scopes_set):
            raise InsufficientScopeError("User does not have requested scopes")

        # Generate tokens directly (simplified flow)
        access_token = self._create_access_token(user.user_id, scopes)
        refresh_token = self._create_refresh_token(user.user_id, scopes)

        return access_token, refresh_token


# Example usage
if __name__ == "__main__":
    # Initialize server
    server = OAuthServer()

    # Register users
    admin_user = server.register_user(
        "admin",
        "admin123",
        [Scope.READ.value, Scope.WRITE.value, Scope.ADMIN.value]
    )

    regular_user = server.register_user(
        "user",
        "user123",
        [Scope.READ.value, Scope.USER.value]
    )

    print("OAuth Server initialized with test users")
    print(f"Admin user: {admin_user.username} (scopes: {', '.join(admin_user.scopes)})")
    print(f"Regular user: {regular_user.username} (scopes: {', '.join(regular_user.scopes)})")

    # Test authentication flow
    try:
        access, refresh = server.login("admin", "admin123", [Scope.READ.value])
        print(f"\nLogin successful!")
        print(f"Access token: {access[:50]}...")
        print(f"Refresh token: {refresh[:50]}...")

        # Validate token
        payload = server.validate_access_token(access)
        print(f"\nToken validated for user: {payload['user_id']}")

    except TokenError as e:
        print(f"Authentication failed: {e}")
