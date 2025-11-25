from typing import Dict, Optional, Tuple, List, Any
from dataclasses import dataclass, field
from enum import Enum
import base64
import json
import time
import hashlib
import hmac
import logging
import secrets
from abc import ABC, abstractmethod
from threading import Lock, RLock
from pathlib import Path

logger = logging.getLogger("mod_auth")
if not logger.handlers:
    log_dir = Path.home() / ".mod" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    stream_handler = logging.StreamHandler()
    file_handler = logging.FileHandler(log_dir / "auth_manager.log")
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    stream_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)
logger.setLevel(logging.DEBUG)


class AuthType(Enum):
    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    JWT = "jwt"
    OAUTH2 = "oauth2"
    DIGEST = "digest"
    NTLM = "ntlm"
    KERBEROS = "kerberos"
    API_KEY = "api_key"
    HMAC = "hmac"
    CUSTOM = "custom"


class TokenStatus(Enum):
    VALID = "valid"
    EXPIRED = "expired"
    INVALID = "invalid"
    REVOKED = "revoked"
    PENDING_REFRESH = "pending_refresh"


@dataclass
class AuthCredentials:
    auth_type: AuthType
    credentials: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TokenInfo:
    token: str
    token_type: str
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    issued_at: float = field(default_factory=time.time)
    
    def is_expired(self) -> bool:
        if self.expires_in is None:
            return False
        return time.time() - self.issued_at > self.expires_in


class JWTHandler:
    """Utilities for decoding and validating JWT tokens.

    Notes:
        - This implementation performs non-cryptographic parsing by default.
        - Callers may request signature verification by providing the secret.
    """

    @staticmethod
    def _b64url_decode(input_str: str) -> bytes:
        padding = -len(input_str) % 4
        if padding:
            input_str += '=' * padding
        return base64.urlsafe_b64decode(input_str)

    @staticmethod
    def decode_jwt(token: str, verify: bool = False, secret: Optional[str] = None) -> Optional[Dict]:
        try:
            parts = token.split('.')
            if len(parts) != 3:
                logger.debug("JWT decode: token does not have 3 parts")
                return None

            header_b = JWTHandler._b64url_decode(parts[0])
            payload_b = JWTHandler._b64url_decode(parts[1])
            signature = parts[2]

            header = json.loads(header_b.decode('utf-8'))
            payload = json.loads(payload_b.decode('utf-8'))

            if verify and secret:
                expected_sig = JWTHandler._create_jwt_signature(parts[0], parts[1], secret)
                if not secrets.compare_digest(signature, expected_sig):
                    logger.info("JWT signature mismatch during verification")
                    return None

            return payload
        except Exception as e:
            logger.exception("Failed to decode JWT: %s", e)
            return None

    @staticmethod
    def _create_jwt_signature(header: str, payload: str, secret: str) -> str:
        message = f"{header}.{payload}"
        signature = hmac.new(
            secret.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')

    @staticmethod
    def is_jwt_expired(token: str) -> bool:
        try:
            payload = JWTHandler.decode_jwt(token)
            if not payload or 'exp' not in payload:
                return False
            return time.time() > float(payload['exp'])
        except Exception:
            logger.exception("Error checking JWT expiration")
            return False

    @staticmethod
    def extract_claims(token: str) -> Optional[Dict]:
        return JWTHandler.decode_jwt(token)


class BasicAuthHandler:
    @staticmethod
    def encode(username: str, password: str) -> str:
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        return f"Basic {encoded}"

    @staticmethod
    def decode(auth_header: str) -> Optional[Tuple[str, str]]:
        try:
            if not isinstance(auth_header, str) or not auth_header.startswith('Basic '):
                return None

            encoded = auth_header[len('Basic '):]
            decoded = base64.b64decode(encoded + '=' * (-len(encoded) % 4)).decode('utf-8')
            parts = decoded.split(':', 1)

            if len(parts) != 2:
                return None

            return parts[0], parts[1]
        except Exception as e:
            logger.debug("Basic auth decode failed: %s", e)
            return None


class BearerTokenHandler:
    @staticmethod
    def create_header(token: str) -> str:
        return f"Bearer {token}"
    
    @staticmethod
    def extract_token(auth_header: str) -> Optional[str]:
        if not isinstance(auth_header, str):
            return None
        if auth_header.startswith('Bearer '):
            return auth_header[len('Bearer '):]
        return None
    
    @staticmethod
    def validate_format(token: str) -> bool:
        if not token or len(token) == 0:
            return False
        if any(char in token for char in ['\n', '\r', ' ']):
            return False
        return True


class OAuth2TokenHandler:
    def __init__(self):
        self.tokens: Dict[str, TokenInfo] = {}
        self.lock = Lock()
    
    def store_token(self, token_info: TokenInfo, key: str = "default"):
        with self.lock:
            self.tokens[key] = token_info
    
    def get_token(self, key: str = "default") -> Optional[TokenInfo]:
        with self.lock:
            if key not in self.tokens:
                return None
            token = self.tokens[key]
            return token
    
    def is_token_expired(self, key: str = "default") -> bool:
        token = self.get_token(key)
        return token is None or token.is_expired()
    
    def refresh_token_needed(self, key: str = "default", threshold: int = 300) -> bool:
        token = self.get_token(key)
        if not token or not token.refresh_token:
            return False

        if token.expires_in is None:
            return False

        time_remaining = token.expires_in - (time.time() - token.issued_at)
        return time_remaining < threshold


class DigestAuthHandler:
    @staticmethod
    def create_digest_response(username: str, password: str, realm: str, 
                              nonce: str, uri: str, method: str = "GET") -> Dict:
        ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
        response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        
        return {
            'username': username,
            'realm': realm,
            'nonce': nonce,
            'uri': uri,
            'response': response,
            'opaque': '',
        }


class APIKeyHandler:
    def __init__(self):
        self.keys: Dict[str, str] = {}
        self.lock = Lock()
    
    def set_api_key(self, key: str, name: str = "default"):
        with self.lock:
            self.keys[name] = key
    
    def get_api_key(self, name: str = "default") -> Optional[str]:
        with self.lock:
            return self.keys.get(name)
    
    def get_header(self, key_name: str = "X-API-Key", api_key_name: str = "default") -> Dict[str, str]:
        api_key = self.get_api_key(api_key_name)
        if api_key:
            return {key_name: api_key}
        return {}
    
    def remove_api_key(self, name: str = "default"):
        with self.lock:
            self.keys.pop(name, None)


class HMACAuthHandler:
    @staticmethod
    def create_signature(method: str, path: str, body: str, secret: str) -> str:
        message = f"{method}\n{path}\n{body}"
        signature = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()
        return base64.b64encode(signature).decode()
    
    @staticmethod
    def create_header(signature: str, algorithm: str = "HMAC-SHA256") -> str:
        return f"Signature: {algorithm} {signature}"


class AuthenticationValidator:
    @staticmethod
    def validate_credentials(username: str, password: str) -> Tuple[bool, Optional[str]]:
        if not username or not isinstance(username, str):
            return False, "Invalid username"
        
        if len(username) < 1 or len(username) > 256:
            return False, "Username length invalid"
        
        if not password or not isinstance(password, str):
            return False, "Invalid password"
        
        if len(password) < 1 or len(password) > 1024:
            return False, "Password length invalid"
        
        return True, None
    
    @staticmethod
    def validate_token(token: str) -> Tuple[bool, Optional[str]]:
        if not token or not isinstance(token, str):
            return False, "Invalid token"
        
        if len(token) > 10000:
            return False, "Token too long"
        
        if any(char in token for char in ['\x00', '\n', '\r']):
            return False, "Token contains invalid characters"
        
        return True, None
    
    @staticmethod
    def validate_api_key(api_key: str) -> Tuple[bool, Optional[str]]:
        if not api_key or not isinstance(api_key, str):
            return False, "Invalid API key"
        
        if len(api_key) < 10 or len(api_key) > 256:
            return False, "API key length invalid"
        
        return True, None


class AuthenticationCache:
    def __init__(self, ttl: int = 3600):
        self.cache: Dict[str, Tuple[Dict, float]] = {}
        self.ttl = ttl
        self.lock = Lock()
    
    def set(self, key: str, auth_data: Dict):
        with self.lock:
            self.cache[key] = (auth_data, time.time())
    
    def get(self, key: str) -> Optional[Dict]:
        with self.lock:
            if key not in self.cache:
                return None
            
            auth_data, timestamp = self.cache[key]
            if time.time() - timestamp > self.ttl:
                del self.cache[key]
                return None
            try:
                return dict(auth_data)
            except Exception:
                return auth_data
    
    def clear(self):
        with self.lock:
            self.cache.clear()
    
    def is_expired(self, key: str) -> bool:
        with self.lock:
            if key not in self.cache:
                return True
            
            _, timestamp = self.cache[key]
            return time.time() - timestamp > self.ttl


class AuthManager:
    """Central authentication manager.

    Responsibilities:
        - Manage current authentication state and credentials
        - Provide helpers to create auth headers
        - Store short-lived auth cache and history

    Thread-safety:
        Uses an `RLock` to allow safe nested acquisitions when public
        methods call other public methods.
    """
    def __init__(self):
        self.current_auth_type: AuthType = AuthType.NONE
        self.current_credentials: Optional[AuthCredentials] = None
        
        self.jwt_handler = JWTHandler()
        self.basic_handler = BasicAuthHandler()
        self.bearer_handler = BearerTokenHandler()
        self.oauth2_handler = OAuth2TokenHandler()
        self.digest_handler = DigestAuthHandler()
        self.api_key_handler = APIKeyHandler()
        self.hmac_handler = HMACAuthHandler()
        
        self.validator = AuthenticationValidator()
        self.cache = AuthenticationCache()
        
        self.auth_history: List[Dict] = []
        self.lock = RLock()

    def _mask(self, value: Optional[str], show: int = 4) -> str:
        """Mask sensitive strings for logging/cache storage.

        Example: secret1234 -> ********1234
        """
        if not value:
            return ''
        if len(value) <= show:
            return '*' * len(value)
        return '*' * (len(value) - show) + value[-show:]
    
    def set_basic_auth(self, username: str, password: str) -> Tuple[bool, Optional[str]]:
        """Set HTTP Basic authentication using provided username and password.

        Returns a tuple of (success, error_message).
        """
        is_valid, error = self.validator.validate_credentials(username, password)
        if not is_valid:
            return False, error
        
        with self.lock:
            try:
                auth_header = self.basic_handler.encode(username, password)
                
                self.current_auth_type = AuthType.BASIC
                self.current_credentials = AuthCredentials(
                    auth_type=AuthType.BASIC,
                    credentials={'username': username, 'password': password}
                )
                
                self.cache.set('current_auth', {'type': 'basic', 'header': auth_header})
                self.auth_history.append({
                    'type': 'basic',
                    'timestamp': time.time(),
                    'success': True
                })
                
                return True, None
            except Exception as e:
                return False, str(e)
    
    def set_bearer_token(self, token: str) -> Tuple[bool, Optional[str]]:
        """Set Bearer token authentication. Validates token format before storing."""
        is_valid, error = self.validator.validate_token(token)
        if not is_valid:
            return False, error
        
        if not self.bearer_handler.validate_format(token):
            return False, "Invalid token format"
        
        with self.lock:
            try:
                self.current_auth_type = AuthType.BEARER
                self.current_credentials = AuthCredentials(
                    auth_type=AuthType.BEARER,
                    credentials={'token': token}
                )
                
                
                self.cache.set('current_auth', {'type': 'bearer', 'token': self._mask(token)})
                self.auth_history.append({
                    'type': 'bearer',
                    'timestamp': time.time(),
                    'success': True,
                    'token': self._mask(token)
                })
                
                return True, None
            except Exception as e:
                return False, str(e)
    
    def set_jwt_auth(self, token: str, secret: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """Set JWT authentication. Validates and extracts claims from token."""
        is_valid, error = self.validator.validate_token(token)
        if not is_valid:
            return False, error
        
        with self.lock:
            try:
                if self.jwt_handler.is_jwt_expired(token):
                    return False, "JWT token is expired"
                
                claims = self.jwt_handler.extract_claims(token)
                if not claims:
                    return False, "Invalid JWT format"
                
                self.current_auth_type = AuthType.JWT
                self.current_credentials = AuthCredentials(
                    auth_type=AuthType.JWT,
                    credentials={'token': token, 'secret': secret},
                    metadata={'claims': claims}
                )
                
                self.cache.set('current_auth', {
                    'type': 'jwt',
                    'token': self._mask(token),
                    'claims': claims
                })

                self.auth_history.append({
                    'type': 'jwt',
                    'timestamp': time.time(),
                    'success': True,
                    'claims': claims
                })
                
                return True, None
            except Exception as e:
                return False, str(e)
    
    def set_oauth2(self, access_token: str, refresh_token: Optional[str] = None,
                  expires_in: Optional[int] = None) -> Tuple[bool, Optional[str]]:
        """Store OAuth2 tokens and metadata.

        `access_token` is required. If provided, token info will be stored
        in the internal OAuth2 token handler.
        """
        is_valid, error = self.validator.validate_token(access_token)
        if not is_valid:
            return False, error
        
        with self.lock:
            try:
                token_info = TokenInfo(
                    token=access_token,
                    token_type="Bearer",
                    expires_in=expires_in,
                    refresh_token=refresh_token
                )
                
                self.oauth2_handler.store_token(token_info)
                
                self.current_auth_type = AuthType.OAUTH2
                self.current_credentials = AuthCredentials(
                    auth_type=AuthType.OAUTH2,
                    credentials={
                        'access_token': access_token,
                        'refresh_token': refresh_token,
                        'expires_in': expires_in
                    }
                )
                
                
                self.cache.set('current_auth', {
                    'type': 'oauth2',
                    'access_token': self._mask(access_token)
                })

                self.auth_history.append({
                    'type': 'oauth2',
                    'timestamp': time.time(),
                    'success': True,
                    'access_token': self._mask(access_token)
                })
                
                return True, None
            except Exception as e:
                return False, str(e)
    
    def set_api_key(self, api_key: str, key_name: str = "X-API-Key") -> Tuple[bool, Optional[str]]:
        """Register an API key for use in requests. Key is stored in the APIKeyHandler."""
        is_valid, error = self.validator.validate_api_key(api_key)
        if not is_valid:
            return False, error
        
        with self.lock:
            try:
                self.api_key_handler.set_api_key(api_key, "default")
                
                self.current_auth_type = AuthType.API_KEY
                self.current_credentials = AuthCredentials(
                    auth_type=AuthType.API_KEY,
                    credentials={'api_key': api_key, 'key_name': key_name}
                )
                
                self.cache.set('current_auth', {
                    'type': 'api_key',
                    'key_name': key_name,
                    'api_key': self._mask(api_key)
                })

                self.auth_history.append({
                    'type': 'api_key',
                    'timestamp': time.time(),
                    'success': True,
                    'key_name': key_name
                })
                
                return True, None
            except Exception as e:
                return False, str(e)
    
    def set_hmac_auth(self, secret: str) -> Tuple[bool, Optional[str]]:
        """Set HMAC secret used for signing requests."""
        if not secret or not isinstance(secret, str):
            return False, "Invalid secret"
        
        with self.lock:
            try:
                self.current_auth_type = AuthType.HMAC
                self.current_credentials = AuthCredentials(
                    auth_type=AuthType.HMAC,
                    credentials={'secret': secret}
                )
                
                self.auth_history.append({
                    'type': 'hmac',
                    'timestamp': time.time(),
                    'success': True
                })
                
                return True, None
            except Exception as e:
                return False, str(e)
    
    def set_digest_auth(self, username: str, password: str, realm: str) -> Tuple[bool, Optional[str]]:
        """Configure Digest authentication credentials."""
        is_valid, error = self.validator.validate_credentials(username, password)
        if not is_valid:
            return False, error
        
        with self.lock:
            try:
                self.current_auth_type = AuthType.DIGEST
                self.current_credentials = AuthCredentials(
                    auth_type=AuthType.DIGEST,
                    credentials={
                        'username': username,
                        'password': password,
                        'realm': realm
                    }
                )
                
                self.auth_history.append({
                    'type': 'digest',
                    'timestamp': time.time(),
                    'success': True
                })
                
                return True, None
            except Exception as e:
                return False, str(e)
    
    def get_auth_header(self) -> Dict[str, str]:
        """Return a headers dict suitable for HTTP requests based on current auth."""
        with self.lock:
            if self.current_auth_type == AuthType.NONE or not self.current_credentials:
                return {}
            
            credentials = self.current_credentials.credentials
            
            if self.current_auth_type == AuthType.BASIC:
                header = self.basic_handler.encode(
                    credentials.get('username', ''),
                    credentials.get('password', '')
                )
                return {'Authorization': header}
            
            elif self.current_auth_type == AuthType.BEARER:
                token = credentials.get('token', '')
                return {'Authorization': self.bearer_handler.create_header(token)}
            
            elif self.current_auth_type == AuthType.JWT:
                token = credentials.get('token', '')
                return {'Authorization': f'Bearer {token}'}
            
            elif self.current_auth_type == AuthType.OAUTH2:
                token = credentials.get('access_token', '')
                return {'Authorization': f'Bearer {token}'}
            
            elif self.current_auth_type == AuthType.API_KEY:
                key_name = credentials.get('key_name', 'X-API-Key')
                api_key = credentials.get('api_key', '')
                return {key_name: api_key}
            
            elif self.current_auth_type == AuthType.HMAC:
                return {}
            
            return {}
    
    def get_current_auth_type(self) -> AuthType:
        """Return the current authentication type."""
        with self.lock:
            return self.current_auth_type
    
    def is_authenticated(self) -> bool:
        """Return True if any authentication is currently set."""
        with self.lock:
            return self.current_auth_type != AuthType.NONE and self.current_credentials is not None
    
    def clear_auth(self):
        """Clear current authentication and cached auth state."""
        with self.lock:
            self.current_auth_type = AuthType.NONE
            self.current_credentials = None
            self.cache.clear()
    
    def validate_oauth2_token(self) -> Tuple[bool, Optional[str]]:
        """Validate OAuth2 token presence and expiration state."""
        with self.lock:
            if self.current_auth_type != AuthType.OAUTH2:
                return False, "Not OAuth2 authentication"

            if self.oauth2_handler.is_token_expired():
                return False, "OAuth2 token expired"

            return True, None
    
    def get_auth_history(self, limit: int = 10) -> List[Dict]:
        """Return a slice of authentication history entries (most recent last)."""
        with self.lock:
            return self.auth_history[-limit:]
    
    def create_hmac_signature(self, method: str, path: str, body: str = "") -> Optional[str]:
        """Create HMAC signature using current HMAC credentials, if configured."""
        with self.lock:
            if self.current_auth_type != AuthType.HMAC:
                return None
            if not self.current_credentials:
                logger.debug("create_hmac_signature called but no credentials set")
                return None

            secret = self.current_credentials.credentials.get('secret')
            if not secret:
                logger.debug("HMAC secret missing in current credentials")
                return None

            return self.hmac_handler.create_signature(method, path, body, secret)
    
    def get_jwt_claims(self) -> Optional[Dict]:
        """Return JWT claims for current JWT authentication, if available."""
        with self.lock:
            if self.current_auth_type != AuthType.JWT:
                return None
            if not self.current_credentials:
                return None

            return self.current_credentials.metadata.get('claims')
    
    def is_token_expiring_soon(self, seconds: int = 300) -> bool:
        """Return True if stored OAuth2 token is expiring within `seconds`."""
        with self.lock:
            if self.current_auth_type != AuthType.OAUTH2:
                return False

            return self.oauth2_handler.refresh_token_needed()
    
    def get_authentication_summary(self) -> Dict:
        """Return a brief summary of current authentication state useful for UI/status."""
        with self.lock:
            return {
                'current_auth_type': self.current_auth_type.value,
                'is_authenticated': self.is_authenticated(),
                'auth_history_count': len(self.auth_history),
                'cache_size': len(self.cache.cache),
            }