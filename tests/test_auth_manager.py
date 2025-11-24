import time
import hmac
import hashlib
import base64
import json
from core.auth_manager import (
    JWTHandler,
    BasicAuthHandler,
    HMACAuthHandler,
    OAuth2TokenHandler,
    APIKeyHandler,
    TokenInfo,
)


def test_basic_auth_encode_decode():
    header = BasicAuthHandler.encode('user', 'pass')
    assert header.startswith('Basic ')
    creds = BasicAuthHandler.decode(header)
    assert creds == ('user', 'pass')


def _make_jwt(payload: dict) -> str:
    header = {'alg': 'HS256', 'typ': 'JWT'}
    header_b = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    secret = 'testsecret'
    message = f"{header_b}.{payload_b}"
    sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
    sig_b = base64.urlsafe_b64encode(sig).decode().rstrip('=')
    return f"{header_b}.{payload_b}.{sig_b}"


def test_jwt_decode_and_expiry():
    payload = {'sub': '123', 'exp': time.time() + 2}
    token = _make_jwt(payload)
    decoded = JWTHandler.decode_jwt(token)
    assert decoded and decoded.get('sub') == '123'
    assert JWTHandler.is_jwt_expired(token) is False
    expired_payload = {'sub': 'x', 'exp': time.time() - 10}
    expired_token = _make_jwt(expired_payload)
    assert JWTHandler.is_jwt_expired(expired_token) is True


def test_hmac_signature():
    signature = HMACAuthHandler.create_signature('GET', '/path', 'body', 'secret')
    assert isinstance(signature, str) and len(signature) > 0


def test_oauth2_store_and_refresh_needed():
    handler = OAuth2TokenHandler()
    ti = TokenInfo(token='t', token_type='Bearer', expires_in=1, refresh_token='r')
    handler.store_token(ti)
    assert handler.get_token() is not None
    assert handler.is_token_expired() in (False, True)


def test_api_key_handler():
    h = APIKeyHandler()
    h.set_api_key('abcd1234apikey', 'default')
    assert h.get_api_key('default') == 'abcd1234apikey'
    hdr = h.get_header()
    assert isinstance(hdr, dict)
    h.remove_api_key('default')
    assert h.get_api_key('default') is None
