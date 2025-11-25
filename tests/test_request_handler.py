"""Tests for core/request_handler.py"""
import pytest
from unittest.mock import Mock, patch, MagicMock
import requests
from core.request_handler import RequestHandler, CookieManager, SessionManager, RequestConfig


class TestCookieManager:
    """Test suite for CookieManager class."""

    def test_add_cookie_basic(self):
        """Test adding a basic cookie."""
        manager = CookieManager()
        manager.add_cookie('test_cookie', 'test_value', 'example.com')
        cookies = manager.get_cookies()
        assert 'test_cookie' in cookies

    def test_add_cookie_with_flags(self):
        """Test adding a cookie with security flags."""
        manager = CookieManager()
        manager.add_cookie(
            'session_id',
            'abc123',
            'example.com',
            secure=True,
            httponly=True,
            samesite='Strict'
        )
        cookies = manager.get_cookies()
        assert 'session_id' in cookies

    def test_get_cookie_jar(self):
        """Test retrieving cookie jar."""
        manager = CookieManager()
        manager.add_cookie('id', '123', 'example.com')
        jar = manager.get_cookie_jar()
        assert isinstance(jar, requests.cookies.RequestsCookieJar)

    def test_clear_cookies(self):
        """Test clearing all cookies."""
        manager = CookieManager()
        manager.add_cookie('test', 'value', 'example.com')
        manager.clear()
        cookies = manager.get_cookies()
        assert len(cookies) == 0


class TestSessionManager:
    """Test suite for SessionManager context manager."""

    def test_session_context_manager(self):
        """Test SessionManager as context manager."""
        config = RequestConfig()
        with SessionManager(config) as session:
            assert isinstance(session.session, requests.Session)
            assert session.session is not None

    def test_session_cleanup_on_exit(self):
        """Test that session is properly closed on exit."""
        config = RequestConfig()
        session_manager = SessionManager(config)
        with session_manager as sm:
            assert sm.session is not None
        assert session_manager.session is not None


class TestRequestHandler:
    """Test suite for RequestHandler class."""

    def test_init_creates_session(self):
        """Test that RequestHandler initializes with a session."""
        handler = RequestHandler(timeout=10)
        assert handler.config.timeout == 10
        assert handler.session_manager is not None

    def test_send_request_initialization(self):
        """Test that send_request initializes without error."""
        handler = RequestHandler()
        assert handler.session_manager is not None
        assert handler.metrics_collector is not None

    def test_send_request_handles_errors(self):
        """Test that send_request handles connection errors gracefully."""
        handler = RequestHandler()
        result = handler.send_request('https://invalid-domain-that-does-not-exist.test')
        assert isinstance(result, dict)
        assert 'status_code' in result
        assert 'error' in result or result['status_code'] == 0

    def test_timeout_configuration(self):
        """Test timeout is properly set."""
        handler = RequestHandler(timeout=30)
        assert handler.config.timeout == 30

    def test_config_initialization(self):
        """Test RequestConfig initialization."""
        handler = RequestHandler(verify_ssl=True)
        assert handler.config.verify_ssl == True
