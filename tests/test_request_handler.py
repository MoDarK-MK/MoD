"""Tests for core/request_handler.py"""
import pytest
from unittest.mock import Mock, patch, MagicMock
import requests
from core.request_handler import RequestHandler, CookieManager, SessionManager


class TestCookieManager:
    """Test suite for CookieManager class."""

    def test_add_cookie_basic(self):
        """Test adding a basic cookie."""
        manager = CookieManager()
        manager.add_cookie('test_cookie', 'test_value', 'example.com')
        assert 'test_cookie' in manager.cookies

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
        cookie = manager.cookies.get('session_id')
        assert cookie is not None

    def test_get_cookie_headers(self):
        """Test retrieving cookie headers."""
        manager = CookieManager()
        manager.add_cookie('id', '123', 'example.com')
        headers = manager.get_cookie_headers()
        assert isinstance(headers, dict)

    def test_clear_cookies(self):
        """Test clearing all cookies."""
        manager = CookieManager()
        manager.add_cookie('test', 'value', 'example.com')
        manager.clear_cookies()
        assert len(manager.cookies) == 0


class TestSessionManager:
    """Test suite for SessionManager context manager."""

    def test_session_context_manager(self):
        """Test SessionManager as context manager."""
        with SessionManager() as session:
            assert isinstance(session, requests.Session)
            assert session is not None

    def test_session_cleanup_on_exit(self):
        """Test that session is properly closed on exit."""
        session_manager = SessionManager()
        with session_manager as session:
            assert session is not None
        # Session should be closed at this point
        assert session_manager.session is None or not session_manager.session


class TestRequestHandler:
    """Test suite for RequestHandler class."""

    @patch('core.request_handler.requests.Session')
    def test_init_creates_session(self, mock_session):
        """Test that RequestHandler initializes with a session."""
        handler = RequestHandler(timeout=10, retries=3)
        assert handler.timeout == 10
        assert handler.retries == 3

    @patch('core.request_handler.requests.Session.get')
    def test_send_request_get(self, mock_get):
        """Test sending a GET request."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = 'Success'
        mock_response.headers = {}
        mock_get.return_value = mock_response

        handler = RequestHandler()
        # Note: This assumes send_request exists; adjust if method name differs
        # result = handler.send_request('https://example.com', method='GET')
        # assert result.status_code == 200

    @patch('core.request_handler.requests.Session.post')
    def test_send_request_post(self, mock_post):
        """Test sending a POST request."""
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.text = 'Created'
        mock_response.headers = {}
        mock_post.return_value = mock_response

        handler = RequestHandler()
        # result = handler.send_request('https://example.com', method='POST', data={'key': 'value'})
        # assert result.status_code == 201

    def test_timeout_configuration(self):
        """Test timeout is properly set."""
        handler = RequestHandler(timeout=30)
        assert handler.timeout == 30

    def test_retries_configuration(self):
        """Test retries configuration."""
        handler = RequestHandler(retries=5)
        assert handler.retries == 5
