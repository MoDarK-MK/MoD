"""Tests for scanners/csrf_scanner.py"""
import pytest
from unittest.mock import Mock, patch
from scanners.csrf_scanner import MegaFormAnalyzer, CSRFToken, MegaTokenAnalyzer
import secrets


class TestCSRFToken:
    """Test suite for CSRFToken dataclass."""

    def test_token_creation(self):
        """Test creating a CSRF token."""
        token = CSRFToken(name='csrf_token', value='abc123xyz789')
        assert token.name == 'csrf_token'
        assert token.value == 'abc123xyz789'
        assert token.token_length == 12

    def test_token_entropy_calculation(self):
        """Test token entropy is calculated."""
        token = CSRFToken(name='token', value='abcdefghij1234567890')
        assert token.entropy_score >= 0.0
        assert token.entropy_score <= 1.0

    def test_token_randomness_detection(self):
        """Test randomness detection."""
        token = CSRFToken(name='random', value='abcdefghijklmnopqrstuvwxyz0123456789')
        assert token.token_length > 0
        assert token.entropy_score >= 0.0


class TestMegaFormAnalyzer:
    """Test suite for MegaFormAnalyzer."""

    def test_csrf_keywords_detection(self):
        """Test CSRF keyword detection."""
        assert 'csrf' in MegaFormAnalyzer.CSRF_KEYWORDS
        assert 'token' in MegaFormAnalyzer.CSRF_KEYWORDS
        assert 'nonce' in MegaFormAnalyzer.CSRF_KEYWORDS

    def test_extract_forms_from_html(self):
        """Test form extraction from HTML."""
        html = '''
        <html>
        <form name="login" action="/login" method="POST">
            <input type="hidden" name="csrf_token" value="token123">
            <input type="text" name="username">
            <input type="password" name="password">
        </form>
        </html>
        '''
        forms = MegaFormAnalyzer.extract_forms(html)
        assert len(forms) > 0
        assert forms[0]['method'] == 'POST'

    def test_find_csrf_tokens_in_form(self):
        """Test CSRF token detection in forms."""
        form = {
            'hidden': [
                {'name': 'csrf_token', 'value': 'token_value_123'},
                {'name': 'other_field', 'value': 'other_value'}
            ]
        }
        tokens = MegaFormAnalyzer.find_csrf_tokens(form)
        assert len(tokens) > 0
        assert tokens[0].name == 'csrf_token'

    def test_generate_secure_token(self):
        """Test secure token generation."""
        token = MegaFormAnalyzer.generate_secure_token(32)
        assert token is not None
        assert len(token) > 0
        assert isinstance(token, str)

    def test_secure_token_uniqueness(self):
        """Test that generated tokens are unique."""
        token1 = MegaFormAnalyzer.generate_secure_token()
        token2 = MegaFormAnalyzer.generate_secure_token()
        assert token1 != token2

    def test_detect_ajax_csrf_protection(self):
        """Test AJAX CSRF token detection."""
        html = '''
        <script>
            xhr.setRequestHeader('X-CSRF-Token', 'csrf_value');
        </script>
        '''
        detected = MegaFormAnalyzer.detect_ajax_csrf(html)
        assert len(detected) > 0

    def test_min_token_length_enforcement(self):
        """Test that token minimum length is enforced."""
        token = MegaFormAnalyzer.generate_secure_token(8)  # Below minimum
        assert len(token) >= 32  # Should be upgraded to minimum


class TestMegaTokenAnalyzer:
    """Test suite for MegaTokenAnalyzer."""

    def test_randomness_analysis(self):
        """Test randomness analysis of tokens."""
        tokens = [
            CSRFToken(name='t1', value='abcdefghijklmnop'),
            CSRFToken(name='t2', value='qrstuvwxyz012345')
        ]
        is_random, score = MegaTokenAnalyzer.analyze_randomness(tokens)
        assert isinstance(score, float)

    def test_pattern_detection_identical(self):
        """Test detection of identical tokens (suspicious pattern)."""
        tokens = ['same_token', 'same_token', 'same_token']
        is_pattern, pattern_type = MegaTokenAnalyzer.detect_pattern(tokens)
        assert is_pattern is True
        assert pattern_type == 'All identical'

    def test_pattern_detection_reuse(self):
        """Test detection of token reuse."""
        tokens = ['token1', 'token1', 'token2']
        is_pattern, pattern_type = MegaTokenAnalyzer.detect_pattern(tokens)
        # First two are identical (reuse), should be detected
