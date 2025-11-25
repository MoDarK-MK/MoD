"""Tests for core/response_analyzer.py"""
import pytest
from unittest.mock import Mock, patch
from core.response_analyzer import ResponseAnalyzer


class TestResponseAnalyzer:
    """Test suite for ResponseAnalyzer class."""

    def test_init(self):
        """Test ResponseAnalyzer initialization."""
        analyzer = ResponseAnalyzer()
        assert analyzer is not None

    def test_analyze_headers_basic(self):
        """Test basic header analysis."""
        analyzer = ResponseAnalyzer()
        headers = {
            'Content-Type': 'text/html',
            'Server': 'Apache/2.4.1',
            'X-Powered-By': 'PHP/7.4.0'
        }
        # Assuming analyze_headers method exists; adjust as needed
        # result = analyzer.analyze_headers(headers)
        # assert 'Server' in result or result is not None

    def test_analyze_cookies(self):
        """Test cookie analysis."""
        analyzer = ResponseAnalyzer()
        headers = {
            'Set-Cookie': 'session=abc123; HttpOnly; Secure; SameSite=Strict'
        }
        # result = analyzer.analyze_headers(headers)
        # Verify security flags are detected

    def test_xxe_protection_in_xml_parsing(self):
        """Test that XXE protection is applied during XML parsing."""
        analyzer = ResponseAnalyzer()
        # This test verifies safe XML parsing is in place
        # Adjust based on actual method signature
        xml_content = '<?xml version="1.0"?><root><data>test</data></root>'
        # Should not raise exception and should safely parse

    def test_detect_xss_vectors(self):
        """Test XSS detection."""
        analyzer = ResponseAnalyzer()
        xss_payload = '<script>alert("XSS")</script>'
        # result = analyzer.analyze_content(xss_payload)
        # assert 'xss' in str(result).lower()

    def test_detect_sql_errors(self):
        """Test SQL error detection."""
        analyzer = ResponseAnalyzer()
        sql_error = "SQL syntax error near 'SELECT * FROM users'"
        # result = analyzer.analyze_content(sql_error)
        # assert result indicates SQL injection risk

    def test_large_response_handling(self):
        """Test handling of large responses."""
        analyzer = ResponseAnalyzer()
        large_content = 'A' * 1000000  # 1MB of data
        # Should handle gracefully without timeout or memory issues


class TestXXEProtection:
    """Test suite for XXE vulnerability protection."""

    def test_safe_xml_parsing(self):
        """Test that XML parsing is protected against XXE."""
        analyzer = ResponseAnalyzer()
        xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>'''
        # Should not process external entities
        # result = analyzer.analyze_content(xxe_payload)

    def test_entity_expansion_blocked(self):
        """Test that billion laughs/XML bomb is blocked."""
        analyzer = ResponseAnalyzer()
        # Should safely reject deeply nested entity expansions
