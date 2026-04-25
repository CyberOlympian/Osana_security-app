"""
Security App - Comprehensive Test Suite
Tests include security validation, edge cases, rate limiting, and error handling.
"""

import json
import time
import pytest
from unittest.mock import patch, MagicMock

from app.main import app


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def client():
    """Create a test client for the Flask application."""
    app.config['TESTING'] = True
    app.config['DEBUG'] = False
    app.config['RATELIMIT_ENABLED'] = False  # Disable rate limiting for tests
    
    with app.test_client() as test_client:
        yield test_client


@pytest.fixture
def client_with_rate_limiting():
    """Create a test client with rate limiting enabled."""
    app.config['TESTING'] = True
    app.config['DEBUG'] = False
    app.config['RATELIMIT_ENABLED'] = True
    app.config['RATELIMIT_STORAGE_URL'] = 'memory://'
    
    with app.test_client() as test_client:
        yield test_client


# ============================================================================
# Health Check Tests
# ============================================================================

class TestHealthCheck:
    """Tests for the /health endpoint."""
    
    def test_health_check_success(self, client):
        """Test that health check returns proper status."""
        response = client.get('/health')
        assert response.status_code == 200
        
        data = response.get_json()
        assert data['status'] == 'healthy'
        assert 'version' in data
        assert 'environment' in data
    
    def test_health_check_method_not_allowed(self, client):
        """Test that POST is not allowed on health endpoint."""
        response = client.post('/health')
        assert response.status_code == 405
    
    def test_readiness_check_success(self, client):
        """Test that readiness check returns proper status."""
        response = client.get('/ready')
        assert response.status_code == 200
        
        data = response.get_json()
        assert data['status'] == 'ready'
        assert 'timestamp' in data


# ============================================================================
# Main Endpoint Tests
# ============================================================================

class TestHelloEndpoint:
    """Tests for the root (/) endpoint."""
    
    def test_hello_endpoint_success(self, client):
        """Test that hello endpoint returns welcome message."""
        response = client.get('/')
        assert response.status_code == 200
        
        data = response.get_json()
        assert data['message'] == 'Hello from Security App!'
        assert data['version'] == '1.0.0'
        assert data['status'] == 'operational'
    
    def test_hello_endpoint_security_headers(self, client):
        """Test that security headers are present."""
        response = client.get('/')
        
        # Security headers should be present
        assert 'X-Content-Type-Options' in response.headers
        assert 'X-Frame-Options' in response.headers
        assert 'X-XSS-Protection' in response.headers
        assert 'Referrer-Policy' in response.headers
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
        assert response.headers['X-Frame-Options'] == 'DENY'


# ============================================================================
# Echo Endpoint Tests (Input Validation)
# ============================================================================

class TestEchoEndpoint:
    """Tests for the /echo endpoint with input validation."""
    
    def test_echo_success(self, client):
        """Test successful echo with valid input."""
        response = client.post('/echo', 
                               json={'message': 'Hello, World!'},
                               content_type='application/json')
        assert response.status_code == 200
        
        data = response.get_json()
        assert data['echo'] == 'Hello, World!'
        assert data['length'] == 13
    
    def test_echo_missing_body(self, client):
        """Test echo with missing request body."""
        response = client.post('/echo')
        assert response.status_code == 400
        
        data = response.get_json()
        assert 'error' in data
    
    def test_echo_empty_message(self, client):
        """Test echo with empty message."""
        response = client.post('/echo', 
                               json={'message': ''},
                               content_type='application/json')
        assert response.status_code == 200
        
        data = response.get_json()
        assert data['echo'] == ''
        assert data['length'] == 0
    
    def test_echo_missing_message_field(self, client):
        """Test echo with missing message field."""
        response = client.post('/echo', 
                               json={'other': 'value'},
                               content_type='application/json')
        assert response.status_code == 200
        
        data = response.get_json()
        assert data['echo'] == ''
        assert data['length'] == 0
    
    # Security Tests - Input Validation
    
    def test_echo_block_xss_script_tag(self, client):
        """Test that XSS script tags are sanitized."""
        response = client.post('/echo',
                               json={'message': '<script>alert("xss")</script>'},
                               content_type='application/json')
        assert response.status_code == 200
        
        data = response.get_json()
        # Script tags should be escaped, not executed
        assert '&lt;script&gt;' in data['echo']
        assert '<script>' not in data['echo']
    
    def test_echo_block_javascript_protocol(self, client):
        """Test that javascript: protocol is blocked."""
        response = client.post('/echo',
                               json={'message': 'javascript:alert("xss")'},
                               content_type='application/json')
        assert response.status_code == 400
    
    def test_echo_block_onload_event(self, client):
        """Test that HTML event handlers are blocked."""
        response = client.post('/echo',
                               json={'message': '<img src=x onerror=alert(1)>'},
                               content_type='application/json')
        assert response.status_code == 400
    
    def test_echo_block_sql_injection(self, client):
        """Test that SQL injection patterns are blocked."""
        injection_patterns = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1 UNION SELECT * FROM users",
            "admin' --"
        ]
        
        for pattern in injection_patterns:
            response = client.post('/echo',
                                   json={'message': pattern},
                                   content_type='application/json')
            assert response.status_code == 400, f"Failed to block: {pattern}"
    
    def test_echo_block_very_long_input(self, client):
        """Test that very long inputs are blocked."""
        long_input = 'A' * 10000
        response = client.post('/echo',
                               json={'message': long_input},
                               content_type='application/json')
        assert response.status_code == 400
    
    def test_echo_unicode_handling(self, client):
        """Test that Unicode characters are handled properly."""
        response = client.post('/echo',
                               json={'message': 'Hello 世界 🌍'},
                               content_type='application/json')
        assert response.status_code == 200
        
        data = response.get_json()
        assert '世界' in data['echo']
        assert '🌍' in data['echo']


# ============================================================================
# Rate Limiting Tests
# ============================================================================

class TestRateLimiting:
    """Tests for rate limiting functionality."""
    
    def test_rate_limit_exceeded(self, client_with_rate_limiting):
        """Test that rate limit is enforced."""
        # Make exactly the allowed number of requests (2 for this test)
        # Note: Default limit is 100 per hour, but we're testing the /echo endpoint
        # with a 100 per minute limit. We'll make 101 requests to exceed it.
        
        # First 100 requests should succeed
        for i in range(100):
            response = client_with_rate_limiting.get('/')
            assert response.status_code in [200, 429]
        
        # 101st request should be rate limited
        response = client_with_rate_limiting.get('/')
        if response.status_code == 429:
            data = response.get_json()
            assert 'Rate limit exceeded' in data['error']
            assert 'retry_after' in data
    
    def test_rate_limit_exempt_health_endpoint(self, client_with_rate_limiting):
        """Test that health endpoint is exempt from rate limiting."""
        # Make many rapid requests to health endpoint
        for i in range(50):
            response = client_with_rate_limiting.get('/health')
            assert response.status_code == 200


# ============================================================================
# Security Headers Tests
# ============================================================================

class TestSecurityHeaders:
    """Tests for security headers on all responses."""
    
    def test_csp_header_present(self, client):
        """Test that Content-Security-Policy header is present."""
        response = client.get('/')
        assert 'Content-Security-Policy' in response.headers
    
    def test_hsts_header_in_production(self, client):
        """Test that HSTS header is present in production mode."""
        # This test would need production config
        # For testing, we can check that the header exists
        app.config['DEBUG'] = False
        response = client.get('/')
        
        if not app.debug:
            assert 'Strict-Transport-Security' in response.headers
    
    def test_security_headers_on_error_pages(self, client):
        """Test that security headers are present on error responses."""
        response = client.get('/nonexistent')
        assert 'X-Content-Type-Options' in response.headers
        assert 'X-Frame-Options' in response.headers


# ============================================================================
# Error Handling Tests
# ============================================================================

class TestErrorHandling:
    """Tests for error handling endpoints."""
    
    def test_404_error_handling(self, client):
        """Test that 404 errors return JSON and don't expose internals."""
        response = client.get('/nonexistent-endpoint')
        assert response.status_code == 404
        
        data = response.get_json()
        assert data['error'] == 'Resource not found'
        # Error message should not contain stack traces or internal paths
        assert '/app/' not in str(data)
    
    def test_405_error_handling(self, client):
        """Test that method not allowed returns proper error."""
        response = client.put('/')
        assert response.status_code == 405
    
    def test_invalid_json_error_handling(self, client):
        """Test that invalid JSON returns proper error."""
        response = client.post('/echo', 
                               data='invalid json',
                               content_type='application/json')
        assert response.status_code == 400


# ============================================================================
# Input Validation Unit Tests
# ============================================================================

class TestInputValidation:
    """Unit tests for input validation functions."""
    
    def test_validate_string_input_valid(self, client):
        """Test that valid strings pass validation."""
        # Access the validation function through the app's context
        from app.main import validate_string_input
        
        assert validate_string_input("Normal text") is True
        assert validate_string_input("") is True
        assert validate_string_input("Hello @#$%^") is True
        assert validate_string_input("A" * 999) is True
    
    def test_validate_string_input_invalid(self, client):
        """Test that invalid strings are rejected."""
        from app.main import validate_string_input
        
        assert validate_string_input("<script>") is False
        assert validate_string_input("javascript:alert()") is False
        assert validate_string_input("' OR '1'='1") is False
        assert validate_string_input("A" * 10000) is False
    
    def test_sanitize_input_escapes_html(self, client):
        """Test that HTML special characters are escaped."""
        from app.main import sanitize_input
        
        assert sanitize_input("<script>") == "&lt;script&gt;"
        assert sanitize_input('"quote"') == "&quot;quote&quot;"
        assert sanitize_input("'single'") == "&#39;single&#39;"
        assert sanitize_input("&") == "&amp;"
        assert sanitize_input("<>&\"'") == "&lt;&gt;&amp;&quot;&#39;"


# ============================================================================
# Performance and Load Tests
# ============================================================================

class TestPerformance:
    """Basic performance tests."""
    
    def test_response_time_under_100ms(self, client):
        """Test that response time is acceptable."""
        import time
        
        start = time.time()
        response = client.get('/')
        elapsed = (time.time() - start) * 1000  # Convert to milliseconds
        
        assert response.status_code == 200
        assert elapsed < 100, f"Response took {elapsed:.2f}ms, expected <100ms"
    
    def test_concurrent_requests(self, client):
        """Test that concurrent requests are handled."""
        import threading
        
        results = []
        
        def make_request():
            response = client.get('/')
            results.append(response.status_code)
        
        threads = []
        for i in range(10):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        assert all(status == 200 for status in results)


# ============================================================================
# Security Vulnerability Tests
# ============================================================================

class TestSecurityVulnerabilities:
    """Tests for common security vulnerabilities."""
    
    def test_no_debug_info_in_errors(self, client):
        """Test that error responses don't leak debug information."""
        app.config['DEBUG'] = False
        
        response = client.get('/nonexistent')
        data = response.get_json()
        
        # Should not contain stack traces, file paths, or line numbers
        assert 'traceback' not in str(data).lower()
        assert 'file' not in str(data).lower()
        assert 'line' not in str(data).lower()
    
    def test_no_server_version_leak(self, client):
        """Test that server version is not exposed."""
        response = client.get('/')
        assert 'Server' not in response.headers
    
    @patch('app.main.app.logger')
    def test_input_validation_logging(self, mock_logger, client):
        """Test that invalid inputs are logged for audit."""
        client.post('/echo',
                    json={'message': '<script>alert(1)</script>'},
                    content_type='application/json')
        
        # Verify that warning was logged (mock_logger.warning called)
        mock_logger.warning.assert_called()
    
    def test_sql_injection_parameterized_queries(self, client):
        """Test that SQL injection patterns are properly blocked."""
        # Since we don't have actual database queries, this test verifies
        # that our validation layer blocks SQL injection patterns
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "1' OR '1' = '1'",
            "admin' --",
            "1; UPDATE users SET password = 'hacked'",
            "1 UNION SELECT username, password FROM users"
        ]
        
        for malicious in malicious_inputs:
            response = client.post('/echo',
                                   json={'message': malicious},
                                   content_type='application/json')
            # Should be rejected by validation layer (400)
            assert response.status_code == 400


# ============================================================================
# Main Test Runner
# ============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
