"""
Security App - Production-Ready Flask Application
Implements security best practices including input validation,
rate limiting, secure headers, and proper error handling.
"""

import os
import re
import logging
from typing import Tuple, Dict, Any

from flask import Flask, request, jsonify, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import HTTPException

# ============================================================================
# Configuration
# ============================================================================

class Config:
    """Application configuration with security defaults."""
    
    # Environment detection
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    TESTING = os.environ.get('FLASK_TESTING', 'False').lower() == 'true'
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(32).hex())
    
    # Server configuration
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 5000))
    
    # Security headers
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour
    
    # Rate limiting
    RATELIMIT_DEFAULT = os.environ.get('RATELIMIT_DEFAULT', '100 per hour')
    RATELIMIT_STRATEGY = 'fixed-window'
    RATELIMIT_STORAGE_URL = os.environ.get('RATELIMIT_STORAGE_URL', 'memory://')
    RATELIMIT_HEADERS_ENABLED = True
    
    # Input validation
    MAX_CONTENT_LENGTH = 1024 * 1024  # 1MB
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# ============================================================================
# Initialize Application
# ============================================================================

app = Flask(__name__)
app.config.from_object(Config())

# Trust proxy headers (important when behind nginx/cloudflare)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# ============================================================================
# Security Headers Middleware
# ============================================================================

@app.after_request
def add_security_headers(response: Response) -> Response:
    """
    Add security headers to all responses.
    Protects against XSS, clickjacking, MIME sniffing, and more.
    """
    # Content Security Policy
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';"
    
    # Prevent XSS attacks
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # HSTS (Force HTTPS - 1 year)
    if not app.debug:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    
    # Permissions policy (formerly Feature-Policy)
    response.headers['Permissions-Policy'] = "geolocation=(), microphone=(), camera=()"
    
    return response

# ============================================================================
# Logging Setup
# ============================================================================

def setup_logging() -> None:
    """Configure application logging for security audit trail."""
    log_level = getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(Config.LOG_FORMAT))
    
    # File handler (for audit trail)
    if not app.debug:
        file_handler = logging.FileHandler('app.log')
        file_handler.setFormatter(logging.Formatter(Config.LOG_FORMAT))
        app.logger.addHandler(file_handler)
    
    app.logger.addHandler(console_handler)
    app.logger.setLevel(log_level)
    
    # Log startup
    app.logger.info(f"Application starting in {'debug' if app.debug else 'production'} mode")

# ============================================================================
# Rate Limiting
# ============================================================================

# Initialize rate limiter after app creation
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[Config.RATELIMIT_DEFAULT],
    storage_uri=Config.RATELIMIT_STORAGE_URL,
    strategy=Config.RATELIMIT_STRATEGY,
    headers_enabled=Config.RATELIMIT_HEADERS_ENABLED,
)

# ============================================================================
# Input Validation Helpers
# ============================================================================

def validate_string_input(value: str, max_length: int = 1000) -> bool:
    """Validate string input to prevent injection attacks."""
    if not isinstance(value, str):
        return False
    if len(value) > max_length:
        return False
    # Block common injection patterns
    dangerous_patterns = [
        r'<script', r'javascript:', r'vbscript:', r'onload=', r'onerror=',
        r'--', r';', r'\x00', r'%00', r'union.*select', r'exec\('
    ]
    for pattern in dangerous_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            return False
    return True

def sanitize_input(value: str) -> str:
    """Sanitize user input by escaping dangerous characters."""
    if not value:
        return ""
    # Escape HTML entities
    value = value.replace('&', '&amp;')
    value = value.replace('<', '&lt;')
    value = value.replace('>', '&gt;')
    value = value.replace('"', '&quot;')
    value = value.replace("'", '&#39;')
    return value

# ============================================================================
# Health Check (for container orchestration)
# ============================================================================

@app.route('/health', methods=['GET'])
@limiter.exempt
def health_check() -> Tuple[Response, int]:
    """
    Health check endpoint for container orchestration.
    Returns status 200 if application is healthy.
    """
    response = jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'environment': 'production' if not app.debug else 'development'
    })
    return response, 200

# ============================================================================
# Readiness Check (for Kubernetes-style deployments)
# ============================================================================

@app.route('/ready', methods=['GET'])
@limiter.exempt
def readiness_check() -> Tuple[Response, int]:
    """
    Readiness check endpoint.
    Indicates if application is ready to serve traffic.
    """
    response = jsonify({
        'status': 'ready',
        'timestamp': '2026-01-01T00:00:00Z'
    })
    return response, 200

# ============================================================================
# Main Routes
# ============================================================================

@app.route('/', methods=['GET'])
@limiter.limit('1000 per hour')  # Stricter limit for public endpoint
def hello() -> Tuple[Response, int]:
    """
    Hello endpoint - returns a welcome message.
    Rate limited to prevent abuse.
    """
    app.logger.info(f"Hello endpoint accessed from {request.remote_addr}")
    
    response_data = {
        'message': 'Hello from Security App!',
        'version': '1.0.0',
        'status': 'operational'
    }
    
    response = jsonify(response_data)
    return response, 200

@app.route('/echo', methods=['POST'])
@limiter.limit('100 per minute')
def echo() -> Tuple[Response, int]:
    """
    Echo endpoint - demonstrates validated input handling.
    Returns sanitized input back to the client.
    """
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Invalid request body'}), 400
    
    # Validate and sanitize input
    message = data.get('message', '')
    
    if not validate_string_input(message):
        app.logger.warning(f"Invalid input blocked from {request.remote_addr}")
        return jsonify({'error': 'Invalid input detected'}), 400
    
    sanitized_message = sanitize_input(message)
    
    return jsonify({
        'echo': sanitized_message,
        'length': len(sanitized_message)
    }), 200

# ============================================================================
# Error Handlers
# ============================================================================

@app.errorhandler(404)
def not_found_error(error: HTTPException) -> Tuple[Response, int]:
    """Handle 404 errors gracefully."""
    response = jsonify({'error': 'Resource not found'})
    return response, 404

@app.errorhandler(500)
def internal_error(error: HTTPException) -> Tuple[Response, int]:
    """Handle 500 errors without exposing internals."""
    app.logger.error(f"Internal server error: {error}")
    response = jsonify({'error': 'Internal server error'})
    return response, 500

@app.errorhandler(429)
def rate_limit_error(error: HTTPException) -> Tuple[Response, int]:
    """Handle rate limit exceeded errors."""
    response = jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.',
        'retry_after': getattr(error, 'retry_after', 60)
    })
    return response, 429

# ============================================================================
# Main Entry Point
# ============================================================================

def main() -> None:
    """Application entry point."""
    setup_logging()
    
    app.logger.info(f"Starting server on {Config.HOST}:{Config.PORT}")
    
    # Use production WSGI server if available
    if not app.debug:
        # When run with gunicorn, gunicorn handles the server
        # This condition ensures Flask dev server only runs in debug
        pass
    
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG,
        use_reloader=Config.DEBUG
    )

if __name__ == '__main__':
    main()
