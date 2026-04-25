# Use specific version pinning for reproducibility
FROM python:3.11-slim-bookworm AS builder

# Set build-time variables
ARG APP_USER=appuser
ARG APP_GROUP=appgroup
ARG APP_UID=10001
ARG APP_GID=10001

# Install build dependencies (remove after use for smaller image)
WORKDIR /app

# Copy only requirements first (better layer caching)
COPY requirements.txt .

# Upgrade pip and install dependencies with security flags
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir --no-deps -r requirements.txt && \
    pip check

# Final stage - creates smaller production image
FROM python:3.11-slim-bookworm

# Set environment variables for security and Python behavior
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PORT=5000

# Create non-root user and group
RUN addgroup --system --gid ${APP_GID:-10001} ${APP_GROUP:-appgroup} && \
    adduser --system --uid ${APP_UID:-10001} --gid ${APP_GID:-10001} \
    --no-create-home --disabled-password --shell /bin/false ${APP_USER:-appuser}

# Set working directory
WORKDIR /app

# Copy installed dependencies from builder stage
COPY --from=builder --chown=${APP_USER:-appuser}:${APP_GROUP:-appgroup} /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder --chown=${APP_USER:-appuser}:${APP_GROUP:-appgroup} /usr/local/bin /usr/local/bin

# Copy application code
COPY --chown=${APP_USER:-appuser}:${APP_GROUP:-appgroup} app/ ./app/

# Copy requirements (for explicit reference)
COPY --chown=${APP_USER:-appuser}:${APP_GROUP:-appgroup} requirements.txt .

# Health check for container orchestration
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${PORT:-5000}/health')" || exit 1

# Switch to non-root user
USER ${APP_USER:-appuser}

# Expose the port
EXPOSE ${PORT:-5000}

# Run the application with gunicorn (production grade) instead of Flask dev server
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 2 --threads 2 --timeout 120 app.main:app"]
