FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv for faster dependency management
RUN pip install --no-cache-dir uv

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install Python dependencies from pyproject.toml
RUN uv pip install --system --no-cache \
    fastapi>=0.115.12 \
    fastmcp>=2.3.3 \
    google-api-python-client>=2.168.0 \
    google-auth-httplib2>=0.2.0 \
    google-auth-oauthlib>=1.2.2 \
    httpx>=0.28.1 \
    "mcp[cli]>=1.6.0" \
    sse-starlette>=2.3.3 \
    uvicorn>=0.34.2

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app
USER app

# Expose port (use default of 8000 if PORT not set)
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/health || exit 1

# Command to run the application
CMD ["python", "main.py", "--transport", "streamable-http"]
