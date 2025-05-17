FROM python:3.11-slim

WORKDIR /app

# Copy dependency management files
COPY pyproject.toml uv.lock ./

# Install project dependencies
RUN pip install --no-cache-dir fastapi>=0.115.12 fastmcp>=2.3.3 google-api-python-client>=2.168.0 google-auth-httplib2>=0.2.0 google-auth-oauthlib>=1.2.2 httpx>=0.28.1 "mcp[cli]>=1.6.0" sse-starlette>=2.3.3 uvicorn>=0.34.2

# Copy application code
COPY . .


# Command to run the application
CMD ["python", "main.py"]
