FROM python:3.11-slim

WORKDIR /app

# Copy dependency management files
COPY pyproject.toml uv.lock ./

# Install uv and dependencies
RUN pip install uv && uv sync

# Copy application code
COPY . .

# Command to run the application
CMD ["python", "main.py"]
