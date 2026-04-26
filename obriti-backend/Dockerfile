# Use official Python image
FROM python:3.10-slim

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y build-essential default-libmysqlclient-dev gcc && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy app source
COPY src/ ./src/

# Expose port
EXPOSE 8000

# Set environment variables (these should be overridden in docker-compose or at runtime)
# ⚠️  NEVER hardcode credentials in the Dockerfile or image
# Instead, use docker-compose.yml with environment variables or secret management solutions
ENV ENVIRONMENT="production"
ENV LOG_LEVEL="INFO"
ENV DEBUG="False"

# Create .env file from build arguments if needed
# This allows passing secrets at runtime without baking them into the image
# Usage: docker build --build-arg DATABASE_URL="..." --build-arg SECRET_KEY="..."

# Start FastAPI app with uvicorn
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"] 