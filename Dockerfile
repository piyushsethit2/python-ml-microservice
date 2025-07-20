# Optimized Dockerfile for Render deployment (512MB memory limit)
FROM python:3.9.18-alpine

# Install system dependencies including C++ compiler for scikit-learn/numpy
RUN apk add --no-cache gcc g++ musl-dev linux-headers build-base

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies with optimizations
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    # Clean up to reduce image size
    rm -rf /root/.cache/pip && \
    # Remove build dependencies to reduce image size
    apk del gcc g++ build-base

# Copy application code
COPY . .

# Set environment variables for memory optimization
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV NLTK_DATA=/app/nltk_data

# Download NLTK data during build
RUN python -c "import nltk; nltk.download('vader_lexicon', download_dir='/app/nltk_data', quiet=True); nltk.download('punkt', download_dir='/app/nltk_data', quiet=True)"

EXPOSE 5002

# Use lightweight command
CMD ["python3", "ml_microservice.py"] 