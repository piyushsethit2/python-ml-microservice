# Optimized Dockerfile for Render deployment (512MB memory limit)
FROM python:3.9.18-alpine

# Install system dependencies including C++ and Fortran compilers for scikit-learn/numpy/scipy
# Also install libgomp for OpenMP support that scikit-learn needs
RUN apk add --no-cache gcc g++ gfortran musl-dev linux-headers build-base libgomp

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies with optimizations
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    # Clean up to reduce image size
    rm -rf /root/.cache/pip && \
    # Remove build dependencies but keep libgomp for runtime
    apk del gcc g++ gfortran build-base

# Copy application code
COPY . .

# Set environment variables for memory optimization
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV NLTK_DATA=/app/nltk_data

# Download NLTK data during build
RUN python -c "import nltk; nltk.download('vader_lexicon', quiet=True)"

# Expose port
EXPOSE 5002

# Health check with increased timeout
HEALTHCHECK --interval=30s --timeout=30s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:5002/health || exit 1

# Use gunicorn for production with optimized settings
CMD ["gunicorn", "--bind", "0.0.0.0:5002", "--workers", "1", "--timeout", "30", "--keep-alive", "2", "--max-requests", "1000", "--max-requests-jitter", "100", "--log-level", "info", "--access-logfile", "-", "--error-logfile", "-", "ml_microservice:app"] 