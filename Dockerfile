# Optimized Dockerfile for Render deployment (512MB memory limit)
FROM python:3.9.18-alpine

# Install system dependencies including C++ and Fortran compilers for scikit-learn/numpy/scipy
RUN apk add --no-cache gcc g++ gfortran musl-dev linux-headers build-base

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies with optimizations
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    # Clean up to reduce image size
    rm -rf /root/.cache/pip && \
    # Remove build dependencies to reduce image size
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
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Run the application
CMD ["python", "ml_microservice.py"] 