# NEURAL-X AI Cyber Defense Platform — Dockerfile
FROM python:3.11-slim

LABEL maintainer="NEURAL-X Team"
LABEL description="NEURAL-X AI Cyber Defense Platform"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # OpenCV dependencies
<<<<<<< HEAD
    libgl1-mesa-glx \
=======
    libgl1\
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    # QR decoding (pyzbar)
    libzbar0 \
    # OCR (pytesseract)
    tesseract-ocr \
    tesseract-ocr-eng \
    # Chrome for Selenium screenshots
    chromium \
    chromium-driver \
    # Misc
    curl \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set Chrome path for Selenium
ENV CHROME_BIN=/usr/bin/chromium
ENV CHROMEDRIVER_PATH=/usr/bin/chromedriver

WORKDIR /app

# Install Python dependencies first (cache layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create necessary directories
RUN mkdir -p app/static/screenshots app/static/uploads app/static/reports instance logs

# Environment
ENV FLASK_ENV=production
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

CMD ["gunicorn", "--config", "docker/gunicorn.conf.py", "run:app"]
