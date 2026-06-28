# ============================================
# Phishing Email Forensics — Docker Image
# ============================================
FROM python:3.12-slim AS base

LABEL maintainer="Ari <arielleetran65@gmail.com>"
LABEL description="Phishing Email Forensics Platform"

# Prevent Python from writing .pyc and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System deps (minimal — add libmagic if needed for file type detection)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        file \
    && rm -rf /var/lib/apt/lists/*

# Python deps — install only non-commented, non-optional lines
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project source
COPY scripts/ ./scripts/
COPY dashboard.html .
COPY webapp.py .
COPY samples/demo_phishing.eml ./samples/

# Create runtime directories
RUN mkdir -p /app/samples /app/reports

# Default volumes for data exchange
VOLUME ["/app/samples", "/app/reports"]

# Healthcheck — verify the analyzer module loads
HEALTHCHECK --interval=30s --timeout=5s \
    CMD python -c "from scripts.phishing_analyzer import PhishingAnalyzer; print('OK')" || exit 1

# Default: show help
ENTRYPOINT ["python", "scripts/phishing_analyzer.py"]
CMD ["--help"]
