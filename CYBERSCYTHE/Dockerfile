FROM python:3.11-slim AS builder

WORKDIR /app

# Install system dependencies first
RUN apt-get update && apt-get install -y \
    gcc python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies with pip cache
COPY requirements.txt .
RUN pip install --upgrade pip     && pip install --no-cache-dir -r requirements.txt     && playwright install --with-deps

# Copy application code
COPY app/ app/
COPY static/ static/

# ----------------------
# Final stage
# ----------------------
FROM python:3.11-slim

WORKDIR /app

# Install runtime system dependencies
RUN apt-get update && apt-get install -y \
    libxml2 libxslt1.1 libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed site-packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --from=builder /app /app

# Create non-root user for security
RUN groupadd --system --gid 1234 malware \
    && useradd --system --uid 1002 --gid 1234 --create-home malware \
    && mkdir -p /app/static/reports \
    && mkdir -p /app/logs \
    && chown -R malware:malware /app

USER malware

EXPOSE 5051

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:5051/health')" || exit 1

# Run the FastAPI server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5051"]
