FROM python:3.11-slim AS builder

WORKDIR /app

# Install system dependencies and Python dependencies with pip cache
COPY requirements.txt .
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    gcc python3-dev \
    && pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && playwright install --with-deps \
    && playwright install-deps \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copy application code
COPY app/ app/
COPY static/ static/

# ----------------------
# Final stage
# ----------------------
FROM python:3.11-slim

WORKDIR /app

# Copy installed site-packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --from=builder /app/app /app/app
COPY --from=builder /app/static /app/static
COPY --from=builder /root/.cache/ms-playwright /home/malware/.cache/ms-playwright

# Create non-root user for security and set permissions
RUN groupadd --system --gid 1234 malware \
    && useradd --system --uid 1002 --gid 1234 --create-home malware \
    && mkdir -p /app/static/reports /app/logs \
    && chown -R malware:malware /app /home/malware/.cache

USER malware

EXPOSE 5051

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://0.0.0.0:5051/health')" || exit 1

# Run the FastAPI server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5051"]

