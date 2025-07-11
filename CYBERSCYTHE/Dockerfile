FROM python:3.11-slim AS builder

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Install Playwright system dependencies
RUN apt-get update && apt-get install -y \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
    libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 \
    libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 \
    libasound2 \
 && playwright install chromium

# Copy application code
COPY app/ app/
COPY static/ static/

# Move Playwright browsers to a shared directory
RUN mkdir /ms-playwright \
 && cp -r /root/.cache/ms-playwright/* /ms-playwright

# ----------------------
# Final stage
# ----------------------
FROM python:3.11-slim

WORKDIR /app

# Install runtime system dependencies
RUN apt-get update && apt-get install -y \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
    libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 \
    libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 \
    libasound2 \
 && rm -rf /var/lib/apt/lists/*

# Copy installed site-packages and Playwright binaries from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /ms-playwright /ms-playwright

# Tell Playwright to look here
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

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
  CMD python -c "import os; os.system('exit 0')" || exit 1

# Run the FastAPI server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5051"]
