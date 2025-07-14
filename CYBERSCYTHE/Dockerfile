FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Create user first
RUN groupadd --system --gid 1000 malware && \
    useradd --system --uid 1000 --gid 1000 --create-home malware

# Install system dependencies and Python packages in one layer
COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc python3-dev \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libx11-xcb1 libxcb1 \
    libxcomposite1 libxcursor1 libxdamage1 libxext6 libxfixes3 \
    libxi6 libpango-1.0-0 libcairo2 libglib2.0-0 libdbus-1-3 \
    libdrm2 libgbm1 libasound2 libpangocairo-1.0-0 libxrandr2 \
    libxss1 libwayland-client0 libwayland-cursor0 libwayland-egl1 \
    libjpeg62-turbo libwebp7 libcups2 libxkbcommon0 fonts-liberation \
    wget ca-certificates && \
    pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    playwright install chromium --with-deps && \
    # Aggressive cleanup
    apt-get purge -y --auto-remove gcc python3-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.cache/pip && \
    find /root/.cache/ms-playwright -type f \( -name "*.log" -o -name "*.tmp" -o -name "*.zip" \) -delete 2>/dev/null || true && \
    find /root/.cache/ms-playwright -name "*firefox*" -type d -exec rm -rf {} + 2>/dev/null || true && \
    find /root/.cache/ms-playwright -name "*webkit*" -type d -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python3.11/site-packages -name "*.pyc" -delete && \
    find /usr/local/lib/python3.11/site-packages -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Copy application files and set up directories
COPY app/ app/
COPY static/ static/
RUN mkdir -p /app/static/reports /app/logs /home/malware/.cache && \
    mv /root/.cache/ms-playwright /home/malware/.cache/ 2>/dev/null || true && \
    chown -R malware:malware /app /home/malware

USER malware

EXPOSE 5051

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import httpx; httpx.get('http://0.0.0.0:5051/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5051"]

