FROM python:3.11-slim AS builder

WORKDIR /app

COPY requirements.txt .

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc python3-dev && \
    pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    playwright install chromium --with-deps && \
    apt-get purge -y --auto-remove gcc python3-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY app/ app/
COPY static/ static/

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libx11-xcb1 \
    libxcb1 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxi6 \
    libpango-1.0-0 \
    libcairo2 \
    libglib2.0-0 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libasound2 \
    libpangocairo-1.0-0 \
    libxrandr2 \
    libxss1 \
    libwayland-client0 \
    libwayland-cursor0 \
    libwayland-egl1 \
    libjpeg62-turbo \
    libwebp7 \
    libcups2 \
    libxkbcommon0 \
    fonts-liberation \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /root/.cache/ms-playwright /home/malware/.cache/ms-playwright

COPY --from=builder /app/app /app/app
COPY --from=builder /app/static /app/static

RUN groupadd --system --gid 1234 malware && \
    useradd --system --uid 1002 --gid 1234 --create-home malware && \
    mkdir -p /app/static/reports /app/logs && \
    chown -R malware:malware /app /home/malware/.cache

USER malware

EXPOSE 5051

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import httpx; httpx.get('http://0.0.0.0:5051/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5051"]

