FROM python:3.11-slim AS builder

# Set environment variables for Python and pip
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Set the working directory inside the container
WORKDIR /app

# Copy only the requirements file to leverage Docker's build cache
COPY requirements.txt .

# Install system dependencies and Python packages into a virtual environment.
# This layer also installs Playwright's browser binaries.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc python3-dev \
        libnss3 libatk1.0-0 libatk-bridge2.0-0 libx11-xcb1 libxcb1 \
        libxcomposite1 libxcursor1 libxdamage1 libxext6 libxfixes3 \
        libxi6 libpango-1.0-0 libcairo2 libglib2.0-0 libdbus-1-3 \
        libdrm2 libgbm1 libasound2 libpangocairo-1.0-0 libxrandr2 \
        libxss1 libwayland-client0 libwayland-cursor0 libwayland-egl1 \
        libjpeg62-turbo libwebp7 libcups2 libxkbcommon0 fonts-liberation \
        wget ca-certificates && \
    # Create a virtual environment at /install
    python -m venv /install && \
    # Install pip and project dependencies into the virtual environment
    /install/bin/pip install --upgrade pip && \
    /install/bin/pip install --no-cache-dir -r requirements.txt && \
    # Install Playwright browser binaries (Chromium) with dependencies
    /install/bin/playwright install chromium --with-deps && \
    # Clean up build artifacts and apt cache to reduce layer size
    find /install -name "*.pyc" -delete && \
    find /install -name "__pycache__" -type d -exec rm -rf {} + && \
    apt-get purge -y --auto-remove gcc python3-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.cache/pip

# ----------------- Runtime stage -----------------
# Use a minimal slim Python image for the final runtime environment
FROM python:3.11-slim

# Set environment variables for Python and pip
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Set the working directory inside the container
WORKDIR /app

# Copy the installed Python virtual environment from the builder stage
COPY --from=builder /install /install
# Copy Playwright's browser binaries cache from the builder stage.
# By default, playwright installs them in /root/.cache/ms-playwright.
COPY --from=builder /root/.cache/ms-playwright /root/.cache/ms-playwright

# Copy the application files
COPY app/ app/
COPY static/ static/

# Create a non-root user and set up necessary directories
RUN groupadd --system --gid 1000 malware && \
    useradd --system --uid 1000 --gid 1000 --create-home malware && \
    mkdir -p /app/static/reports /app/logs /home/malware/.cache && \
    # Move the Playwright cache to the non-root user's home directory
    # This is crucial for Playwright to function correctly when running as 'malware' user
    mv /root/.cache/ms-playwright /home/malware/.cache 2>/dev/null || true && \
    chown -R malware:malware /app /home/malware

# Switch to the non-root user
USER malware

# Add the virtual environment's bin directory to the PATH
ENV PATH="/install/bin:$PATH"

# Expose the port the application listens on
EXPOSE 5051

# Define a health check for the container
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import httpx; httpx.get('http://0.0.0.0:5051/health')" || exit 1

# Command to run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5051"]