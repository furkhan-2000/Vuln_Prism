# --- Stage 1: Builder ---
FROM python:3.11-slim AS builder

# Install system dependencies required by Playwright and other tools
RUN apt-get update && apt-get install -y --no-install-recommends     libnss3     libxss1     libasound2     libatk-bridge2.0-0     libgtk-3-0     libgbm-dev     libu2f-udev     libvulkan1     fonts-liberation     xdg-utils     curl     build-essential     pkg-config     libcairo2-dev     --no-install-recommends &&     rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers in the builder stage
# Playwright installs browsers to ~/.cache/ms-playwright by default, which is /root/.cache/ms-playwright in this stage.
# We will copy this to a non-root user's home directory in the runtime stage.
RUN playwright install --with-deps chromium

# --- Stage 2: Runtime ---
FROM python:3.11-slim

# Install only the essential runtime dependencies for Playwright
RUN apt-get update && apt-get install -y --no-install-recommends     libnss3     libxss1     libasound2     libatk-bridge2.0-0     libgtk-3-0     libgbm-dev     libu2f-udev     libvulkan1     fonts-liberation     xdg-utils     curl     --no-install-recommends &&     rm -rf /var/lib/apt/lists/*

# Create a non-root user and group
RUN groupadd --system --gid 10001 malware && useradd --system --uid 10001 --gid 10001 malware

# Set the working directory and change ownership
WORKDIR /app
RUN chown malware:malware /app

# Copy installed Python packages from builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# Copy Playwright browser binaries from builder stage to a location accessible by appuser
# Playwright expects browsers in ~/.cache/ms-playwright. We'll set HOME for appuser to /app
# and copy to /app/.cache/ms-playwright
COPY --from=builder /root/.cache/ms-playwright /app/.cache/ms-playwright
RUN chown -R malware:malware /app/.cache

# Copy the application code
COPY . .

# Set the user to non-root
USER malware

# Expose the port the app runs on
EXPOSE 5051 

# Set DATABASE_URL environment variable
ENV DATABASE_URL="postgresql://user:password@host:port/dbname"

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --retries=3   CMD curl -f http://localhost:5051/health || exit 1

# Command to run the application
# Set HOME for Playwright to find its browsers
CMD ["/usr/local/bin/python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5051", "--log-level", "info"]