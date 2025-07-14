# Stage 1: Builder
FROM python:3.11.9-slim AS builder

# Install essential build tools and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends     build-essential     pkg-config     libcairo2-dev     git     curl     unzip     openjdk-17-jre-headless 
    && rm -rf /var/lib/apt/lists/*

# Set up a virtual environment
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install security tools in the virtual environment
RUN pip install --no-cache-dir semgrep bandit

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Dependency-Check
RUN curl -sLo /tmp/dependency-check.zip https://github.com/jeremylong/DependencyCheck/releases/download/v9.0.9/dependency-check-9.0.9-release.zip && \
    unzip /tmp/dependency-check.zip -d /opt && \
    rm /tmp/dependency-check.zip

# ---

# Stage 2: Final Image
FROM python:3.11.9-slim

# Install only necessary runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
    git \
    openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# Copy the virtual environment from the builder stage
COPY --from=builder /opt/venv /opt/venv

# Copy the security tools from the builder stage
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /opt/dependency-check /opt/dependency-check

# Set the PATH to include the virtual environment
ENV PATH="/opt/venv/bin:$PATH"

# Set up the application directory
WORKDIR /sast
COPY . .

# Create a non-root user and switch to it
RUN groupadd --system --gid 1001 appuser && \
    useradd --system --uid 1001 --gid 1001 appuser && \
    chown -R appuser:appuser /sast
USER appuser

# Healthcheck and entrypoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:5050/health || exit 1

EXPOSE 5050
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5050"]