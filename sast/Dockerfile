# Dockerfile

# Builder stage
FROM python:3.11.9-slim AS builder

WORKDIR /app

# Install build and runtime dependencies (including Java 17)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      pkg-config \
      libcairo2-dev \
      libfreetype6-dev \
      libpng-dev \
      libjpeg-dev \
      python3-dev \
      git \
      curl \
      unzip \
      openjdk-17-jre-headless \
      libgl1-mesa-glx \
      libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Install semgrep, bandit, trivy, and dependency-check CLI
RUN pip install --no-cache-dir semgrep bandit && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    curl -sLo dependency-check.zip https://github.com/jeremylong/DependencyCheck/releases/download/v9.0.9/dependency-check-9.0.9-release.zip && \
    unzip dependency-check.zip -d /opt && \
    rm dependency-check.zip && \
    ln -s /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check.sh

# Final stage
FROM python:3.11.9-slim

WORKDIR /sast

# Install runtime libraries and Java
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      git \
      curl \
      unzip \
      libcairo2 \
      libfreetype6 \
      libpng16-16 \
      libjpeg62-turbo \
      fontconfig \
      tini \
      openjdk-17-jre-headless \
      libgl1-mesa-glx \
      libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Java environment
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV PATH="${JAVA_HOME}/bin:${PATH}"
ENV HOME=/home/jenkins

# Matplotlib config (headless)
ENV MPLCONFIGDIR=/tmp
ENV MATPLOTLIBRC=/tmp
RUN mkdir -p /tmp && chmod 777 /tmp && \
    echo "backend: Agg" > /tmp/matplotlibrc

# Copy installed Python packages & tools from builder
COPY --from=builder /app/requirements.txt /sast/requirements.txt
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages/
COPY --from=builder /usr/local/bin /usr/local/bin/
COPY --from=builder /opt/dependency-check /opt/dependency-check/

# Copy application source
COPY . /sast/

# Create non-root user
RUN groupadd --system jenkins && \
    useradd --system --gid jenkins --create-home --home-dir /home/jenkins jenkins && \
    chown -R jenkins:jenkins /sast /home/jenkins /tmp

USER jenkins

# Healthcheck and entrypoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl --fail http://localhost:5050/health || exit 1

EXPOSE 5050
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5050"]
