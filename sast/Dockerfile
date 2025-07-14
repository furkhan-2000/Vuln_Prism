FROM python:3.11.9-slim AS builder

WORKDIR /app

# Install build dependencies and clean up in single layer
RUN apt-get update &&     apt-get install -y --no-install-recommends       build-essential pkg-config libcairo2-dev libfreetype6-dev       libpng-dev libjpeg-dev python3-dev git curl unzip       openjdk-17-jre-headless libgl1-mesa-glx libglib2.0-0 &&     rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && apt-get clean

COPY requirements.txt .

# Install Python packages and tools, then clean up aggressively
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir semgrep bandit && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    curl -sLo dependency-check.zip https://github.com/jeremylong/DependencyCheck/releases/download/v9.0.9/dependency-check-9.0.9-release.zip && \
    unzip dependency-check.zip -d /opt && \
    rm -f dependency-check.zip && \
    ln -s /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check.sh && \
    # Aggressive cleanup to save space
    apt-get purge -y --auto-remove build-essential pkg-config python3-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.cache/pip && \
    find /usr/local/lib/python3.11/site-packages -name "*.pyc" -delete && \
    find /usr/local/lib/python3.11/site-packages -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true && \
    # Clean up dependency-check unnecessary files
    find /opt/dependency-check -name "*.jar.bak" -delete 2>/dev/null || true && \
    find /opt/dependency-check -name "*.log" -delete 2>/dev/null || true

FROM python:3.11.9-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /sast

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      git curl unzip libcairo2 libfreetype6 libpng16-16 \
      libjpeg62-turbo fontconfig tini openjdk-17-jre-headless \
      libgl1-mesa-glx libglib2.0-0 && \
    rm -rf /var/lib/apt/lists/*

# Java environment
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV PATH="${JAVA_HOME}/bin:${PATH}"
ENV HOME=/home/jenkins

# Matplotlib config (headless)
ENV MPLCONFIGDIR=/tmp
ENV MATPLOTLIBRC=/tmp
RUN mkdir -p /tmp && chmod 777 /tmp && \
    echo "backend: Agg" > /tmp/matplotlibrc

COPY --from=builder /app/requirements.txt /sast/requirements.txt
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages/
COPY --from=builder /usr/local/bin/semgrep /usr/local/bin/semgrep
COPY --from=builder /usr/local/bin/bandit /usr/local/bin/bandit
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /usr/local/bin/dependency-check.sh /usr/local/bin/dependency-check.sh
COPY --from=builder /usr/local/bin/uvicorn /usr/local/bin/uvicorn
COPY --from=builder /opt/dependency-check /opt/dependency-check/

COPY . /sast/

RUN groupadd --system --gid 1001 jenkins && \
    useradd --system --uid 1001 --gid 1001 --create-home --home-dir /home/jenkins jenkins && \
    chown -R jenkins:jenkins /sast /home/jenkins /tmp

USER jenkins

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:5050/health || exit 1

EXPOSE 5050

ENTRYPOINT ["/usr/bin/tini", "--"]

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5050"]
