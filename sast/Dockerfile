# ─── Stage 1: Builder ─────────────────────────────────────────────────────────

FROM python:3.11.9-slim AS builder

# 1) Install build tools, curl, unzip, JRE
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential pkg-config libcairo2-dev git curl unzip openjdk-17-jre-headless && \
    rm -rf /var/lib/apt/lists/*

# 2) Create & activate venv
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# 3) Copy & install Python deps
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4) Install semgrep & bandit into venv
RUN pip install --no-cache-dir semgrep bandit

# 5) Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin

# 6) Download & unpack Dependency‑Check directly into a stable folder
RUN curl -sLo /tmp/dc.zip \
      https://github.com/jeremylong/DependencyCheck/releases/download/v9.0.9/dependency-check-9.0.9-release.zip && \
    unzip /tmp/dc.zip -d /opt/dependency-check && \
    rm /tmp/dc.zip && \
    chmod +x /opt/dependency-check/dependency-check/bin/dependency-check.sh

# ─── Stage 2: Runtime ─────────────────────────────────────────────────────────

FROM python:3.11.9-slim

# 7) Install minimal runtime deps (incl. curl for HEALTHCHECK)
RUN apt-get update && \
    apt-get install -y --no-install-recommends tini git curl openjdk-17-jre-headless && \
    rm -rf /var/lib/apt/lists/*

# 8) Copy venv, Trivy, and Dependency‑Check from builder
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /opt/dependency-check /opt/dependency-check

# 9) Ensure venv is first in PATH
ENV PATH="/opt/venv/bin:$PATH"

# 10) Add Dependency-Check to PATH
ENV PATH="/opt/dependency-check/dependency-check/bin:$PATH"

# 11) Re‑install semgrep & bandit into final venv (guarantees availability)
RUN pip install --no-cache-dir semgrep bandit

# 12) Copy application code
WORKDIR /sast
COPY . .

# 13) Create + switch to non‑root user
RUN groupadd --system --gid 1001 appuser &&     useradd --system --uid 1001 --gid 1001 appuser &&     mkdir -p /home/appuser &&     chown -R appuser:appuser /home/appuser /sast
ENV HOME=/home/appuser
RUN mkdir -p /home/appuser/.cache /home/appuser/.dependency-check && \
    chown -R appuser:appuser /home/appuser/.cache /home/appuser/.dependency-check

# Pre-populate Dependency-Check database
USER appuser
RUN dependency-check.sh --update
USER root # Switch back to root for subsequent commands if needed, or stay as appuser if all subsequent commands are user-specific

USER appuser


# 14) Healthcheck & entrypoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:5050/health || exit 1

EXPOSE 5050
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5050"]

