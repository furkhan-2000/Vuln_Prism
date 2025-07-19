FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Create non-root user to match Kubernetes security context
RUN groupadd --system --gid 1000 appuser && \
    useradd --system --uid 1000 --gid 1000 --create-home appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 3000

CMD ["python", "backend.py"]
