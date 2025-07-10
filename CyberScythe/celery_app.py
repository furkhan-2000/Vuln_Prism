
from celery import Celery
from config import DATABASE_URL

# Configure Celery
celery_app = Celery(
    "cyberscythe",
    broker="redis://localhost:6379/0",  # Redis as message broker
    backend="redis://localhost:6379/1"   # Redis as result backend
)

celery_app.conf.update(
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    timezone='UTC',
    enable_utc=True,
)

# Import tasks after celery_app is defined to avoid circular imports
from core.scanner import run_scan_task
celery_app.task(name="run_scan_task")(run_scan_task)
