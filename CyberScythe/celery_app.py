
from celery import Celery
from config import REDIS_BROKER_URL, REDIS_BACKEND_URL, MONITORED_SITES
import json
import os
import logging

logger = logging.getLogger(__name__)

# Configure Celery
celery_app = Celery(
    "cyberscythe",
    broker=REDIS_BROKER_URL,  # Redis as message broker
    backend=REDIS_BACKEND_URL   # Redis as result backend
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
    beat_schedule={
        'run-periodic-scan-every-day': {
            'task': 'periodic_scan',
            'schedule': 86400.0, # Every 24 hours (86400 seconds)
            'args': ()
        },
    },
)

# Import tasks after celery_app is defined to avoid circular imports
from core.scanner import run_scan_task
celery_app.task(name="run_scan_task")(run_scan_task)

@celery_app.task(name="periodic_scan")
def periodic_scan():
    """Celery periodic task to run scans on monitored sites."""
    from core.database import SessionLocal, Scan # Import here to avoid circular dependency
    from config import MONITORED_SITES
    import logging

    logger = logging.getLogger(__name__)
    logger.info("Running periodic scan for monitored sites...")

    # Helper functions for differential scanning
    def get_scan_state_path(site_url: str) -> str:
        """Generates a unique file path for storing a site's scan state."""
        # Use a hashed version of the URL to create a safe filename
        import hashlib
        url_hash = hashlib.sha256(site_url.encode()).hexdigest()
        return os.path.join(SCAN_STATES_DIR, f"{url_hash}.json")

    def load_scan_state(site_url: str) -> dict:
        """Loads the previous scan state for a given site."""
        state_path = get_scan_state_path(site_url)
        if os.path.exists(state_path):
            with open(state_path, 'r') as f:
                return json.load(f)
        return {"crawled_urls": [], "forms": [], "url_params": []}

    def save_scan_state(site_url: str, state: dict):
        """Saves the current scan state for a given site."""
        state_path = get_scan_state_path(site_url)
        os.makedirs(os.path.dirname(state_path), exist_ok=True)
        with open(state_path, 'w') as f:
            json.dump(state, f, indent=4)

    def diff_scan_states(old_state: dict, new_state: dict) -> dict:
        """Compares two scan states and returns detected changes."""
        changes = {
            "new_urls": list(set(new_state["crawled_urls"]) - set(old_state["crawled_urls"])),
            "removed_urls": list(set(old_state["crawled_urls"]) - set(new_state["crawled_urls"])),
            # More sophisticated diffing for forms and parameters can be added here
            # For simplicity, we'll just check for new forms/params for now
            "new_forms": [f for f in new_state["forms"] if f not in old_state["forms"]],
            "new_url_params": list(set(new_state["url_params"]) - set(old_state["url_params"])),
        }
        return changes

    db = SessionLocal()
    try:
        for site_url in MONITORED_SITES:
            logger.info(f"Initiating periodic scan for: {site_url}")
            
            # Load previous state
            old_state = load_scan_state(site_url)

            # Run a full crawl to get the current state
            # Note: This will be a full crawl, not just a diff. The diff is for reporting/focused scanning.
            # For a true differential scan, the crawler itself would need to be smarter.
            # For now, we'll use the existing crawl_and_discover and then diff the results.
            # This requires running crawl_and_discover outside of the main run_scan_task for state comparison.
            # This is a simplification for now, as crawl_and_discover is currently part of run_scan_task.
            # A more robust solution would separate crawling from scanning.
            
            # For demonstration, we'll simulate a new state for diffing. In a real scenario,
            # you'd run a dedicated lightweight crawler here to get the current_state.
            # For now, we'll assume run_scan_task will eventually provide the new state.
            
            # Create a new scan record for the periodic scan
            new_scan = Scan(target_url=site_url, status="pending")
            db.add(new_scan)
            db.commit()
            db.refresh(new_scan)
            
            # Trigger the scan task. The scan task itself will generate the new state.
            run_scan_task.delay(new_scan.id, site_url, old_scan_state=old_state) # Pass old state for diffing later

    except Exception as e:
        logger.error(f"Error during periodic scan: {e}", exc_info=True)
    finally:
        db.close()
