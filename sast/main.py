import os
import shutil
import uuid
import logging
import subprocess
from zipfile import ZipFile
from tarfile import open as TarOpen
from pathlib import Path

from fastapi import FastAPI, UploadFile, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

import scan_engine

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("app.main")

app = FastAPI(title="VulnPrism SAST API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)
templates = Jinja2Templates(directory="templates")

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning("Validation error: %s", exc)
    return JSONResponse({"detail": "Invalid payload"}, status_code=422)

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.post("/scan")
async def scan_code(
    request: Request,
    repo_url: str = Form(None),
    code_text: str = Form(None),
    file: UploadFile = None
):
    temp_id = str(uuid.uuid4())
    base_dir = os.path.join("/tmp", temp_id) # Use os.path.join for robustness
    code_dir = os.path.join(base_dir, "source")
    report_path = None # Initialize report_path

    try:
        os.makedirs(code_dir, exist_ok=True) # Create code_dir first

        # Git repo
        if repo_url:
            logger.info("[%s] Cloning repo %s", temp_id, repo_url)
            # Ensure git clone is run from the parent directory of code_dir or specify target
            result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, code_dir],
                capture_output=True,
                text=True,
                timeout=300
            )
            if result.returncode != 0:
                logger.error("[%s] Clone failed: %s", temp_id, result.stderr)
                raise HTTPException(400, f"Clone failed: {result.stderr}")

        # Pasted code
        elif code_text:
            logger.info("[%s] Writing pasted code", temp_id)
            snippet_path = os.path.join(code_dir, "snippet.txt")
            with open(snippet_path, "w") as f:
                f.write(code_text)

        # Uploaded file
        elif file:
            logger.info("[%s] Handling file upload %s", temp_id, file.filename)
            safe_filename = Path(file.filename).name
            upload_path = os.path.join(base_dir, safe_filename) # Upload to base_dir initially

            with open(upload_path, "wb") as f:
                shutil.copyfileobj(file.file, f)

            # Archive handling
            if safe_filename.endswith(".zip"):
                with ZipFile(upload_path, "r") as z:
                    z.extractall(code_dir)
            elif safe_filename.endswith((".tar.gz", ".tgz", ".tar")):
                with TarOpen(upload_path, "r:*") as t:
                    t.extractall(code_dir)
            else:
                # If it's a single file, move it directly into code_dir
                shutil.move(upload_path, os.path.join(code_dir, safe_filename))
        else:
            raise HTTPException(400, "No input provided")

        # Run scan
        logger.info("[%s] Starting scan...", temp_id)
        report_path = scan_engine.run_full_scan_and_report(code_dir, temp_id)
        if not report_path or not os.path.exists(report_path):
            raise HTTPException(500, "Report generation failed or report path is invalid")

        logger.info("[%s] Scan complete", temp_id)
        return FileResponse(
            report_path,
            filename=f"VulnPrism_Report_{temp_id}.pdf",
            media_type="application/pdf"
        )

    except subprocess.TimeoutExpired:
        logger.error("[%s] Operation timed out", temp_id)
        raise HTTPException(408, "Operation timed out")
    except HTTPException:
        raise
    except Exception as e:
        logger.error("[%s] Scan failed: %s", temp_id, e, exc_info=True)
        raise HTTPException(500, f"Internal server error: {str(e)}")
    finally:
        # Clean up temporary directory
        if os.path.exists(base_dir):
            logger.info("[%s] Cleaning up temporary directory %s", temp_id, base_dir)
            try:
                shutil.rmtree(base_dir)
            except OSError as e:
                logger.error("[%s] Error cleaning up directory %s: %s", temp_id, base_dir, e)
