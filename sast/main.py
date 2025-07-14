import os
import sys
import shutil
import uuid
import logging
import subprocess
from zipfile import ZipFile
from tarfile import open as TarOpen
from pathlib import Path
from dotenv import load_dotenv

from fastapi import FastAPI, UploadFile, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

import scan_engine

# Load environment variables
load_dotenv(".env")
load_dotenv()  # Also check local .env if exists

# Enhanced Logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s:%(lineno)d - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/tmp/sast_debug.log")
    ]
)
logger = logging.getLogger("app.main")
logger.info("🚀 SAST Service Starting Up...")
logger.info("📁 Working Directory: %s", os.getcwd())
logger.info("🐍 Python Version: %s", sys.version)
logger.info("📦 Available Tools Check:")
try:
    subprocess.run(["git", "--version"], capture_output=True, check=True)
    logger.info("✅ Git is available")
except Exception as e:
    logger.error("❌ Git not available: %s", e)
try:
    subprocess.run(["semgrep", "--version"], capture_output=True, check=True)
    logger.info("✅ Semgrep is available")
except Exception as e:
    logger.error("❌ Semgrep not available: %s", e)

app = FastAPI(title="VulnPrism SAST API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"]
)
templates = Jinja2Templates(directory="templates")

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning("Validation error: %s", exc)
    return JSONResponse({"detail": "Invalid payload"}, status_code=422)

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    logger.info("🌐 Frontend page requested from IP: %s", request.client.host if request.client else "unknown")
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health")
async def health_check():
    logger.debug("💓 Health check requested")
    return {"status": "ok"}

@app.post("/scan")
async def scan_code(
    request: Request,
    repo_url: str = Form(None),
    code_text: str = Form(None),
    file: UploadFile = None
):
    temp_id = str(uuid.uuid4())
    base_dir = os.path.join("/tmp", temp_id)
    code_dir = os.path.join(base_dir, "source")
    report_path = None

    logger.info("🔍 SCAN REQUEST RECEIVED - ID: %s", temp_id)
    logger.info("📊 Request Details:")
    logger.info("  - Client IP: %s", request.client.host if request.client else "unknown")
    logger.info("  - Repo URL: %s", repo_url if repo_url else "None")
    logger.info("  - Code Text Length: %s", len(code_text) if code_text else "None")
    logger.info("  - File Upload: %s", file.filename if file else "None")
    logger.info("📁 Temp Directory: %s", base_dir)

    try:
        logger.info("📂 Creating directories...")
        os.makedirs(code_dir, exist_ok=True)
        logger.info("✅ Directory created: %s", code_dir)

        # Git repo
        if repo_url:
            logger.info("🔗 Processing Git Repository...")
            logger.info("  - URL: %s", repo_url)
            logger.info("  - Target Dir: %s", code_dir)

            result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, code_dir],
                capture_output=True,
                text=True,
                timeout=300
            )
            logger.info("📋 Git Clone Result:")
            logger.info("  - Return Code: %s", result.returncode)
            logger.info("  - STDOUT: %s", result.stdout)
            logger.info("  - STDERR: %s", result.stderr)

            if result.returncode != 0:
                logger.error("❌ Git clone failed!")
                raise HTTPException(400, f"Clone failed: {result.stderr}")
            logger.info("✅ Git clone successful")

        # Pasted code
        elif code_text:
            logger.info("📝 Processing Pasted Code...")
            snippet_path = os.path.join(code_dir, "snippet.txt")
            logger.info("  - Writing to: %s", snippet_path)
            logger.info("  - Code length: %d characters", len(code_text))

            with open(snippet_path, "w") as f:
                f.write(code_text)
            logger.info("✅ Code snippet saved")

        # Uploaded file
        elif file:
            logger.info("📁 Processing File Upload...")
            logger.info("  - Original filename: %s", file.filename)
            logger.info("  - Content type: %s", file.content_type)

            safe_filename = Path(file.filename).name
            upload_path = os.path.join(base_dir, safe_filename)
            logger.info("  - Safe filename: %s", safe_filename)
            logger.info("  - Upload path: %s", upload_path)

            # Save uploaded file
            with open(upload_path, "wb") as f:
                shutil.copyfileobj(file.file, f)

            file_size = os.path.getsize(upload_path)
            logger.info("  - File saved, size: %d bytes", file_size)

            # Archive handling
            if safe_filename.endswith(".zip"):
                logger.info("📦 Extracting ZIP archive...")
                with ZipFile(upload_path, "r") as z:
                    z.extractall(code_dir)
                logger.info("✅ ZIP extracted")
            elif safe_filename.endswith((".tar.gz", ".tgz", ".tar")):
                logger.info("📦 Extracting TAR archive...")
                with TarOpen(upload_path, "r:*") as t:
                    t.extractall(code_dir)
                logger.info("✅ TAR extracted")
            else:
                logger.info("📄 Moving single file...")
                shutil.move(upload_path, os.path.join(code_dir, safe_filename))
                logger.info("✅ File moved")
        else:
            logger.error("❌ No input provided!")
            raise HTTPException(400, "No input provided")

        # List files in code directory
        logger.info("📋 Files in scan directory:")
        try:
            for root, dirs, files in os.walk(code_dir):
                level = root.replace(code_dir, '').count(os.sep)
                indent = ' ' * 2 * level
                logger.info("  %s%s/", indent, os.path.basename(root))
                subindent = ' ' * 2 * (level + 1)
                for file in files:
                    logger.info("  %s%s", subindent, file)
        except Exception as e:
            logger.error("❌ Error listing files: %s", e)

        # Run scan
        logger.info("🔍 Starting security scan...")
        logger.info("  - Scan ID: %s", temp_id)
        logger.info("  - Code Directory: %s", code_dir)

        try:
            report_path = scan_engine.run_full_scan_and_report(code_dir, temp_id)
            logger.info("📊 Scan engine completed")
            logger.info("  - Report path: %s", report_path)

            if not report_path:
                logger.error("❌ Scan engine returned None for report path")
                raise HTTPException(500, "Report generation failed - no path returned")

            if not os.path.exists(report_path):
                logger.error("❌ Report file does not exist: %s", report_path)
                raise HTTPException(500, f"Report file not found: {report_path}")

            report_size = os.path.getsize(report_path)
            logger.info("✅ Report generated successfully")
            logger.info("  - File size: %d bytes", report_size)

        except Exception as scan_error:
            logger.error("❌ Scan engine error: %s", scan_error, exc_info=True)
            raise HTTPException(500, f"Scan failed: {str(scan_error)}")

        logger.info("🎉 Scan complete - returning PDF report")
        return FileResponse(
            report_path,
            filename=f"VulnPrism_Report_{temp_id}.pdf",
            media_type="application/pdf"
        )

    except subprocess.TimeoutExpired:
        logger.error("⏰ Operation timed out for scan ID: %s", temp_id)
        raise HTTPException(408, "Operation timed out")
    except HTTPException as he:
        logger.error("🚫 HTTP Exception for scan ID %s: %s", temp_id, he.detail)
        raise
    except Exception as e:
        logger.error("💥 Unexpected error for scan ID %s: %s", temp_id, e, exc_info=True)
        raise HTTPException(500, f"Internal server error: {str(e)}")
    finally:
        # Clean up temporary directory
        if os.path.exists(base_dir):
            logger.info("🧹 Cleaning up temporary directory: %s", base_dir)
            try:
                shutil.rmtree(base_dir)
                logger.info("✅ Cleanup successful")
            except OSError as e:
                logger.error("❌ Cleanup error: %s", e)
