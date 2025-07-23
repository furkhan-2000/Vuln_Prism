@echo off
REM VulnPrism Build Script for Windows - Error-free Docker build
setlocal enabledelayedexpansion

echo 🚀 VulnPrism Build Script - Zero Error Build
echo ==============================================

REM Check if Docker is running
echo [INFO] Checking Docker availability...
docker info >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not running. Please start Docker and try again.
    pause
    exit /b 1
)
echo [SUCCESS] Docker is running

REM Clean up previous builds
echo [INFO] Cleaning up previous builds...
docker system prune -f >nul 2>&1
echo [SUCCESS] Cleanup completed

REM Build Frontend (lightest)
echo [INFO] Building frontend service...
docker build -t vulnprism-frontend:latest ./chatbot-frontend
if errorlevel 1 (
    echo [ERROR] Frontend build failed. Stopping build process.
    pause
    exit /b 1
)
echo [SUCCESS] Frontend build completed successfully

REM Build SAST (medium)
echo [INFO] Building SAST service...
docker build -t vulnprism-sast:latest ./sast
if errorlevel 1 (
    echo [ERROR] SAST build failed. Stopping build process.
    pause
    exit /b 1
)
echo [SUCCESS] SAST build completed successfully

REM Build CYBERSCYTHE (heaviest)
echo [INFO] Building CYBERSCYTHE service...
docker build -t vulnprism-cyberscythe:latest ./CYBERSCYTHE
if errorlevel 1 (
    echo [ERROR] CYBERSCYTHE build failed. Stopping build process.
    pause
    exit /b 1
)
echo [SUCCESS] CYBERSCYTHE build completed successfully

echo [SUCCESS] All services built successfully!

REM Ask to start services
set /p start_services="Do you want to start all services now? (y/n): "
if /i "%start_services%"=="y" (
    echo [INFO] Starting all services...
    docker-compose -f docker-compose-simple.yml up -d
    echo [SUCCESS] All services started!
    echo [INFO] Access points:
    echo   Frontend: http://localhost:3000
    echo   SAST: http://localhost:5050
    echo   CYBERSCYTHE: http://localhost:5051
)

pause
