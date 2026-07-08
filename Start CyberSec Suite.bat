@echo off
title CyberSec Suite - Launcher
color 0B

echo.
echo  ╔══════════════════════════════════════════════╗
echo  ║         CyberSec Suite - Launcher            ║
echo  ║      AI-Powered Security Operations          ║
echo  ╚══════════════════════════════════════════════╝
echo.

:: Navigate to the folder where this BAT file lives
cd /d "%~dp0"

:: Check if docker-compose.yml exists here
if not exist "docker-compose.yml" (
    echo  [ERROR] docker-compose.yml not found in this folder.
    echo  Place this BAT file next to docker-compose.yml.
    echo.
    pause
    exit /b 1
)

:: ── Step 1: Check Docker ──────────────────────────────
echo  [1/5] Checking Docker Desktop...
docker info >nul 2>&1
if %errorlevel% equ 0 (
    echo        Docker is already running.
    goto :docker_ready
)

echo        Docker is not running. Starting Docker Desktop...
start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe" 2>nul
if %errorlevel% neq 0 (
    start "" "%ProgramFiles%\Docker\Docker\Docker Desktop.exe" 2>nul
)

echo        Waiting for Docker to start (this may take 30-60 seconds)...
set /a attempts=0

:wait_docker
timeout /t 3 /nobreak >nul
docker info >nul 2>&1
if %errorlevel% equ 0 goto :docker_ready
set /a attempts+=1
if %attempts% geq 40 (
    echo.
    echo  [ERROR] Docker did not start after 2 minutes.
    echo  Please open Docker Desktop manually and try again.
    echo.
    pause
    exit /b 1
)
echo        Still waiting... (%attempts%)
goto :wait_docker

:docker_ready
echo        Docker is ready.
echo.

:: ── Step 2: Create .env if missing ────────────────────
if not exist ".env" (
    if exist ".env.example" (
        echo  [2/5] Creating .env from .env.example...
        copy .env.example .env >nul
        echo        .env file created.
    ) else (
        echo  [2/5] No .env file found. Continuing anyway...
    )
) else (
    echo  [2/5] .env file exists.
)
echo.

:: ── Step 3: Build and start containers ────────────────
echo  [3/5] Building and starting containers...
echo        This may take 2-5 minutes on first run...
echo.
docker compose up --build -d
if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Failed to start containers.
    echo  Check the error messages above.
    echo.
    pause
    exit /b 1
)
echo.

:: ── Step 4: Wait for services ─────────────────────────
echo  [4/5] Waiting for services to come online...
set /a health_attempts=0

:wait_health
timeout /t 3 /nobreak >nul
curl -s -o nul -w "%%{http_code}" http://localhost:8000/api/health 2>nul | findstr "200" >nul 2>&1
if %errorlevel% equ 0 goto :services_ready

:: Fallback: check if containers are running
docker compose ps --format "{{.State}}" 2>nul | findstr /i "running" >nul 2>&1
if %errorlevel% equ 0 (
    set /a health_attempts+=1
    if %health_attempts% geq 20 goto :services_ready
)

set /a health_attempts+=1
if %health_attempts% geq 30 (
    echo        Services taking longer than expected...
    goto :services_ready
)
echo        Waiting... (%health_attempts%)
goto :wait_health

:services_ready
echo        All services are running.
echo.

:: ── Step 5: Open browser ──────────────────────────────
echo  [5/5] Opening CyberSec Suite in browser...
timeout /t 2 /nobreak >nul
start http://localhost:4000
echo.

:: ── Done ──────────────────────────────────────────────
echo  ╔══════════════════════════════════════════════╗
echo  ║       CyberSec Suite is running!             ║
echo  ║                                              ║
echo  ║  Frontend:  http://localhost:4000             ║
echo  ║  API Docs:  http://localhost:8000/api/docs    ║
echo  ║                                              ║
echo  ║  To stop: run "Stop CyberSec Suite.bat"      ║
echo  ║  Or press any key in this window to stop.    ║
echo  ╚══════════════════════════════════════════════╝
echo.
pause >nul

echo.
echo  Shutting down CyberSec Suite...
docker compose down
echo  All containers stopped. Goodbye!
timeout /t 3 >nul
