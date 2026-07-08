@echo off
title CyberSec Suite - Shutdown
color 0C

echo.
echo  ╔══════════════════════════════════════════════╗
echo  ║       CyberSec Suite - Shutdown              ║
echo  ╚══════════════════════════════════════════════╝
echo.

:: Navigate to the folder where this BAT file lives
cd /d "%~dp0"

:: Check if docker-compose.yml exists
if not exist "docker-compose.yml" (
    echo  [ERROR] docker-compose.yml not found in this folder.
    echo  Place this BAT file next to docker-compose.yml.
    echo.
    pause
    exit /b 1
)

:: Check if Docker is running
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo  [INFO] Docker is not running. Nothing to stop.
    echo.
    pause
    exit /b 0
)

:: Show running containers
echo  Currently running containers:
echo.
docker compose ps 2>nul
echo.

:: Stop containers
echo  Stopping all CyberSec Suite containers...
echo.
docker compose down
if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Failed to stop containers.
    echo  Try running: docker compose down --force
    echo.
    pause
    exit /b 1
)

echo.
echo  ╔══════════════════════════════════════════════╗
echo  ║    All containers stopped successfully.      ║
echo  ║                                              ║
echo  ║    To restart: run "Start CyberSec Suite"    ║
echo  ╚══════════════════════════════════════════════╝
echo.
echo  Closing in 5 seconds...
timeout /t 5 >nul
