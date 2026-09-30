#!/usr/bin/env python3
"""
CyberCop AI - Start All Services (Backend & Frontend Dashboard)

This script starts:
1. FastAPI Backend Server (http://localhost:8000)
2. React Vite Frontend Dashboard (http://localhost:5173)

Press Ctrl+C at any time to gracefully stop all services.
"""

import os
import sys
import subprocess
import signal
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
DASHBOARD_DIR = os.path.join(BASE_DIR, "dashboard")

processes = []


def cleanup(signum=None, frame=None):
    print("\n\n🛑 Shutting down CyberCop AI services...")
    for proc in processes:
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
    print("✅ All services stopped successfully.")
    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    print("==================================================")
    print("🚀 CyberCop AI Security Suite - Starting All Services")
    print("==================================================\n")

    # 1. Start Backend Server
    print("📡 [1/2] Launching FastAPI Backend Server...")
    backend_proc = subprocess.Popen(
        [sys.executable, "app.py"],
        cwd=BACKEND_DIR
    )
    processes.append(backend_proc)
    print("   👉 Backend API running at: http://localhost:8000 (API Docs: http://localhost:8000/docs)\n")

    time.sleep(2)

    # 2. Start Frontend Dashboard
    print("💻 [2/2] Launching React Dashboard Frontend...")
    npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
    dashboard_proc = subprocess.Popen(
        [npm_cmd, "run", "dev"],
        cwd=DASHBOARD_DIR
    )
    processes.append(dashboard_proc)
    print("   👉 Frontend UI running at: http://localhost:5173\n")

    print("--------------------------------------------------")
    print("🎉 All CyberCop AI services are now running!")
    print("   • Backend Server:   http://localhost:8000")
    print("   • Interactive UI:   http://localhost:5173")
    print("   Press Ctrl+C to stop all services.")
    print("--------------------------------------------------\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup()


if __name__ == "__main__":
    main()
