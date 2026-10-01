"""
SecureScript Multi-Tenant WAF Platform Launcher.

Starts the Uvicorn ASGI server running the Multi-Tenant WAF Gateway.
Automatically opens the platform sign-up page in your default browser.
"""

import sys
import threading
import time
import webbrowser
import uvicorn


def main():
    print("=" * 75)
    print("     SecureScript: Multi-Tenant SaaS Web Application Firewall")
    print("=" * 75)
    print("")
    print("  Platform UI:")
    print("  * Platform Portal:       http://127.0.0.1:8000/platform")
    print("  * Direct Protected App:  http://127.0.0.1:8000/")
    print("  * Sign Up:               http://127.0.0.1:8000/signup")
    print("  * Login:                 http://127.0.0.1:8000/login")
    print("  * My Projects:           http://127.0.0.1:8000/app/projects")
    print("  * Connect New Site:      http://127.0.0.1:8000/app/projects/new")
    print("")
    print("  Platform API:")
    print("  * Register:              POST http://127.0.0.1:8000/auth/register")
    print("  * Login:                 POST http://127.0.0.1:8000/auth/login")
    print("  * Create Project:        POST http://127.0.0.1:8000/platform/projects")
    print("  * WAF Proxy:             http://127.0.0.1:8000/proxy/{slug}/")
    print("  * API Documentation:     http://127.0.0.1:8000/docs")
    print("")
    print("  Telemetry & Legacy:")
    print("  * Security Dashboard:    http://127.0.0.1:8000/dashboard")
    print("  * SIEM Feed:             http://127.0.0.1:8000/api/v1/siem/events")
    print("  * CSP Reports:           http://127.0.0.1:8000/api/v1/csp-report")
    print("")
    print("  Detection Engine:")
    print("  * Fast-Path Lexer:       Active (< 2ms SLA)")
    print("  * PyTorch Bi-LSTM:       Active (< 20ms SLA)")
    print("  * WAF Mode:              BLOCK")
    print("")
    print("=" * 75)
    print("\nStarting WAF Platform on http://127.0.0.1:8000 ... (Press Ctrl+C to stop)\n")

    def open_browser():
        time.sleep(1.5)
        webbrowser.open("http://127.0.0.1:8000/signup")

    threading.Thread(target=open_browser, daemon=True).start()

    uvicorn.run(
        "securescript.proxy.gateway:waf_app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
