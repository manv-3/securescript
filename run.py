"""
SecureScript Full-Stack WAF Launcher.

Starts the Uvicorn ASGI server running the Reverse-Proxy WAF Gateway,
protecting https://basic-form-project.vercel.app with the 3-tier hybrid inspection engine.
Automatically opens the protected website and security dashboard in your default browser.
"""

import sys
import threading
import time
import webbrowser
import uvicorn


def main():
    print("=" * 75)
    print("     SecureScript: Real-Time Web Application Firewall (WAF)")
    print("=" * 75)
    print("  * Target Protected Website:      https://basic-form-project.vercel.app")
    print("  * Backend API Target:            https://basic-form-project.onrender.com")
    print("  * Local Protected URL:           http://127.0.0.1:8000/")
    print("  * Fast-Path Lexer:               Active (< 2ms SLA)")
    print("  * PyTorch Bi-LSTM Neural Engine: Active (< 20ms SLA)")
    print("  * Security Operations Dashboard: http://127.0.0.1:8000/dashboard")
    print("  * SIEM Telemetry Feed:           http://127.0.0.1:8000/api/v1/siem/events")
    print("  * Swagger API Documentation:     http://127.0.0.1:8000/docs")
    print("=" * 75)
    print("\nStarting WAF Gateway on http://127.0.0.1:8000 ... (Press Ctrl+C to stop)\n")

    # Automatically open the protected website in browser
    def open_browser():
        time.sleep(1.5)
        webbrowser.open("http://127.0.0.1:8000/")

    threading.Thread(target=open_browser, daemon=True).start()

    # Launch WAF Reverse-Proxy Gateway
    uvicorn.run(
        "securescript.proxy.gateway:waf_app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="info"
    )


if __name__ == "__main__":
    main()
