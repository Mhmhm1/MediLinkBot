#!/usr/bin/env python3
"""
Start app with ngrok for public URL
"""

import os
import sys
import time
import threading
from flask import Flask
from pyngrok import ngrok

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app import app

def start_ngrok():
    """Start ngrok tunnel"""
    public_url = ngrok.connect(5000).public_url
    print(f"Public URL: {public_url}")
    print(f"SMS Callback: {public_url}/sms")
    print(f"USSD Callback: {public_url}/ussd")
    print(f"Web App: {public_url}")
    return public_url

if __name__ == "__main__":
    print("Starting MediLinkBot with ngrok...")
    
    # Start ngrok
    ngrok_thread = threading.Thread(target=start_ngrok)
    ngrok_thread.daemon = True
    ngrok_thread.start()
    
    time.sleep(2)
    
    # Start Flask
    print("Flask app starting...")
    app.run(host='0.0.0.0', port=5000, debug=False)
