#!/usr/bin/env python3
"""
Start Flask app with ngrok for public URL testing
"""

import os
import sys
import time
import threading
from flask import Flask
from pyngrok import ngrok

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import your Flask app
from app import app

def start_ngrok():
    """Start ngrok tunnel"""
    # Get ngrok tunnel
    public_url = ngrok.connect(5000).public_url
    print(f"🌐 Public URL: {public_url}")
    print(f"📱 USSD Callback URL: {public_url}/ussd")
    print(f"🌍 Web App URL: {public_url}")
    return public_url

if __name__ == "__main__":
    print("🚀 Starting MediLinkBot with ngrok...")
    
    # Start ngrok in a separate thread
    ngrok_thread = threading.Thread(target=start_ngrok)
    ngrok_thread.daemon = True
    ngrok_thread.start()
    
    # Wait a moment for ngrok to start
    time.sleep(2)
    
    # Start Flask app
    print("📱 Flask app starting on port 5000...")
    print("🔧 Use the public URL above in your Africa's Talking dashboard")
    app.run(host='0.0.0.0', port=5000, debug=False)
