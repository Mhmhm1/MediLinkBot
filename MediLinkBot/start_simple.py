#!/usr/bin/env python3
"""
Start Flask app without ngrok for local testing
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app

if __name__ == "__main__":
    print("Starting MediLinkBot on localhost:5000...")
    print("SMS endpoint: http://localhost:5000/sms")
    print("USSD endpoint: http://localhost:5000/ussd")
    app.run(host='0.0.0.0', port=5000, debug=False)
