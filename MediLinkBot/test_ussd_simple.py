#!/usr/bin/env python3
"""
Simple USSD test without external dependencies
"""

import requests
import urllib.parse

BASE_URL = "http://localhost:5000"

def test_ussd():
    """Test USSD endpoint"""
    
    print("Testing MediLinkBot USSD...")
    
    # Test 1: Initial menu
    data = {
        'sessionId': 'test123',
        'phoneNumber': '+254712345678',
        'text': ''
    }
    
    try:
        print("\n1. Testing initial menu...")
        response = requests.post(f"{BASE_URL}/ussd", data=data)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
        
        if "CON Welcome to MediLinkBot" in response.text:
            print("PASS - Initial menu working!")
        else:
            print("FAIL - Initial menu failed")
            
    except Exception as e:
        print(f"Error: {e}")
        return False
    
    # Test 2: Symptom checker
    data['text'] = '1'
    try:
        print("\n2. Testing symptom categories...")
        response = requests.post(f"{BASE_URL}/ussd", data=data)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
        
        if "CON Select symptom category" in response.text:
            print("PASS - Symptom categories working!")
        else:
            print("FAIL - Symptom categories failed")
            
    except Exception as e:
        print(f"Error: {e}")
    
    # Test 3: Emergency contacts
    data['text'] = '3'
    try:
        print("\n3. Testing emergency contacts...")
        response = requests.post(f"{BASE_URL}/ussd", data=data)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
        
        if "END Emergency Contacts" in response.text:
            print("PASS - Emergency contacts working!")
        else:
            print("FAIL - Emergency contacts failed")
            
    except Exception as e:
        print(f"Error: {e}")
    
    print("\nUSSD testing completed!")
    return True

if __name__ == "__main__":
    test_ussd()
