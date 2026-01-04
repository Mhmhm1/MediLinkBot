#!/usr/bin/env python3
"""
Test script for USSD functionality
This simulates Africa's Talking USSD requests to your Flask app
"""

import requests
import json

# Base URL for your Flask app (change if running on different port/host)
BASE_URL = "http://localhost:5000"

def test_ussd_endpoint():
    """Test the USSD endpoint with sample requests"""
    
    print("Testing MediLinkBot USSD functionality...")
    
    # Test 1: Initial menu
    print("\n1. Testing initial menu...")
    data = {
        'sessionId': 'test123',
        'phoneNumber': '+254712345678',
        'text': ''
    }
    
    try:
        response = requests.post(f"{BASE_URL}/ussd", data=data)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200 and "CON Welcome to MediLinkBot" in response.text:
            print("Initial menu test passed!")
        else:
            print("Initial menu test failed!")
            
    except requests.exceptions.ConnectionError:
        print("Cannot connect to Flask app. Make sure it's running on localhost:5000")
        return
    except Exception as e:
        print(f"Error: {e}")
        return
    
    # Test 2: Symptom checker
    print("\n2. Testing symptom checker...")
    data = {
        'sessionId': 'test123',
        'phoneNumber': '+254712345678',
        'text': '1'
    }
    
    try:
        response = requests.post(f"{BASE_URL}/ussd", data=data)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200 and "CON Select symptom category" in response.text:
            print("Symptom category test passed!")
        else:
            print("Symptom category test failed!")
            
    except Exception as e:
        print(f"Error: {e}")
    
    # Test 3: Select fever category
    print("\n3. Testing fever category selection...")
    data = {
        'sessionId': 'test123',
        'phoneNumber': '+254712345678',
        'text': '1*1'
    }
    
    try:
        response = requests.post(f"{BASE_URL}/ussd", data=data)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200 and "CON Select your symptoms" in response.text:
            print("Fever category test passed!")
        else:
            print("Fever category test failed!")
            
    except Exception as e:
        print(f"Error: {e}")
    
    # Test 4: Analyze symptoms
    print("\n4. Testing symptom analysis...")
    data = {
        'sessionId': 'test123',
        'phoneNumber': '+254712345678',
        'text': '1*1*1,2,3'
    }
    
    try:
        response = requests.post(f"{BASE_URL}/ussd", data=data)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200 and "END Possible conditions" in response.text:
            print("Symptom analysis test passed!")
        else:
            print("Symptom analysis test failed!")
            
    except Exception as e:
        print(f"Error: {e}")
    
    # Test 5: Emergency contacts
    print("\n5. Testing emergency contacts...")
    data = {
        'sessionId': 'test456',
        'phoneNumber': '+254712345678',
        'text': '3'
    }
    
    try:
        response = requests.post(f"{BASE_URL}/ussd", data=data)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200 and "END Emergency Contacts" in response.text:
            print("Emergency contacts test passed!")
        else:
            print("Emergency contacts test failed!")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("Make sure your Flask app is running on localhost:5000")
    print("   Run: python app.py")
    input("Press Enter to start testing...")
    test_ussd_endpoint()
    print("\nUSSD testing completed!")
