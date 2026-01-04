#!/usr/bin/env python3
"""
Test SMS functionality for MediLinkBot
"""

import requests

BASE_URL = "http://localhost:5000"

def test_sms_commands():
    """Test various SMS commands"""
    
    print("Testing MediLinkBot SMS Commands...")
    
    test_cases = [
        # Initial interaction
        {'from': '+254712345678', 'text': 'hi', 'desc': 'Welcome message'},
        {'from': '+254712345678', 'text': 'menu', 'desc': 'Main menu'},
        
        # Symptom checking
        {'from': '+254712345678', 'text': 'symptoms fever headache', 'desc': 'Single symptom'},
        {'from': '+254712345678', 'text': 'symptoms fever, headache, cough', 'desc': 'Multiple symptoms'},
        {'from': '+254712345678', 'text': 'symptom stomach pain nausea', 'desc': 'Stomach symptoms'},
        
        # Emergency services
        {'from': '+254712345678', 'text': 'emergency', 'desc': 'Emergency contacts'},
        {'from': '+254712345678', 'text': 'doctor', 'desc': 'Doctor finder'},
        {'from': '+254712345678', 'text': 'help', 'desc': 'Help information'},
        
        # Invalid command
        {'from': '+254712345678', 'text': 'random text', 'desc': 'Invalid command'},
    ]
    
    for i, test in enumerate(test_cases, 1):
        print(f"\n{i}. Testing: {test['desc']}")
        print(f"   Message: '{test['text']}'")
        
        try:
            response = requests.post(f"{BASE_URL}/sms", data=test)
            print(f"   Status: {response.status_code}")
            
            if response.status_code == 200:
                print(f"   Result: PASS - SMS endpoint working")
            else:
                print(f"   Result: FAIL - Status {response.status_code}")
                
        except Exception as e:
            print(f"   Error: {e}")
    
    print("\nSMS testing completed!")

if __name__ == "__main__":
    test_sms_commands()
