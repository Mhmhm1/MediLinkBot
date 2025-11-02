# MediLink - Smart Health Chatbot

## Overview
MediLink is a complete Flask-based web application that provides intelligent health symptom analysis and specialist recommendations. The chatbot-style interface guides users through symptom reporting, analyzes potential conditions with confidence scoring, and recommends appropriate medications and healthcare specialists.

## Project Architecture

### Technology Stack
- **Backend**: Flask (Python 3.11)
- **Frontend**: Bootstrap 5, HTML5, CSS3, JavaScript
- **Data Storage**: CSV file for disease database, Flask sessions for user data
- **Styling**: Custom medical-themed CSS (white and blue color scheme)

### Directory Structure
```
.
├── app.py                 # Main Flask application with routing logic
├── data/
│   └── diseases.csv      # Disease dataset (20 diseases)
├── templates/            # Jinja2 HTML templates
│   ├── index.html        # Welcome page with chatbot greeting
│   ├── symptoms.html     # Symptom input with checkboxes and text
│   ├── results.html      # Analysis results with confidence scores
│   ├── specialist.html   # User info form and specialist selection
│   └── summary.html      # Complete session summary
├── static/
│   ├── css/
│   │   └── style.css     # Medical-themed styling
│   └── js/
│       └── script.js     # Interactive features and animations
└── replit.md             # This file
```

## Features Implemented

### 1. Symptom Input System
- Common symptoms displayed as checkboxes (extracted from disease dataset)
- Custom symptom text input for additional symptoms
- Validation to ensure at least one symptom is entered

### 2. Disease Analysis Engine
- Symptom matching algorithm with confidence scoring
- Calculates percentage match based on symptom overlap
- Returns top 5 most likely conditions ranked by confidence

### 3. Results Display
- Color-coded confidence badges (red 70%+, orange 50-70%, yellow <50%)
- Visual progress bars showing match percentage
- Medication recommendations for each disease
- Specialist recommendations

### 4. User Information Collection
- Personal details form (name, age, location)
- Disease selection for follow-up focus
- Automatic specialist assignment based on selected disease

### 5. Session Summary
- Complete patient information display
- Symptom list with checkmarks
- Primary diagnosis highlighting
- Medication list with visual indicators
- Recommended specialist information
- Full conversation history
- Print functionality for medical records

### 6. Chatbot Interface
- Friendly welcome message from MediLink bot
- Conversational flow throughout the process
- Chat history tracking in session
- Medical-themed visual design

## Disease Dataset
The application includes 20 comprehensive disease entries:
- Malaria, Typhoid, Common Cold, Influenza
- Pneumonia, Bronchitis, Asthma
- Diabetes Type 2, Hypertension
- Migraine, Gastritis
- Urinary Tract Infection
- Skin Allergy, Eczema
- Conjunctivitis, Sinusitis
- Arthritis, Anxiety, Depression, Anemia

Each disease includes:
- Associated symptoms (semicolon-separated)
- Recommended medications
- Appropriate specialist type

## Routes
- `/` - Welcome page with chatbot greeting
- `/symptoms` - Symptom input page (GET/POST)
- `/results` - Display analysis results
- `/specialist` - User info and specialist selection (GET/POST)
- `/summary` - Final session summary
- `/restart` - Clear session and start over

## Session Management
- Flask sessions store user data throughout the consultation
- Chat history tracked for display in summary
- Timestamp recorded for each session
- All data cleared on restart

## Recent Changes
- **2025-10-28**: Initial project creation
  - Set up Flask application with all routes
  - Created disease dataset with 20 diseases
  - Built 5 HTML templates with chatbot interface
  - Implemented medical-themed CSS styling
  - Added interactive JavaScript features
  - Configured workflow for port 5000

## User Preferences
- Clean, professional medical interface
- Easy-to-use chatbot-style interaction
- Comprehensive symptom analysis
- Clear medication and specialist recommendations

## Security Features
- **Required SESSION_SECRET**: Application requires SESSION_SECRET environment variable for secure session management (will not start without it)
- Input validation on all forms
- No storage of sensitive medical data beyond session
- Disclaimer about professional medical advice
- No hardcoded secrets in source code

## Environment Variables Required
- `SESSION_SECRET`: Required for secure Flask session management. Must be set before running the application.

## How to Use
1. Start consultation from the welcome page
2. Select or enter symptoms
3. Review analysis results with confidence scores
4. Enter personal information and select primary condition
5. View comprehensive summary
6. Print or save summary for medical records
7. Restart for new consultation

## Future Enhancements
- Database migration for persistent user history
- User account system for tracking multiple sessions
- Advanced symptom matching with severity levels
- PDF export functionality
- Email summary to user
- Integration with appointment booking systems
