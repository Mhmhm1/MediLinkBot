from flask import Flask, render_template, request, session, redirect, url_for, jsonify, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import csv
import os
import re
import html
from dotenv import load_dotenv
from datetime import datetime, timedelta
#import jsonvenv
import random
import requests
import africastalking
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
load_dotenv()

# Helper to resolve data file paths relative to the Flask app root
def data_file_path(*parts) -> str:
    try:
        base = app.root_path
    except Exception:
        base = os.getcwd()
    return os.path.join(base, 'data', *parts)

# Security: Require SESSION_SECRET in production
SESSION_SECRET = os.getenv("SESSION_SECRET")
if not SESSION_SECRET:
    if os.getenv("FLASK_ENV") == "production":
        raise ValueError("SESSION_SECRET environment variable is required in production")
    else:
        logger.warning("Using default SESSION_SECRET - NOT SAFE FOR PRODUCTION")
        SESSION_SECRET = "dev_secret_key_change_in_production"

app.secret_key = SESSION_SECRET
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///medilink.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# CSRF Protection
csrf = CSRFProtect(app)

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Security: Google API key from environment variable
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
if not GOOGLE_API_KEY:
    logger.error("GOOGLE_API_KEY not found in environment variables")
    raise ValueError("GOOGLE_API_KEY environment variable is required")

import google.generativeai as genai
genai.configure(api_key=GOOGLE_API_KEY)

# Initialize Africa's Talking
AT_USERNAME = os.getenv('AT_USERNAME', 'sandbox')
AT_API_KEY = os.getenv('AT_API_KEY', '')

try:
    africastalking.initialize(AT_USERNAME, AT_API_KEY)
    # Initialize SMS service
    sms = africastalking.SMS
    print("Africa's Talking initialized successfully")
except Exception as e:
    print(f"Africa's Talking initialization failed: {e}")
    sms = None

# --- Configuration for external services ---
GOOGLE_MAPS_OVERPASS_URL = "https://overpass-api.de/api/interpreter"


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(120))
    age = db.Column(db.String(10))
    location = db.Column(db.String(120))
    preferences_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class ChatThread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    doctor_name = db.Column(db.String(255), nullable=False)
    doctor_specialty = db.Column(db.String(120))
    messages_json = db.Column(db.Text)  # JSON array of messages
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class SummaryModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    disease = db.Column(db.String(255))
    specialist = db.Column(db.String(120))
    selected_doctor = db.Column(db.String(255))
    meds_json = db.Column(db.Text)  # JSON array of {name, dosage, side_effects}
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    doctor_name = db.Column(db.String(255), nullable=False)
    doctor_specialty = db.Column(db.String(120))
    doctor_hospital = db.Column(db.String(255))
    doctor_phone = db.Column(db.String(64))
    mode = db.Column(db.String(20))  # 'virtual' or 'physical'
    contact_method = db.Column(db.String(20))  # 'phone' or 'email' (virtual only)
    contact_value = db.Column(db.String(255))
    start_at = db.Column(db.DateTime, nullable=False)
    end_at = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='scheduled', index=True)
    reason = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None


# --- Security: Input Validation Utilities ---
def sanitize_string(text: str, max_length: int = 1000) -> str:
    """Sanitize user input by escaping HTML and limiting length."""
    if not text:
        return ""
    # Escape HTML entities
    sanitized = html.escape(str(text))
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    return sanitized.strip()


def validate_email(email: str) -> bool:
    """Validate email format."""
    if not email:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email.lower()))


def validate_phone(phone: str) -> bool:
    """Validate phone number format (basic validation)."""
    if not phone:
        return False
    # Remove common separators
    cleaned = re.sub(r'[\s\-\(\)]', '', phone)
    # Check if it's digits and reasonable length
    return cleaned.isdigit() and 7 <= len(cleaned) <= 15


def validate_symptom_list(symptoms: list) -> bool:
    """Validate symptom list - check for reasonable length and content."""
    if not symptoms or len(symptoms) == 0:
        return False
    if len(symptoms) > 50:  # Prevent abuse
        return False
    # Check each symptom length
    for symptom in symptoms:
        if len(symptom) > 200:  # Prevent extremely long inputs
            return False
        # Check for suspicious patterns (basic check)
        if len(re.findall(r'<|>|script|javascript', symptom, re.IGNORECASE)) > 0:
            return False
    return True


def validate_name(name: str) -> bool:
    """Validate name format."""
    if not name or len(name.strip()) == 0:
        return False
    if len(name) > 120:
        return False
    # Allow letters, spaces, hyphens, apostrophes
    pattern = r'^[a-zA-Z\s\-\']+$'
    return bool(re.match(pattern, name))


def validate_age(age: str) -> bool:
    """Validate age input."""
    if not age:
        return False
    try:
        age_int = int(age)
        return 0 <= age_int <= 150
    except ValueError:
        return False


def validate_doctor_name(doctor_name: str, doctors_db: dict) -> bool:
    """Validate that doctor name exists in the database."""
    if not doctor_name:
        return False
    for specialty, doctors in doctors_db.items():
        for doc in doctors:
            if doc.get('name') == doctor_name:
                return True
    return False


def sanitize_json_input(data: any) -> any:
    """Recursively sanitize JSON data."""
    if isinstance(data, str):
        return sanitize_string(data, max_length=5000)
    elif isinstance(data, dict):
        return {k: sanitize_json_input(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_json_input(item) for item in data]
    else:
        return data


# ---- User preferences helpers ----
def get_user_prefs(user: 'User') -> dict:
    try:
        return json.loads(user.preferences_json or '{}')
    except Exception:
        return {}

def set_user_prefs(user: 'User', prefs: dict):
    try:
        user.preferences_json = json.dumps(prefs)
        db.session.commit()
    except Exception as e:
        print(f"[Prefs Save Error] {e}")


def is_resolution_message(text: str) -> bool:
    """Detect if the patient's message indicates resolution/closing (e.g., 'fine now', 'okay now', 'thanks')."""
    if not text:
        return False
    t = text.strip().lower()
    keywords = [
        'fine now', 'am fine', "i'm fine", 'feeling fine', 'okay now', 'ok now', 'all good', 'better now',
        'resolved', 'no longer', 'symptoms gone', 'i am fine', 'i feel fine', 'thanks', 'thank you'
    ]
    return any(k in t for k in keywords)

def generate_doctor_response(doctor_profile, patient_message, chat_context=None):
    """
    Generates a doctor-like reply using Gemini with safety handling and short, contextual output.
    """

    import google.generativeai as genai

    # Initialize the model (flash is fast, pro gives richer tone)
    model = genai.GenerativeModel("gemini-2.5-flash")

    name = doctor_profile.get('name', 'Doctor')
    specialty = doctor_profile.get('specialty', 'doctor')
    hospital = (doctor_profile.get('hospital') or '').strip()
    affiliation = f" a {specialty} at {hospital}" if hospital and hospital.lower() != 'unknown' else f" an independent {specialty}"

    # Prepare brief recent context from chat_messages
    convo = chat_context or []
    recent = []
    for m in convo[-6:]:
        role = 'Patient' if m.get('type') == 'user' else 'Doctor'
        text = m.get('message', '')
        if text:
            recent.append(f"{role}: {text}")
    context_block = "\n".join(recent)

    # Infer simple known facts to avoid repetition
    known = {
        'fever': None,
        'back_pain': None,
        'duration': None,
    }
    import re
    # Try to extract a simple duration like "2 days" or "3 hours" from patient messages
    for m in reversed(convo[-8:]):
        if m.get('type') == 'user':
            match = re.search(r"\b(\d+)\s*(day|days|hour|hours|week|weeks)\b", m.get('message',''), re.IGNORECASE)
            if match:
                qty, unit = match.groups()
                known['duration'] = f"{qty} {unit}"
                break
    # Map last yes/no to previous doctor question entities
    last_user = next((m for m in reversed(convo) if m.get('type')=='user'), None)
    last_ai = None
    ai_seen = 0
    for m in reversed(convo):
        if m.get('type') != 'user':
            last_ai = m
            ai_seen += 1
            if ai_seen >= 1:
                break
    if last_user and last_ai:
        lu = last_user.get('message','').strip().lower()
        q = last_ai.get('message','').lower()
        if lu in {'yes','yes.','yeah','yep','y','sure'}:
            if 'fever' in q:
                known['fever'] = True
            if 'back pain' in q or 'lower back' in q:
                known['back_pain'] = True
        elif lu in {'no','no.','nope','n'}:
            if 'fever' in q:
                known['fever'] = False
            if 'back pain' in q or 'lower back' in q:
                known['back_pain'] = False

    # Build a concise known facts block
    facts = []
    if known['duration']:
        facts.append(f"duration={known['duration']}")
    if known['fever'] is not None:
        facts.append(f"fever={'yes' if known['fever'] else 'no'}")
    if known['back_pain'] is not None:
        facts.append(f"back_pain={'yes' if known['back_pain'] else 'no'}")
    facts_block = ", ".join(facts)

    prompt = f"""
    Role: You are Dr. {name},{affiliation}. You are chatting inside MediLinkBot (a secure patient–doctor assistant). Speak as a real clinician.

    Style guidelines:
    - Use first-person ("I") and address the patient by "you".
    - Keep it brief (≤ 60 words), warm, supportive, professional.
    - Prefer simple, everyday language; avoid medical jargon unless essential.
    - Ask at most one focused question only when needed (e.g., severity, duration, fever, back pain). Do not end every message with a question.
    - If the patient indicates they are fine or symptoms resolved, acknowledge and close with a short reassurance or next step; no question is necessary.
    - Acknowledge MediLinkBot’s medication list as educational; suitability depends on age/condition and should be clinician-confirmed.
    - Avoid urgent directives unless clear red flags (severe chest pain, trouble breathing, fainting, persistent high fever).
    - If needed, include one short next step (e.g., hydrate, monitor) and optionally invite them to ask more if they wish. A brief reassurance is welcome.
    - Only mention your hospital if asked or contextually relevant. Never say you are an AI.

    Conversation so far (most recent last):
    {context_block}

    Guidance:
    - Do not repeat greetings or prior questions.
    - Vary endings: alternate between a short statement/plan and a question as appropriate; avoid a question if the patient says issues are resolved.
    - If the last patient message answers a previous question (e.g., "yes" to fever/back pain), advance by briefly quantifying (temp, duration, location/severity). Ask ONE clarifying question only if it changes management; otherwise provide a brief next step.
    - Known facts (use to avoid repeating): {facts_block}

    Patient message:
    "{patient_message}"
    """

    try:
        response = model.generate_content(prompt)
        if hasattr(response, "text") and response.text:
            return response.text.strip()
        else:
            # Gemini might finish early or skip response — handle gracefully
            return "I'm here to help. Could you tell me a bit more about your symptoms?"
    except Exception as e:
        print(f"[Gemini Error] {e}")
        return "Sorry, I couldn’t process your message right now."
@app.route("/chat/<doctor_name>", methods=["GET", "POST"])
@login_required
@limiter.limit("30 per minute")
@csrf.exempt
def chat(doctor_name):
    # Validate and sanitize doctor_name
    doctor_name = sanitize_string(doctor_name, max_length=255)
    if not doctor_name or len(doctor_name) < 2:
        abort(400, "Invalid doctor name")
    
    patient_message = ""
    if request.method == "POST":
        data = request.get_json() or {}
        patient_message = data.get("message", "").strip()
        
        # Validate message
        if not patient_message:
            return jsonify({"reply": "Please type a message to send."}), 400
        
        # Sanitize and validate message length
        patient_message = sanitize_string(patient_message, max_length=2000)
        if len(patient_message) < 1:
            return jsonify({"reply": "Message is too short."}), 400
        
        # Prevent abuse: limit message frequency
        if len(session.get('chat_messages', [])) > 100:
            return jsonify({"reply": "Conversation too long. Please start a new chat."}), 400

    doctors_db = load_doctors_data()
    doctor_profile = None

    for specialty, doctors in doctors_db.items():
        for doc in doctors:
            if doc['name'] == doctor_name:
                doctor_profile = {
                    'name': doc.get('name', 'Unknown'),
                    'specialty': specialty,
                    'qualifications': doc.get('qualifications', 'Unknown'),
                    'experience': doc.get('experience', 'Unknown'),
                    'rating': doc.get('rating', 'Unknown'),
                    'hospital': doc.get('hospital', '').strip() or 'Unknown'
                }
                break
        if doctor_profile:
            break

    # Ensure chat histories exist in session
    if 'chat_history' not in session:
        session['chat_history'] = []  # global/system history
    if 'chat_messages' not in session:
        session['chat_messages'] = []  # per-doctor chat thread

    if request.method == "GET":
        # Render the chat UI
        initial_summary = request.args.get('summary', '')
        thread_id = request.args.get('thread_id', type=int)
        # Determine whether to continue an existing thread or start fresh
        if current_user.is_authenticated and thread_id:
            # Continue specific existing thread
            try:
                thread = ChatThread.query.filter_by(id=thread_id, user_id=current_user.id).first()
                if thread:
                    saved = json.loads(thread.messages_json or '[]')
                    session['chat_messages'] = saved if isinstance(saved, list) else []
                    session['current_thread_id'] = thread.id
            except Exception as e:
                print(f"[DB Load Specific ChatThread Error] {e}")
        else:
            # New consultation: start fresh regardless of same doctor
            session['chat_messages'] = []
            session['current_thread_id'] = None
        # Append initial summary and auto-reply for both cases
        if initial_summary:
            session['chat_messages'].append({'type': 'user', 'message': initial_summary})
            reply = ""
            if doctor_profile:
                reply = generate_doctor_response(doctor_profile, initial_summary, chat_context=session['chat_messages']) or "Thanks for sharing that summary."
            else:
                reply = "Thanks for your summary. I'm ready to help."
            session['chat_messages'].append({'type': 'ai', 'message': reply})
            # Persist: update existing thread if resuming; otherwise create new thread
            if current_user.is_authenticated:
                try:
                    if session.get('current_thread_id'):
                        thread = ChatThread.query.filter_by(id=session['current_thread_id'], user_id=current_user.id).first()
                        if thread:
                            thread.messages_json = json.dumps(session.get('chat_messages', []))
                            thread.updated_at = datetime.utcnow()
                            db.session.commit()
                    else:
                        new_thread = ChatThread(user_id=current_user.id,
                                                doctor_name=doctor_name,
                                                doctor_specialty=doctor_profile.get('specialty', 'doctor'),
                                                messages_json=json.dumps(session.get('chat_messages', [])),
                                                updated_at=datetime.utcnow())
                        db.session.add(new_thread)
                        db.session.commit()
                        session['current_thread_id'] = new_thread.id
                except Exception as e:
                    print(f"[DB ChatThread Persist (GET) Error] {e}")
        theme = None
        if current_user.is_authenticated:
            try:
                prefs = get_user_prefs(current_user)
                theme = prefs.get('theme')
            except Exception:
                theme = None
        return render_template('chat.html', doctor_profile=doctor_profile, doctor_name=doctor_name, chat_messages=session.get('chat_messages', []), theme=theme)

    # POST -> generate and return JSON reply
    # Append user message to chat thread
    if patient_message:
        session['chat_messages'].append({'type': 'user', 'message': patient_message})

    ai_reply = ""
    if doctor_profile and patient_message:
        # If the user indicates resolution/closing, provide a brief supportive closure without a follow-up question.
        if is_resolution_message(patient_message):
            ai_reply = "I'm glad you're feeling better. Keep hydrating and rest as needed. If any symptoms return or new concerns arise, message me anytime."
        else:
            ai_reply = generate_doctor_response(doctor_profile, patient_message, chat_context=session['chat_messages'])
            if not ai_reply:
                ai_reply = "Sorry, I couldn't generate a reply right now."
        session['chat_messages'].append({"type": "ai", "message": ai_reply})
        # Persist chat thread if logged in: update current thread or create new if none
        if current_user.is_authenticated:
            try:
                if session.get('current_thread_id'):
                    thread = ChatThread.query.filter_by(id=session['current_thread_id'], user_id=current_user.id).first()
                    if thread:
                        thread.messages_json = json.dumps(session.get('chat_messages', []))
                        thread.updated_at = datetime.utcnow()
                        db.session.commit()
                else:
                    new_thread = ChatThread(user_id=current_user.id,
                                            doctor_name=doctor_name,
                                            doctor_specialty=doctor_profile.get('specialty', 'doctor'),
                                            messages_json=json.dumps(session.get('chat_messages', [])),
                                            updated_at=datetime.utcnow())
                    db.session.add(new_thread)
                    db.session.commit()
                    session['current_thread_id'] = new_thread.id
            except Exception as e:
                print(f"[DB ChatThread Persist Error] {e}")
    elif patient_message:
        ai_reply = "Thanks for your message. A doctor could not be identified."
        session['chat_messages'].append({"type": "ai", "message": ai_reply})

    return {"reply": ai_reply}


def load_doctors_data():
    doctors = {}
    path = data_file_path('doctors.csv')
    try:
        with open(path, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                specialty = row['specialty']
                if specialty not in doctors:
                    doctors[specialty] = []
                doctors[specialty].append({
                    'name': row['name'],
                    'qualifications': row['qualifications'],
                    'experience': row['experience'],
                    'rating': row['rating'],
                    'hospital': row.get('hospital', 'Unknown'),
                    'phone': row.get('phone', '').strip() or 'N/A'
                })
    except FileNotFoundError:
        logger.error(f"Doctors data file not found: {path}")
    except Exception as e:
        logger.error(f"Error loading doctors data: {e}")
    return doctors


def load_disease_data():
    diseases = []
    path = data_file_path('diseases.csv')
    try:
        with open(path, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                diseases.append({
                    'name': row['disease'],
                    'symptoms': row['symptoms'].split(';'),
                    'medications': row['medications'].split(';'),
                    'specialist': row['specialist']
                })
    except FileNotFoundError:
        logger.error(f"Diseases data file not found: {path}")
    except Exception as e:
        logger.error(f"Error loading diseases data: {e}")
    return diseases


def load_medication_data():
    medications = {}
    path = data_file_path('medications.csv')
    try:
        with open(path, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                medications[row['medication']] = {
                    'dosage': row['dosage'],
                    'side_effects': row['side_effects'].split(';') if row['side_effects'] else []
                }
    except FileNotFoundError:
        logger.error(f"Medications data file not found: {path}")
    except Exception as e:
        logger.error(f"Error loading medications data: {e}")
    return medications


def get_all_symptoms():
    diseases = load_disease_data()
    symptoms = set()
    for disease in diseases:
        for symptom in disease['symptoms']:
            symptoms.add(symptom.strip().lower())
    return sorted(list(symptoms))


def analyze_symptoms(user_symptoms):
    diseases = load_disease_data()
    medication_data = load_medication_data()
    results = []

    normalized_user_symptoms = [s.strip().lower() for s in user_symptoms]
    for disease in diseases:
        normalized_disease_symptoms = [s.strip().lower() for s in disease['symptoms']]
        matches = sum(1 for symptom in normalized_user_symptoms if symptom in normalized_disease_symptoms)

        if matches > 0:
            confidence = (matches / len(normalized_disease_symptoms)) * 100
            medications_with_details = [
                {
                    'name': med,
                    'dosage': medication_data.get(med, {}).get('dosage', 'Consult doctor for dosage'),
                    'side_effects': medication_data.get(med, {}).get('side_effects', ['Consult doctor'])
                }
                for med in disease['medications']
            ]
            results.append({
                'disease': disease['name'],
                'confidence': round(confidence, 1),
                'medications': medications_with_details,
                'specialist': disease['specialist'],
                'matched_symptoms': matches,
                'total_symptoms': len(normalized_disease_symptoms)
            })
    results.sort(key=lambda x: x['confidence'], reverse=True)
    return results


# --- Routes ---
@app.route('/')
def index():
    if 'chat_history' not in session:
        session['chat_history'] = []
    if 'timestamp' not in session:
        session['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    recent_summaries = []
    recent_chats = []
    theme = None
    if current_user.is_authenticated:
        try:
            recent_summaries = SummaryModel.query.filter_by(user_id=current_user.id).order_by(SummaryModel.created_at.desc()).limit(5).all()
            recent_chats = ChatThread.query.filter_by(user_id=current_user.id).order_by(ChatThread.updated_at.desc()).limit(5).all()
            prefs = get_user_prefs(current_user)
            theme = prefs.get('theme')
        except Exception as e:
            print(f"[DB Home Query Error] {e}")
    return render_template('home.html', recent_summaries=recent_summaries, recent_chats=recent_chats, theme=theme)


# --- Auth Routes ---
@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def signup():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        password2 = request.form.get('password2', '')
        
        # Validation
        if not email or not password:
            flash('Email and password are required.', 'danger')
            return render_template('signup.html')
        
        if not validate_email(email):
            flash('Invalid email format.', 'danger')
            return render_template('signup.html')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('signup.html')
        
        if len(password) > 128:
            flash('Password is too long.', 'danger')
            return render_template('signup.html')
        
        if password != password2:
            flash('Passwords do not match.', 'danger')
            return render_template('signup.html')
        
        if User.query.filter_by(email=email).first():
            flash('An account with this email already exists. Please log in.', 'warning')
            return redirect(url_for('login'))
        
        try:
            user = User(email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            logger.info(f"New user registered: {email}")
            flash('Account created. You are now logged in.', 'success')
            next_url = request.args.get('next')
            return redirect(next_url or url_for('index'))
        except Exception as e:
            logger.error(f"Signup error: {e}")
            db.session.rollback()
            flash('An error occurred. Please try again.', 'danger')
            return render_template('signup.html')
    
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
@csrf.exempt
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = bool(request.form.get('remember'))
        
        # Validation
        if not email or not password:
            flash('Email and password are required.', 'danger')
            return render_template('login.html')
        
        if not validate_email(email):
            flash('Invalid email format.', 'danger')
            return render_template('login.html')
        
        if len(password) > 128:
            flash('Invalid credentials.', 'danger')
            return render_template('login.html')
        
        try:
            user = User.query.filter_by(email=email).first()
            if not user or not user.check_password(password):
                logger.warning(f"Failed login attempt for: {email}")
                flash('Invalid email or password.', 'danger')
                return render_template('login.html')
            
            login_user(user, remember=remember)
            logger.info(f"User logged in: {email}")
            flash('Welcome back!', 'success')
            next_url = request.args.get('next')
            return redirect(next_url or url_for('index'))
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('An error occurred. Please try again.', 'danger')
            return render_template('login.html')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/symptoms', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute")
@csrf.exempt
def symptoms():
    if request.method == 'POST':
        selected_symptoms = request.form.getlist('symptoms[]')
        custom_symptoms = request.form.get('custom_symptoms', '').strip()
        
        # Sanitize selected symptoms
        selected_symptoms = [sanitize_string(s, max_length=200) for s in selected_symptoms if s]
        
        all_symptoms = selected_symptoms.copy()
        if custom_symptoms:
            custom_symptoms = sanitize_string(custom_symptoms, max_length=500)
            custom_list = [sanitize_string(s.strip(), max_length=200) for s in custom_symptoms.split(',') if s.strip()]
            all_symptoms.extend(custom_list)

        # Validate symptom list
        if not validate_symptom_list(all_symptoms):
            return render_template('symptoms.html', symptoms=get_all_symptoms(),
                                   error="Please select or enter at least one valid symptom (max 50 symptoms).")

        session['user_symptoms'] = all_symptoms
        session['chat_history'].append({'type': 'user', 'message': f"I'm experiencing: {', '.join(all_symptoms)}"})

        results = analyze_symptoms(all_symptoms)
        if not results:
            session['chat_history'].append({'type': 'bot',
                                            'message': "I couldn't find exact matches. Please consult a General Practitioner."})
            return render_template('symptoms.html', symptoms=get_all_symptoms(),
                                   error="No matching diseases found. Please try again or consult a doctor.")

        session['diagnosis_results'] = results
        session['chat_history'].append({'type': 'bot',
                                        'message': f"Based on your symptoms, I found {len(results)} possible condition(s)."})
        return redirect(url_for('results'))

    return render_template('symptoms.html', symptoms=get_all_symptoms())


@app.route('/results')
@login_required
def results():
    if 'diagnosis_results' not in session:
        return redirect(url_for('symptoms'))
    return render_template('results.html', results=session['diagnosis_results'])


@app.route('/specialist', methods=['GET', 'POST'])
@login_required
def specialist():
    if 'diagnosis_results' not in session:
        return redirect(url_for('symptoms'))

    results = session['diagnosis_results']
    doctors_db = load_doctors_data()
    specialty = results[0]['specialist'] if results else 'General Practitioner'
    doctors = doctors_db.get(specialty, [])
    # Top 2 diseases
    results_top2 = results[:2] if results else []
    # Build doctors_by_specialty for top 2 diseases
    top_specs = list({r['specialist'] for r in results_top2}) if results_top2 else [specialty]
    doctors_by_specialty = {spec: doctors_db.get(spec, []) for spec in top_specs}
    # Build disease -> medications string map
    disease_meds = {}
    for r in results:
        meds_list = []
        for med in r.get('medications', []):
            name = med.get('name', '')
            dosage = med.get('dosage', '')
            meds_list.append(f"{name} ({dosage})")
        disease_meds[r['disease']] = ", ".join(meds_list)

    if request.method == 'POST':
        name = sanitize_string(request.form.get('name', '').strip(), max_length=120)
        age = request.form.get('age', '').strip()
        location = sanitize_string(request.form.get('location', '').strip(), max_length=120)
        selected_disease = sanitize_string(request.form.get('selected_disease', '').strip(), max_length=255)
        selected_doctor = sanitize_string(request.form.get('selected_doctor', '').strip(), max_length=255)

        # Validation
        if not all([name, age, location, selected_disease, selected_doctor]):
            return render_template('specialist.html', results=results_top2, doctors=doctors,
                                   error="Please fill in all fields and select a doctor.")
        
        if not validate_name(name):
            return render_template('specialist.html', results=results_top2, doctors=doctors,
                                   error="Invalid name format.")
        
        if not validate_age(age):
            return render_template('specialist.html', results=results_top2, doctors=doctors,
                                   error="Invalid age. Please enter a number between 0 and 150.")
        
        # Validate doctor exists
        if not validate_doctor_name(selected_doctor, doctors_db):
            return render_template('specialist.html', results=results_top2, doctors=doctors,
                                   error="Selected doctor not found. Please choose a valid doctor.")

        selected_info = next((r for r in results if r['disease'] == selected_disease), None)
        if not selected_info:
            return render_template('specialist.html', results=results_top2, doctors=doctors,
                                   error="Selected disease not found.")
        
        session['user_info'] = {
            'name': name,
            'age': age,
            'location': location,
            'selected_disease': selected_disease,
            'specialist': selected_info['specialist'] if selected_info else 'General Practitioner',
            'selected_doctor': selected_doctor,
            'medications': selected_info['medications'] if selected_info else []
        }

        session['chat_history'].append({'type': 'user',
                                        'message': f"My name is {name}, I'm {age} years old from {location}."})
        session['chat_history'].append({'type': 'bot',
                                        'message': f"Thank you, {name}. You've selected {selected_doctor} for {selected_disease}."})
        return redirect(url_for('summary'))

    return render_template('specialist.html', results=results_top2, doctors=doctors, specialty=specialty,
                           doctors_by_specialty=doctors_by_specialty, disease_meds=disease_meds)


@app.route('/summary')
@login_required
def summary():
    if 'user_info' not in session:
        return redirect(url_for('specialist'))
    # Persist summary for history
    try:
        if current_user.is_authenticated:
            ui = session['user_info']
            meds_json = json.dumps(ui.get('medications', []))
            s = SummaryModel(user_id=current_user.id,
                             disease=ui.get('selected_disease',''),
                             specialist=ui.get('specialist',''),
                             selected_doctor=ui.get('selected_doctor',''),
                             meds_json=meds_json)
            db.session.add(s)
            db.session.commit()
    except Exception as e:
        print(f"[DB Summary Persist Error] {e}")
    return render_template('summary.html',
                           user_info=session['user_info'],
                           symptoms=session.get('user_symptoms', []),
                           chat_history=session.get('chat_history', []),
                           timestamp=session.get('timestamp', ''))


@app.route('/summary_view/<int:summary_id>')
@login_required
def summary_view(summary_id: int):
    s = SummaryModel.query.filter_by(id=summary_id, user_id=current_user.id).first()
    if not s:
        flash('Summary not found.', 'warning')
        return redirect(url_for('index'))
    user_info = {
        'name': current_user.name or '',
        'age': current_user.age or '',
        'location': current_user.location or '',
        'selected_disease': s.disease,
        'specialist': s.specialist,
        'selected_doctor': s.selected_doctor,
        'medications': json.loads(s.meds_json or '[]')
    }
    return render_template('summary.html',
                           user_info=user_info,
                           symptoms=session.get('user_symptoms', []),
                           chat_history=[],
                           timestamp=s.created_at.strftime('%Y-%m-%d %H:%M:%S'))


# ---- Deletion routes for history ----
@app.route('/delete_summary/<int:summary_id>', methods=['POST'])
@login_required
def delete_summary(summary_id: int):
    s = SummaryModel.query.filter_by(id=summary_id, user_id=current_user.id).first()
    if not s:
        flash('Summary not found.', 'warning')
    else:
        try:
            db.session.delete(s)
            db.session.commit()
            flash('Summary deleted.', 'success')
        except Exception as e:
            print(f"[Delete Summary Error] {e}")
            flash('Could not delete summary.', 'danger')
    return redirect(url_for('index'))


@app.route('/delete_chat/<int:thread_id>', methods=['POST'])
@login_required
def delete_chat(thread_id: int):
    t = ChatThread.query.filter_by(id=thread_id, user_id=current_user.id).first()
    if not t:
        flash('Chat not found.', 'warning')
    else:
        try:
            db.session.delete(t)
            db.session.commit()
            flash('Chat deleted.', 'success')
        except Exception as e:
            print(f"[Delete Chat Error] {e}")
            flash('Could not delete chat.', 'danger')
    return redirect(url_for('index'))


# ---- Profile page ----
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        name = sanitize_string(request.form.get('name', '').strip(), max_length=120)
        age = request.form.get('age', '').strip()
        location = sanitize_string(request.form.get('location', '').strip(), max_length=120)
        theme = request.form.get('theme')  # 'light' or 'dark'
        
        # Validation
        if name and not validate_name(name):
            flash('Invalid name format.', 'danger')
            return redirect(url_for('profile'))
        
        if age and not validate_age(age):
            flash('Invalid age. Please enter a number between 0 and 150.', 'danger')
            return redirect(url_for('profile'))
        
        current_user.name = name if name else current_user.name
        current_user.age = age if age else current_user.age
        current_user.location = location if location else current_user.location
        
        # Save theme in preferences
        prefs = get_user_prefs(current_user)
        if theme in ('light', 'dark'):
            prefs['theme'] = theme
        set_user_prefs(current_user, prefs)
        try:
            db.session.commit()
            logger.info(f"Profile updated for user: {current_user.email}")
            flash('Profile updated.', 'success')
        except Exception as e:
            logger.error(f"[Profile Save Error] {e}")
            db.session.rollback()
            flash('Could not save profile.', 'danger')
        return redirect(url_for('profile'))

    prefs = get_user_prefs(current_user)
    return render_template('profile.html', theme=prefs.get('theme'))


# ---- Booking helpers ----
def parse_slot_times(mode: str, slot_key: str):
    # Returns start_hour, end_hour as integers
    if mode == 'virtual':
        if slot_key == '10-12':
            return 10, 12
        if slot_key == '14-16':
            return 14, 16
    elif mode == 'physical':
        mapping = {
            '8-10': (8, 10),
            '10-12': (10, 12),
            '12-14': (12, 14),
            '14-16': (14, 16),
            '16-18': (16, 18),
        }
        if slot_key in mapping:
            return mapping[slot_key]
    return None, None


def allowed_weekday(mode: str, dt: datetime) -> bool:
    # Monday=0 ... Sunday=6
    wd = dt.weekday()
    if mode == 'virtual':
        return wd in (0, 2, 5)  # Mon, Wed, Sat
    if mode == 'physical':
        return wd in (1, 3)  # Tue, Thu
    return False


# ---- Booking routes ----
@app.route('/book', methods=['GET', 'POST'])
@login_required
def book():
    doctor_name = request.args.get('doctor') or request.form.get('doctor')
    doctor_specialty = request.args.get('specialty') or request.form.get('specialty')
    # Lookup hospital/phone from doctors data
    doctors_db = load_doctors_data()
    hospital = 'Unknown'
    phone = 'N/A'
    if doctor_specialty in doctors_db:
        for doc in doctors_db[doctor_specialty]:
            if doc.get('name') == doctor_name:
                hospital = doc.get('hospital', 'Unknown')
                phone = doc.get('phone', 'N/A')
                break

    if request.method == 'POST':
        # Sanitize inputs
        doctor_name = sanitize_string(doctor_name or '', max_length=255)
        doctor_specialty = sanitize_string(doctor_specialty or '', max_length=120)
        mode = (request.form.get('mode') or '').lower()
        date_str = request.form.get('date')  # yyyy-mm-dd
        slot_key = sanitize_string(request.form.get('slot', ''), max_length=20)  # e.g., '10-12'
        reason = sanitize_string(request.form.get('reason', '').strip(), max_length=1000)
        contact_method = request.form.get('contact_method') if mode == 'virtual' else None
        contact_value = sanitize_string(request.form.get('contact_value', ''), max_length=255) if mode == 'virtual' else None

        # Validation
        if not all([doctor_name, doctor_specialty, mode, date_str, slot_key]):
            flash('Please complete all required fields.', 'danger')
            return render_template('book.html', doctor_name=doctor_name, doctor_specialty=doctor_specialty,
                                   hospital=hospital, phone=phone)
        
        if mode not in ('virtual', 'physical'):
            flash('Invalid appointment mode.', 'danger')
            return render_template('book.html', doctor_name=doctor_name, doctor_specialty=doctor_specialty,
                                   hospital=hospital, phone=phone)
        
        if mode == 'virtual' and contact_method not in ('phone', 'email'):
            flash('Invalid contact method for virtual appointment.', 'danger')
            return render_template('book.html', doctor_name=doctor_name, doctor_specialty=doctor_specialty,
                                   hospital=hospital, phone=phone)
        
        if mode == 'virtual' and contact_value:
            if contact_method == 'email' and not validate_email(contact_value):
                flash('Invalid email address.', 'danger')
                return render_template('book.html', doctor_name=doctor_name, doctor_specialty=doctor_specialty,
                                       hospital=hospital, phone=phone)
            elif contact_method == 'phone' and not validate_phone(contact_value):
                flash('Invalid phone number.', 'danger')
                return render_template('book.html', doctor_name=doctor_name, doctor_specialty=doctor_specialty,
                                       hospital=hospital, phone=phone)

        try:
            date_obj = datetime.strptime(date_str, '%Y-%m-%d')
            # Prevent booking in the past
            if date_obj.date() < datetime.now().date():
                flash('Cannot book appointments in the past.', 'danger')
                return render_template('book.html', doctor_name=doctor_name, doctor_specialty=doctor_specialty,
                                       hospital=hospital, phone=phone)
        except ValueError:
            flash('Invalid date format.', 'danger')
            return render_template('book.html', doctor_name=doctor_name, doctor_specialty=doctor_specialty,
                                   hospital=hospital, phone=phone)

        if not allowed_weekday(mode, date_obj):
            flash('Selected date is not available for the chosen mode.', 'danger')
            return render_template('book.html', doctor_name=doctor_name, doctor_specialty=doctor_specialty,
                                   hospital=hospital, phone=phone)

        start_h, end_h = parse_slot_times(mode, slot_key)
        if start_h is None:
            flash('Invalid time slot.', 'danger')
            return render_template('book.html', doctor_name=doctor_name, doctor_specialty=doctor_specialty,
                                   hospital=hospital, phone=phone)

        start_at = datetime(year=date_obj.year, month=date_obj.month, day=date_obj.day, hour=start_h, minute=0)
        end_at = datetime(year=date_obj.year, month=date_obj.month, day=date_obj.day, hour=end_h, minute=0)

        appt = Appointment(user_id=current_user.id,
                           doctor_name=doctor_name,
                           doctor_specialty=doctor_specialty,
                           doctor_hospital=hospital,
                           doctor_phone=phone,
                           mode=mode,
                           contact_method=contact_method,
                           contact_value=contact_value,
                           start_at=start_at,
                           end_at=end_at,
                           status='scheduled',
                           reason=reason)
        try:
            db.session.add(appt)
            db.session.commit()
            return redirect(url_for('booking_detail', booking_id=appt.id))
        except Exception as e:
            print(f"[Booking Save Error] {e}")
            flash('Could not save booking.', 'danger')

    # GET
    # Build a brief suggested reason from session context
    brief = None
    try:
        ui = session.get('user_info') or {}
        syms = session.get('user_symptoms') or []
        disease = ui.get('selected_disease')
        sel_doc = ui.get('selected_doctor')
        meds = ui.get('medications') or []
        meds_list = ", ".join([m.get('name','') for m in meds][:3]) if isinstance(meds, list) else ''
        parts = []
        if syms:
            parts.append(f"Symptoms: {', '.join(syms)}")
        if disease:
            parts.append(f"Focus: {disease}")
        if sel_doc:
            parts.append(f"Preferred doctor: {sel_doc}")
        if meds_list:
            parts.append(f"Suggested meds: {meds_list}")
        brief = "; ".join(parts) if parts else None
    except Exception:
        brief = None

    return render_template('book.html', doctor_name=doctor_name, doctor_specialty=doctor_specialty,
                           hospital=hospital, phone=phone, brief_summary=brief)


@app.route('/booking/<int:booking_id>')
@login_required
def booking_detail(booking_id: int):
    appt = Appointment.query.filter_by(id=booking_id, user_id=current_user.id).first()
    if not appt:
        flash('Appointment not found.', 'warning')
        return redirect(url_for('bookings'))

    # Generate a simple random payment reference for now (not persisted)
    payment_ref = f"ML{random.randint(100000000, 999999999)}"

    # Try to fetch the most recent summary linked to this user/doctor
    latest_summary = None
    summary_meds = []
    try:
        latest_summary = (
            SummaryModel.query
            .filter_by(user_id=current_user.id, selected_doctor=appt.doctor_name)
            .order_by(SummaryModel.created_at.desc())
            .first()
        )
        if latest_summary and latest_summary.meds_json:
            summary_meds = json.loads(latest_summary.meds_json or "[]")
    except Exception as e:
        print(f"[Booking Detail Summary Load Error] {e}")

    return render_template(
        'booking_detail.html',
        appt=appt,
        payment_ref=payment_ref,
        latest_summary=latest_summary,
        summary_meds=summary_meds,
    )


@app.route('/bookings')
@login_required
def bookings():
    my_appts = Appointment.query.filter_by(user_id=current_user.id).order_by(Appointment.start_at.desc()).all()
    return render_template('bookings.html', appts=my_appts)


@app.route('/booking/<int:booking_id>/cancel', methods=['POST'])
@login_required
def booking_cancel(booking_id: int):
    appt = Appointment.query.filter_by(id=booking_id, user_id=current_user.id).first()
    if not appt:
        flash('Appointment not found.', 'warning')
    else:
        try:
            appt.status = 'cancelled'
            db.session.commit()
            flash('Appointment cancelled.', 'success')
        except Exception as e:
            print(f"[Booking Cancel Error] {e}")
            flash('Could not cancel appointment.', 'danger')
    return redirect(url_for('bookings'))

@app.route('/booking/<int:booking_id>/status', methods=['POST'])
@login_required
def booking_status(booking_id: int):
    appt = Appointment.query.filter_by(id=booking_id, user_id=current_user.id).first()
    if not appt:
        flash('Appointment not found.', 'warning')
        return redirect(url_for('bookings'))
    new_status = (request.form.get('status') or '').lower()
    if new_status not in ('scheduled', 'completed'):
        flash('Invalid status.', 'danger')
        return redirect(url_for('booking_detail', booking_id=booking_id))
    try:
        appt.status = new_status
        db.session.commit()
        flash('Status updated.', 'success')
    except Exception as e:
        print(f"[Booking Status Error] {e}")
        flash('Could not update status.', 'danger')
    return redirect(url_for('booking_detail', booking_id=booking_id))
@app.route('/history')
@login_required
def history():
    recent_summaries = []
    recent_chats = []
    try:
        recent_summaries = SummaryModel.query.filter_by(user_id=current_user.id).order_by(SummaryModel.created_at.desc()).limit(20).all()
        recent_chats = ChatThread.query.filter_by(user_id=current_user.id).order_by(ChatThread.updated_at.desc()).limit(20).all()
    except Exception as e:
        print(f"[DB History Query Error] {e}")
    return render_template('history.html', recent_summaries=recent_summaries, recent_chats=recent_chats)
@app.route('/restart')
def restart():
    session.clear()
    return redirect(url_for('index'))


# --- USSD Routes ---
@app.route('/ussd', methods=['POST', 'GET'])
@csrf.exempt  # USSD doesn't support CSRF tokens
@limiter.limit("20 per minute")
def ussd_callback():
    """Handle USSD requests from Africa's Talking"""
    if request.method == 'GET':
        return "USSD endpoint is active", 200
    
    # Get and validate USSD session data
    session_id = sanitize_string(request.form.get('sessionId', ''), max_length=100)
    phone_number = request.form.get('phoneNumber', '')
    text = sanitize_string(request.form.get('text', ''), max_length=500)
    
    # Validate phone number
    if phone_number and not validate_phone(phone_number):
        return "END Invalid phone number format.", 200
    
    # Parse user input
    if text:
        user_input = text.split('*')[-1].strip()
    else:
        user_input = ''
    
    # Load disease data for symptom analysis
    try:
        disease_data = []
        with open(data_file_path('diseases.csv'), 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                disease_data.append(row)
    except Exception as e:
        print(f"[USSD Error] Could not load disease data: {e}")
        disease_data = []
    
    # USSD Menu Logic
    response = ""
    
    if text == '':
        # Main menu - First interaction
        response = "CON Welcome to MediLinkBot Health Check\n"
        response += "1. Check Symptoms\n"
        response += "2. Talk to Doctor\n"
        response += "3. Emergency Contacts\n"
        response += "4. Exit"
    
    elif user_input == '1':
        # Symptom checker menu
        if len(text.split('*')) == 1:
            response = "CON Select symptom category:\n"
            response += "1. Fever & Headache\n"
            response += "2. Cough & Cold\n"
            response += "3. Stomach Issues\n"
            response += "4. Skin Problems\n"
            response += "5. Other Symptoms"
        else:
            # Get symptoms based on category
            category = text.split('*')[1]
            symptoms = get_ussd_symptoms_by_category(category, disease_data)
            
            if len(text.split('*')) == 2:
                response = "CON Select your symptoms (enter numbers separated by commas):\n"
                for i, symptom in enumerate(symptoms[:5], 1):  # Limit to 5 symptoms for USSD
                    response += f"{i}. {symptom}\n"
                response += "6. Enter custom symptom"
            else:
                # Analyze symptoms
                selected_indices = text.split('*')[2].split(',')
                selected_symptoms = []
                
                for idx in selected_indices:
                    try:
                        if int(idx) <= len(symptoms):
                            selected_symptoms.append(symptoms[int(idx) - 1])
                    except (ValueError, IndexError):
                        continue
                
                if selected_symptoms:
                    analysis = analyze_ussd_symptoms(selected_symptoms, disease_data)
                    response = f"END Possible conditions:\n"
                    for condition in analysis[:3]:  # Top 3 results
                        response += f"• {condition['disease']} ({condition['confidence']}%)\n"
                    response += f"\nRecommended: {analysis[0]['specialist']}\n"
                    response += "Consult a healthcare provider for accurate diagnosis."
                else:
                    response = "END No valid symptoms selected. Please try again."
    
    elif user_input == '2':
        # Talk to doctor
        response = "END To consult with a doctor:\n"
        response += "Visit: medilinkbot.com\n"
        response += "Call: +254700123456\n"
        response += "Available 24/7 for emergencies"
    
    elif user_input == '3':
        # Emergency contacts
        response = "END Emergency Contacts:\n"
        response += "• Emergency: 999/112\n"
        response += "• COVID-19: 719\n"
        response += "• Mental Health: 1190\n"
        response += "Nearest Hospital: Call 119 for directions"
    
    elif user_input == '4':
        # Exit
        response = "END Thank you for using MediLinkBot. Stay healthy!"
    
    else:
        # Invalid input
        response = "CON Invalid choice. Please try again:\n"
        response += "1. Check Symptoms\n"
        response += "2. Talk to Doctor\n"
        response += "3. Emergency Contacts\n"
        response += "4. Exit"
    
    return response, 200, {'Content-Type': 'text/plain'}


# --- SMS Routes ---
@app.route('/sms', methods=['POST'])
@csrf.exempt  # SMS doesn't support CSRF tokens
@limiter.limit("30 per minute")
def sms_callback():
    """Handle incoming SMS messages from Africa's Talking"""
    # Get and validate SMS data
    from_number = request.form.get('from', '')
    to_number = request.form.get('to', '')
    text = sanitize_string(request.form.get('text', '').strip().lower(), max_length=500)
    message_id = sanitize_string(request.form.get('id', ''), max_length=100)
    
    # Validate phone number
    if not validate_phone(from_number):
        logger.warning(f"Invalid phone number in SMS: {from_number}")
        return "OK", 200  # Return OK to prevent retries
    
    logger.info(f"[SMS] From: {from_number}, Message: {text[:50]}...")
    
    # Process SMS commands
    response_text = process_sms_command(text, from_number)
    
    # Send response via SMS
    if sms and response_text:
        try:
            result = sms.send(response_text, [from_number])
            print(f"[SMS] Response sent: {result}")
        except Exception as e:
            print(f"[SMS Error] Failed to send: {e}")
    
    return "OK", 200

def process_sms_command(message, phone_number):
    """Process SMS commands and return response"""
    
    # Load disease data
    try:
        disease_data = []
        with open(data_file_path('diseases.csv'), 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                disease_data.append(row)
    except Exception as e:
        print(f"[SMS Error] Could not load disease data: {e}")
        return "Sorry, our symptom checker is temporarily unavailable."
    
    # Command processing
    if message in ['hi', 'hello', 'start']:
        return """MediLinkBot Health Service
Commands:
MENU - Show main menu
SYMPTOMS <symptoms> - Check symptoms
EMERGENCY - Emergency contacts
DOCTOR - Find doctor
HELP - More info"""
    
    elif message == 'menu':
        return """MediLinkBot Menu:
1. SYMPTOMS <your symptoms>
2. EMERGENCY
3. DOCTOR
4. HELP

Example: SYMPTOMS fever headache"""
    
    elif message.startswith('symptom'):
        # Extract symptoms after "symptom" or "symptoms"
        symptoms_text = message.replace('symptom', '').replace('symptoms', '').strip()
        if not symptoms_text:
            return "Please provide symptoms. Example: SYMPTOMS fever headache"
        
        # Parse symptoms (split by common separators)
        symptoms = []
        for sep in [',', ' and ', ' & ', ' ']:
            if sep in symptoms_text:
                symptoms = [s.strip() for s in symptoms_text.split(sep) if s.strip()]
                break
        else:
            symptoms = [symptoms_text]
        
        # Analyze symptoms
        analysis = analyze_ussd_symptoms(symptoms, disease_data)
        
        if analysis:
            response = f"MediLinkBot Analysis:\n\n"
            for i, condition in enumerate(analysis[:3], 1):
                response += f"{i}. {condition['disease']} ({condition['confidence']}% match)\n"
            
            response += f"\nRecommended: {condition['specialist']}\n"
            response += f"\nConsult a healthcare provider for accurate diagnosis."
            return response
        else:
            return "No matching conditions found. Please describe symptoms differently."
    
    elif message == 'emergency':
        return """EMERGENCY CONTACTS:
• Emergency: 999/112
• COVID-19: 719
• Mental Health: 1190
• Nearest Hospital: Call 119

For immediate emergencies, call 999 now."""
    
    elif message == 'doctor':
        return """FIND A DOCTOR:
Visit: medilinkbot.com
Call: +254700123456
Available 24/7 for emergencies

Or reply with: SYMPTOMS <your symptoms> to get specialist recommendation."""
    
    elif message == 'help':
        return """MediLinkBot Help:
• SYMPTOMS fever headache - Check symptoms
• EMERGENCY - Get emergency numbers
• DOCTOR - Find healthcare provider
• MENU - Show all options

This is a free service. For medical emergencies, call 999."""
    
    else:
        return """Unknown command. Reply MENU for options or HELP for more info.
Example: SYMPTOMS fever headache"""


def get_ussd_symptoms_by_category(category, disease_data):
    """Extract symptoms by category for USSD interface"""
    category_symptoms = {
        '1': ['Fever', 'Headache', 'Body Pain', 'Chills', 'Fatigue'],
        '2': ['Cough', 'Cold', 'Sore Throat', 'Runny Nose', 'Chest Pain'],
        '3': ['Stomach Pain', 'Nausea', 'Vomiting', 'Diarrhea', 'Loss of Appetite'],
        '4': ['Skin Rash', 'Itching', 'Swelling', 'Redness', 'Dry Skin'],
        '5': ['Dizziness', 'Difficulty Breathing', 'Joint Pain', 'Anxiety', 'Depression']
    }
    return category_symptoms.get(category, ['Fever', 'Headache', 'Cough', 'Fatigue', 'Pain'])


def analyze_ussd_symptoms(symptoms, disease_data):
    """Simple symptom analysis for USSD interface"""
    results = []
    
    for disease in disease_data:
        disease_symptoms = [s.strip() for s in disease.get('symptoms', '').split(';')]
        match_count = sum(1 for symptom in symptoms if symptom in disease_symptoms)
        
        if match_count > 0:
            confidence = min(95, (match_count / len(symptoms)) * 100)
            results.append({
                'disease': disease.get('disease', 'Unknown'),
                'confidence': round(confidence),
                'specialist': disease.get('specialist', 'General Practitioner'),
                'medications': disease.get('medications', 'Consult doctor')
            })
    
    # Sort by confidence
    results.sort(key=lambda x: x['confidence'], reverse=True)
    return results[:5]  # Return top 5


# --- Nearby Health Facilities (OpenStreetMap / Leaflet) ---
@app.route('/facilities')
def facilities_page():
    """Render the nearby health facilities page (map + list)."""
    return render_template('facilities.html')


@app.route('/api/facilities')
def api_facilities():
    """Return nearby health facilities using OpenStreetMap / Overpass API."""
    try:
        lat = float(request.args.get('lat', ''))
        lng = float(request.args.get('lng', ''))
    except ValueError:
        return jsonify({'error': 'Invalid or missing coordinates'}), 400

    radius = int(request.args.get('radius', 3000))  # in meters

    overpass_url = "https://overpass-api.de/api/interpreter"
    overpass_query = f"""
    [out:json];
    (
      node["amenity"~"hospital|clinic|doctors|pharmacy"](around:{radius},{lat},{lng});
      way["amenity"~"hospital|clinic|doctors|pharmacy"](around:{radius},{lat},{lng});
      relation["amenity"~"hospital|clinic|doctors|pharmacy"](around:{radius},{lat},{lng});
    );
    out center 40;
    """

    try:
        resp = requests.post(overpass_url, data={'data': overpass_query}, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[Facilities Overpass Error] {e}")
        return jsonify({'error': 'Could not fetch facilities at the moment.'}), 500

    facilities = []
    for element in data.get('elements', []):
        tags = element.get('tags', {})
        name = tags.get('name')
        if not name:
            continue

        # Determine coordinates
        if 'lat' in element and 'lon' in element:
            flat = element['lat']
            flng = element['lon']
        elif 'center' in element:
            flat = element['center'].get('lat')
            flng = element['center'].get('lon')
        else:
            continue

        amenity = tags.get('amenity', '')
        address_parts = [
            tags.get('addr:street'),
            tags.get('addr:housenumber'),
            tags.get('addr:suburb'),
            tags.get('addr:city'),
        ]
        address = ", ".join([p for p in address_parts if p]) or tags.get('addr:full') or ''

        facilities.append({
            'name': name,
            'lat': flat,
            'lng': flng,
            'amenity': amenity,
            'address': address,
            'osm_id': element.get('id')
        })

    facilities = facilities[:40]
    return jsonify({'facilities': facilities})


# --- Local Disease Alerts ---
@app.route('/alerts')
def alerts_page():
    """Show local disease alerts & prevention tips."""
    region_code = request.args.get('region') or 'GLOBAL'
    region_code = region_code.upper()

    user_location = None
    if current_user.is_authenticated:
        loc = (current_user.location or '').lower()
        user_location = current_user.location or None
        if any(x in loc for x in ['kenya', 'nairobi', 'ke ']):
            region_code = 'KE'

    alerts = []
    global_alerts = []
    try:
        with open(data_file_path('alerts.json'), 'r', encoding='utf-8') as f:
            all_alerts = json.load(f)
        alerts = all_alerts.get(region_code, [])
        global_alerts = all_alerts.get('GLOBAL', [])
    except Exception as e:
        print(f"[Alerts Load Error] {e}")

    region_name_map = {
        'KE': 'Kenya',
        'GLOBAL': 'Global'
    }
    region_name = region_name_map.get(region_code, region_code)

    # Display name prioritises the user's saved location if available
    display_region = user_location or region_name

    return render_template(
        'alerts.html',
        region_code=region_code,
        region_name=region_name,
        display_region=display_region,
        alerts=alerts,
        global_alerts=global_alerts
    )


# --- App Launch ---
if __name__ == '__main__':
    # Initialize database tables
    with app.app_context():
        db.create_all()
    print("✅ MediLinkBot is running successfully!")
    app.run(host='0.0.0.0', port=5000, debug=True)
