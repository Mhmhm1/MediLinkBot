from flask import Flask, render_template, request, session, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import csv
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
import json
import google.generativeai as genai


app = Flask(__name__)
load_dotenv()

app.secret_key = os.getenv("SESSION_SECRET", "dev_secret_key")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///medilink.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

genai.configure(api_key="AIzaSyB30a5xsNaMevk3_OenzjyM9jq4GF3YvUg")

import google.generativeai as genai

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
def chat(doctor_name):
    patient_message = ""
    if request.method == "POST":
        data = request.get_json() or {}
        patient_message = data.get("message", "").strip()
        if not patient_message:
            return {"reply": "Please type a message to send."}

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
    with open('data/doctors.csv', newline='', encoding='utf-8') as csvfile:
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
    return doctors


def load_disease_data():
    diseases = []
    with open('data/diseases.csv', 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            diseases.append({
                'name': row['disease'],
                'symptoms': row['symptoms'].split(';'),
                'medications': row['medications'].split(';'),
                'specialist': row['specialist']
            })
    return diseases


def load_medication_data():
    medications = {}
    with open('data/medications.csv', 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            medications[row['medication']] = {
                'dosage': row['dosage'],
                'side_effects': row['side_effects'].split(';') if row['side_effects'] else []
            }
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
def signup():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        password2 = request.form.get('password2', '')
        if not email or not password:
            flash('Email and password are required.', 'danger')
            return render_template('signup.html')
        if password != password2:
            flash('Passwords do not match.', 'danger')
            return render_template('signup.html')
        if User.query.filter_by(email=email).first():
            flash('An account with this email already exists. Please log in.', 'warning')
            return redirect(url_for('login'))
        user = User(email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Account created. You are now logged in.', 'success')
        next_url = request.args.get('next')
        return redirect(next_url or url_for('index'))
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = bool(request.form.get('remember'))
        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash('Invalid email or password.', 'danger')
            return render_template('login.html')
        login_user(user, remember=remember)
        flash('Welcome back!', 'success')
        next_url = request.args.get('next')
        return redirect(next_url or url_for('index'))
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/symptoms', methods=['GET', 'POST'])
@login_required
def symptoms():
    if request.method == 'POST':
        selected_symptoms = request.form.getlist('symptoms[]')
        custom_symptoms = request.form.get('custom_symptoms', '').strip()
        all_symptoms = selected_symptoms.copy()
        if custom_symptoms:
            custom_list = [s.strip() for s in custom_symptoms.split(',') if s.strip()]
            all_symptoms.extend(custom_list)

        if not all_symptoms:
            return render_template('symptoms.html', symptoms=get_all_symptoms(),
                                   error="Please select or enter at least one symptom.")

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
        name = request.form.get('name', '').strip()
        age = request.form.get('age', '').strip()
        location = request.form.get('location', '').strip()
        selected_disease = request.form.get('selected_disease', '').strip()
        selected_doctor = request.form.get('selected_doctor', '').strip()

        if not all([name, age, location, selected_disease, selected_doctor]):
            return render_template('specialist.html', results=results_top2, doctors=doctors,
                                   error="Please fill in all fields and select a doctor.")

        selected_info = next((r for r in results if r['disease'] == selected_disease), None)
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
        name = request.form.get('name', '').strip()
        age = request.form.get('age', '').strip()
        location = request.form.get('location', '').strip()
        theme = request.form.get('theme')  # 'light' or 'dark'
        current_user.name = name
        current_user.age = age
        current_user.location = location
        # Save theme in preferences
        prefs = get_user_prefs(current_user)
        if theme in ('light', 'dark'):
            prefs['theme'] = theme
        set_user_prefs(current_user, prefs)
        try:
            db.session.commit()
            flash('Profile updated.', 'success')
        except Exception as e:
            print(f"[Profile Save Error] {e}")
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
        mode = (request.form.get('mode') or '').lower()
        date_str = request.form.get('date')  # yyyy-mm-dd
        slot_key = request.form.get('slot')  # e.g., '10-12'
        reason = request.form.get('reason', '').strip()
        contact_method = request.form.get('contact_method') if mode == 'virtual' else None
        contact_value = request.form.get('contact_value') if mode == 'virtual' else None

        if not all([doctor_name, doctor_specialty, mode, date_str, slot_key]):
            flash('Please complete all required fields.', 'danger')
            return render_template('book.html', doctor_name=doctor_name, doctor_specialty=doctor_specialty,
                                   hospital=hospital, phone=phone)

        try:
            date_obj = datetime.strptime(date_str, '%Y-%m-%d')
        except ValueError:
            flash('Invalid date.', 'danger')
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
    return render_template('booking_detail.html', appt=appt)


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


# --- App Launch ---
if __name__ == '__main__':
    # Initialize database tables
    with app.app_context():
        db.create_all()
    print("✅ MediLinkBot is running successfully!")
    app.run(host='0.0.0.0', port=5000, debug=True)
