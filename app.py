from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import psycopg2.extras
import os
from dotenv import load_dotenv

load_dotenv()
load_dotenv('.env.local')
from datetime import datetime, time
import requests
import re
import pandas as pd
import json
import secrets
import smtplib
from email.message import EmailMessage
from functools import wraps
import csv
import resend

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24))
app.config['DATABASE'] = os.getenv('DATABASE_URL', 'postgresql://neondb_owner:npg_aG0AXHZwe1Fb@ep-little-hill-adfj9zrj-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require')
app.config['ATTENDANCE_CSV'] = 'attendance.csv'
app.config['TIMETABLE_CSV'] = 'timetable.csv'

# Resend API Key
resend.api_key = os.getenv('RESEND_API_KEY', 're_RQs14xkL_AKD8VjE5UM78GhCyMPZqWhEk')

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config['RECAPTCHA_SITE_KEY'] = os.getenv('RECAPTCHA_SITE_KEY', '6LdEGxQsAAAAANrCOOl8NAPb68ZvrlvC1HPOMAZo')
app.config['RECAPTCHA_SECRET_KEY'] = os.getenv('RECAPTCHA_SECRET_KEY', '6LdEGxQsAAAAACcRR6OkK1MOBAlsDikyFfsPangx')

# Template filter for 12-hour time format
@app.template_filter('time12')
def time12_format(time_str):
    """Convert 24-hour time (HH:MM) to 12-hour format with AM/PM"""
    try:
        hour, minute = map(int, time_str.split(':'))
        period = 'AM' if hour < 12 else 'PM'
        if hour == 0:
            hour = 12
        elif hour > 12:
            hour -= 12
        return f"{hour}:{minute:02d} {period}"
    except:
        return time_str

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, email, full_name, student_id, role='student', section=None):
        self.id = id
        self.email = email
        self.full_name = full_name
        self.student_id = student_id
        self.role = role
        self.section = section
    
    def is_professor(self):
        return self.role == 'professor'

def init_db():
    conn = psycopg2.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            student_id TEXT NOT NULL,
            role TEXT DEFAULT 'student',
            department TEXT,
            designation TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Chamber hours table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chamber_hours (
            id SERIAL PRIMARY KEY,
            professor_id INTEGER NOT NULL,
            day_of_week TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            room_number TEXT,
            is_available INTEGER DEFAULT 1,
            FOREIGN KEY (professor_id) REFERENCES users(id)
        )
    ''')
    
    # Appointments table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS appointments (
            id SERIAL PRIMARY KEY,
            student_id INTEGER NOT NULL,
            professor_id INTEGER NOT NULL,
            chamber_hour_id INTEGER NOT NULL,
            appointment_date DATE NOT NULL,
            purpose TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES users(id),
            FOREIGN KEY (professor_id) REFERENCES users(id),
            FOREIGN KEY (chamber_hour_id) REFERENCES chamber_hours(id)
        )
    ''')
    
    # Password resets table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # Feedbacks table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedbacks (
            id SERIAL PRIMARY KEY,
            user_id INTEGER,
            course TEXT,
            q1 INTEGER,
            q2 INTEGER,
            q3 INTEGER,
            q4 INTEGER,
            q5 INTEGER,
            remarks TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Venue bookings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bookings (
            id SERIAL PRIMARY KEY,
            user_id INTEGER,
            venue_type TEXT,
            block TEXT,
            room_number TEXT,
            purpose TEXT,
            date TEXT,
            start_time TEXT,
            end_time TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Study materials table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS study_materials (
            id SERIAL PRIMARY KEY,
            course_code TEXT NOT NULL,
            course_name TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            file_path TEXT,
            file_name TEXT,
            file_size INTEGER,
            uploaded_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploaded_by) REFERENCES users(id)
        )
    ''')

    # Leaves table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS leaves (
            id SERIAL PRIMARY KEY,
            user_id INTEGER,
            leave_type TEXT,
            start_date TEXT,
            end_date TEXT,
            contact TEXT,
            reason TEXT,
            status TEXT,
            approver_notes TEXT,
            created_at TEXT
        )
    ''')

    conn.commit()
    conn.close()
    # Announcements and read-tracking
    try:
        conn = psycopg2.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS announcements (
                id SERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS announcement_reads (
                id SERIAL PRIMARY KEY,
                announcement_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(announcement_id, user_id)
            )
        ''')
        conn.commit()
        conn.close()
    except Exception:
        pass
    # Ensure single admin user exists
    try:
        conn = psycopg2.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        admin_email = 'admin@iimidr.ac.in'
        cursor.execute('SELECT * FROM users WHERE email = %s', (admin_email,))
        if not cursor.fetchone():
            from werkzeug.security import generate_password_hash
            admin_pw = 'adminiim'
            pw_hash = generate_password_hash(admin_pw)
            cursor.execute('INSERT INTO users (email, password_hash, full_name, student_id, role) VALUES (%s, %s, %s, %s, %s)',
                           (admin_email, pw_hash, 'Administrator', 'ADMIN', 'admin'))
            conn.commit()
        conn.close()
    except Exception:
        pass

def get_db():
    conn = psycopg2.connect(app.config['DATABASE'], cursor_factory=psycopg2.extras.DictCursor)
    return conn


def email_in_attendance(email):
    """Return True if the given email exists in the attendance CSV (4th column).
    Admin email is always allowed."""
    if not email:
        return False
    email_low = email.strip().lower()
    admin_email = 'admin@iimidr.ac.in'
    if email_low == admin_email:
        return True

    csv_path = app.config.get('ATTENDANCE_CSV')
    try:
        with open(csv_path, newline='', encoding='utf-8') as fh:
            reader = __import__('csv').reader(fh)
            rows = list(reader)
            # Data rows start after the first 3 header/meta lines in this file
            for r in rows[2:]:
                if len(r) > 3 and r[3] and str(r[3]).strip().lower() == email_low:
                    return True
    except Exception:
        # If CSV cannot be read, be conservative and deny
        return False
    return False


def create_reset_otp(user_id, expiry_minutes=15):
    # Generate 6-digit OTP
    otp = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    expires_at = (datetime.utcnow() + pd.Timedelta(minutes=expiry_minutes)).isoformat()
    conn = get_db()
    cursor = conn.cursor()
    # Clear existing tokens for this user
    cursor.execute('DELETE FROM password_resets WHERE user_id = %s', (user_id,))
    # Insert new OTP
    cursor.execute('INSERT INTO password_resets (user_id, token, expires_at) VALUES (%s, %s, %s)',
                   (user_id, otp, expires_at))
    conn.commit()
    conn.close()
    return otp


def verify_reset_otp(otp, user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM password_resets WHERE token = %s AND user_id = %s', (otp, user_id))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return False
    try:
        expires_at = datetime.fromisoformat(row['expires_at'])
    except Exception:
        return False
    if datetime.utcnow() > expires_at:
        return False
    return True

def send_reset_email(to_email, otp):
    subject = 'Password Reset OTP'
    html_content = f"""
    <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Password Reset Request</h2>
        <p>Your One-Time Password (OTP) for resetting your password is:</p>
        <div style="background: #f4f4f4; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; margin: 20px 0; border-radius: 8px;">
            {otp}
        </div>
        <p>This code will expire in 15 minutes.</p>
        <p>If you did not request this, please ignore this email.</p>
    </div>
    """

    try:
        params = {
            "from": "onboarding@resend.dev",
            "to": [to_email],
            "subject": subject,
            "html": html_content,
        }

        email = resend.Emails.send(params)
        print(f"OTP sent to {to_email} via Resend. ID: {email.get('id')}")
        return True
    except Exception as e:
        print(f"Failed to send OTP via Resend: {e}")
        # Fallback to console for development
        print(f"FALLBACK: OTP for {to_email}: {otp}")
        return False
    return False

@login_manager.user_loader
def load_user(user_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            # Debug logging for admin role issues
            if user_data['email'] == 'admin@iimidr.ac.in':
                print(f"DEBUG: Loading admin user. Role in DB: {user_data.get('role')}")

            # Try to infer section from attendance.csv by matching email
            section = None
            try:
                if os.path.exists(app.config['ATTENDANCE_CSV']):
                    df = pd.read_csv(app.config['ATTENDANCE_CSV'], skiprows=2)
                    df.columns = df.columns.str.strip()
                    email_col = None
                    for col in df.columns:
                        if 'email' in col.lower():
                            email_col = col
                            break
                    if email_col is not None:
                        matched = df[df[email_col].str.strip().str.lower() == user_data['email'].strip().lower()]
                        if not matched.empty and 'Section' in df.columns:
                            section_val = matched.iloc[0].get('Section')
                            if pd.notna(section_val):
                                section = str(section_val).strip()
            except Exception as e:
                print(f"Error reading section from CSV: {e}")
                section = None

            return User(user_data['id'], user_data['email'], 
                       user_data['full_name'], user_data['student_id'], 
                       user_data['role'], section)
    except Exception as e:
        print(f"Error loading user: {e}")
        return None
    return None

def verify_recaptcha(response):
    data = {
        'secret': app.config['RECAPTCHA_SECRET_KEY'],
        'response': response
    }
    r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
    if r.status_code != 200:
        flash('reCAPTCHA verification failed. Please try again.', 'error')
        return False
    return r.json().get('success', False)

def get_user_attendance(user_email):
    try:
        subject_row = pd.read_csv(app.config['ATTENDANCE_CSV'], nrows=1)
        subject_names_raw = subject_row.columns[7:].tolist()
        
        subject_names = []
        for s in subject_names_raw:
            s_clean = str(s).strip()
            if s_clean and s_clean != 'nan' and s_clean != '':
                subject_names.append(s_clean)
        
        df = pd.read_csv(app.config['ATTENDANCE_CSV'], skiprows=2)
        df.columns = df.columns.str.strip()
        
        email_col = None
        for col in df.columns:
            if 'email' in col.lower():
                email_col = col
                break
        
        if email_col is None:
            return None
        
        user_row = df[df[email_col].str.strip().str.lower() == user_email.strip().lower()]
        
        if user_row.empty:
            return None
        
        user_data = user_row.iloc[0]
        attendance_cols = df.columns[7:].tolist()
        
        attendance_dict = {}
        for i, subject in enumerate(subject_names):
            if i < len(attendance_cols):
                col_name = attendance_cols[i]
                value = str(user_data[col_name])
                
                if value and value != '#N/A' and value != 'nan' and value != '':
                    try:
                        percentage = float(value.replace('%', '').strip())
                        if percentage > 100:
                            percentage = 100
                        attendance_dict[subject] = percentage
                    except Exception as e:
                        pass
        
        return {
            'name': user_data.get('Name', 'N/A'),
            'roll_no': user_data.get('Roll No.', 'N/A'),
            'section': user_data.get('Section', 'N/A'),
            'subjects': attendance_dict
        }
    except Exception as e:
        print(f"Error reading attendance: {e}")
        return None

def get_timetable():
    try:
        df = pd.read_csv(app.config['TIMETABLE_CSV'], skiprows=3)
        time_slots = []
        for col in df.columns[2:]:
            header = str(col).strip() if col is not None else ''
            # Skip unnamed or empty columns that pandas may create (e.g., 'Unnamed: 5')
            if header and header.lower().startswith('unnamed'):
                continue
            if header and header.lower() != 'nan':
                time_slots.append(header)
        
        timetable = {}
        # Only include rows from today onwards
        today = datetime.now().date()
        for idx, row in df.iterrows():
            # First column expected to contain a date-like string
            day_date = str(row.iloc[0]).strip()
            room = str(row.iloc[1]).strip()

            if not day_date or day_date == 'nan':
                continue

            # Try to parse the date portion using pandas to_datetime (handles many formats)
            date_obj = pd.to_datetime(day_date, errors='coerce')
            if pd.isna(date_obj):
                # If parsing fails, include the row (defensive), but prefer to skip
                include_row = True
            else:
                include_row = date_obj.date() >= today

            if not include_row:
                continue

            day_key = day_date
            if day_key not in timetable:
                timetable[day_key] = {}

            for i, time_slot in enumerate(time_slots):
                col_idx = i + 2
                if col_idx < len(row):
                    class_name = str(row.iloc[col_idx]).strip()
                    if class_name and class_name != 'nan':
                        timetable[day_key].setdefault(time_slot, [])
                        timetable[day_key][time_slot].append({
                            'class': class_name,
                            'room': room
                        })
        
        # --- Apply column-entry remapping requested by UI/PM:
        # Shift entries so that the classes scheduled at
        # 4:00pm appear under 2:30pm, 5:30pm -> 4:00pm, and 7:00pm -> 5:30pm
        # (the original final 7:00pm slot will be left empty)
        def _norm(t):
            return re.sub(r"\s+", "", str(t)).lower()

        # helper to find first timeslot in list matching any of these keys
        def _find_slot(keys):
            for ts in time_slots:
                nt = _norm(ts)
                for k in keys:
                    if k in nt:
                        return ts
            return None

        # candidate search keys for mapping
        # use more specific patterns (avoid generic '5pm' that can match '15pm')
        slot_4 = _find_slot(['4.00', '4:00', '4.00pm', '4:00 pm', '4.00pmto'])
        slot_530 = _find_slot(['5.30', '5:30', '5.30pm', '5:30 pm', '5.30pmto'])
        slot_7 = _find_slot(['7.00', '7:00', '7.00pm', '7:00 pm', '7.00pmto'])

        new_schedule = {}
        for day_key, slots in timetable.items():
            new_slots = {}
            for ts in time_slots:
                nts = _norm(ts)
                source = None
                # if the displayed column is a 2:30 slot - show 4pm's content
                if ('2.30' in nts) or ('2:30' in nts) or ('2.30pm' in nts) or ('2:30pm' in nts):
                    source = slot_4
                # if displayed column is a 4:00 slot - show 5:30's content
                elif ('4.00' in nts) or ('4:00' in nts) or ('4pm' in nts) or ('4.00pm' in nts):
                    source = slot_530
                # if displayed column is 5:30 - show 7pm's content
                elif ('5.30' in nts) or ('5:30' in nts) or ('5:30pm' in nts):
                    source = slot_7
                # if displayed column is 7pm, we intentionally leave it empty (mapped None)
                elif ('7.00' in nts) or ('7:00' in nts) or ('7pm' in nts):
                    source = None
                else:
                    # default: keep original column entries
                    source = ts

                if source and source in slots:
                    new_slots[ts] = slots.get(source, [])
                else:
                    # either source is None (leave empty) or there is no data for that source
                    new_slots[ts] = slots.get(source, []) if source else []

            new_schedule[day_key] = new_slots

        return {
            'time_slots': time_slots,
            'schedule': new_schedule
        }
    except Exception as e:
        print(f"Error reading timetable: {e}")
        return None

@app.route('/bg-image')
def get_bg_image():
    """Serve background image from static folder."""
    # Try to serve .jpeg first, then .jpg
    image_dir = os.path.join(os.path.dirname(__file__), 'static', 'images')
    image_path = os.path.join(image_dir, 'iim-indore-bg.jpeg')
    
    if not os.path.exists(image_path):
        image_path = os.path.join(image_dir, 'iim-indore-bg.jpg')
    
    # Serve the image
    try:
        with open(image_path, 'rb') as f:
            image_data = f.read()
        return image_data, 200, {'Content-Type': 'image/jpeg', 'Cache-Control': 'public, max-age=604800'}
    except Exception as e:
        print(f"Error serving background image: {e}")
        return '', 404

@app.route('/')
def index():
    if current_user.is_authenticated:
        if getattr(current_user, 'role', '') == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.is_professor():
            return redirect(url_for('professor_dashboard'))
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if getattr(current_user, 'role', '') == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.is_professor():
            return redirect(url_for('professor_dashboard'))
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        captcha_response = request.form.get('g-recaptcha-response')
        
        if not verify_recaptcha(captcha_response):
            flash('Please complete the reCAPTCHA verification', 'error')
            return render_template('login.html', 
                                 site_key=app.config['RECAPTCHA_SITE_KEY'],
                                 email=email)
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user_data = cursor.fetchone()
        conn.close()

        # If a user exists and is not admin/professor, ensure their email is in attendance
        if user_data:
            role = user_data['role'] if user_data['role'] else ''
            if role not in ('admin', 'professor') and not email_in_attendance(email):
                flash('This email is not authorized to access the student portal.', 'error')
                return render_template('login.html', site_key=app.config['RECAPTCHA_SITE_KEY'], email=email)

        if user_data and check_password_hash(user_data['password_hash'], password):
            user = User(user_data['id'], user_data['email'], 
                       user_data['full_name'], user_data['student_id'],
                       user_data['role'])
            login_user(user, remember=True)
            flash('Login successful!', 'success')
            
            if user_data['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.is_professor():
                return redirect(url_for('professor_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            # Provide a clearer, user-friendly message for failed sign-ins
            flash("Unable to sign in. Please check your email and password and try again.", 'error')
    
    return render_template('login.html', site_key=app.config['RECAPTCHA_SITE_KEY'])


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if not email:
            flash('Please provide your registered email address', 'error')
            return render_template('forgot_password.html')

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE lower(email) = %s', (email,))
        user = cursor.fetchone()
        conn.close()

        if user:
            otp = create_reset_otp(user['id'])
            send_reset_email(user['email'], otp)
            session['reset_email'] = user['email']
            session['reset_user_id'] = user['id']
            return redirect(url_for('verify_otp'))
        else:
            # Do not reveal whether email exists, but for UX we might want to just say sent
            # However, since we need to redirect to OTP page, if user doesn't exist, 
            # we can't really redirect to OTP page effectively without a user ID.
            # So we will just flash a message and stay here or redirect to login.
            # But to mimic security, we could redirect to OTP page anyway but it will fail.
            # For simplicity in this project, let's just say "If account exists..."
            flash('If an account with that email exists, an OTP has been sent.', 'info')
            # Redirect to verify_otp anyway to prevent enumeration, but without session data it will fail or redirect back
            # Actually, let's just redirect to login as before if not found, or stay on page.
            # The user wants to go to OTP page. If we go to OTP page without sending email, they can't proceed.
            # So let's just redirect to login with the message.
            return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'reset_user_id' not in session:
        flash('Session expired. Please try again.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        otp = request.form.get('otp')
        user_id = session.get('reset_user_id')
        
        if verify_reset_otp(otp, user_id):
            session['otp_verified'] = True
            return redirect(url_for('reset_password_new'))
        else:
            flash('Invalid or expired OTP.', 'error')
    
    return render_template('verify_otp.html')


@app.route('/reset-password-new', methods=['GET', 'POST'])
def reset_password_new():
    if 'reset_user_id' not in session or not session.get('otp_verified'):
        flash('Unauthorized access. Please verify OTP first.', 'error')
        return redirect(url_for('forgot_password'))
        
    if request.method == 'POST':
        password = request.form.get('password')
        password2 = request.form.get('password2')
        
        if not password or password != password2:
            flash('Passwords do not match or are empty', 'error')
            return render_template('reset_password.html') # We can reuse the template or create new one

        user_id = session['reset_user_id']
        pw_hash = generate_password_hash(password)
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET password_hash = %s WHERE id = %s', (pw_hash, user_id))
        # Clear OTP
        cursor.execute('DELETE FROM password_resets WHERE user_id = %s', (user_id,))
        conn.commit()
        conn.close()
        
        # Clear session
        session.pop('reset_email', None)
        session.pop('reset_user_id', None)
        session.pop('otp_verified', None)

        flash('Password updated successfully. You can now log in.', 'success')
        return redirect(url_for('login'))

    # Reuse existing reset_password.html but we don't need token in context
    return render_template('reset_password.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name')
        student_id = request.form.get('student_id')
        captcha_response = request.form.get('g-recaptcha-response')
        
        if not verify_recaptcha(captcha_response):
            flash('Please complete the reCAPTCHA verification', 'error')
            return render_template('signup.html', 
                                 site_key=app.config['RECAPTCHA_SITE_KEY'],
                                 email=email, full_name=full_name, student_id=student_id)
        
        if not all([email, password, confirm_password, full_name, student_id]):
            flash('Please fill in all fields', 'error')
            return render_template('signup.html', 
                                 site_key=app.config['RECAPTCHA_SITE_KEY'],
                                 email=email, full_name=full_name, student_id=student_id)
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('signup.html', 
                                 site_key=app.config['RECAPTCHA_SITE_KEY'],
                                 email=email, full_name=full_name, student_id=student_id)
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('signup.html', 
                                 site_key=app.config['RECAPTCHA_SITE_KEY'],
                                 email=email, full_name=full_name, student_id=student_id)

        # Only allow signup if the email appears in the attendance CSV
        if not email_in_attendance(email):
            flash('Signup not allowed: your email is not listed in the attendance records.', 'error')
            return render_template('signup.html', 
                                 site_key=app.config['RECAPTCHA_SITE_KEY'],
                                 email=email, full_name=full_name, student_id=student_id)
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            conn.close()
            flash('An account with this email already exists. Please login instead.', 'error')
            return render_template('signup.html', 
                                 site_key=app.config['RECAPTCHA_SITE_KEY'],
                                 email=email, full_name=full_name, student_id=student_id)
        
        password_hash = generate_password_hash(password)
        cursor.execute('''
            INSERT INTO users (email, password_hash, full_name, student_id, role)
            VALUES (%s, %s, %s, %s, 'student') RETURNING id
        ''', (email, password_hash, full_name, student_id))
        conn.commit()
        user_id = cursor.fetchone()[0]
        conn.close()
        
        user = User(user_id, email, full_name, student_id, 'student')
        login_user(user, remember=True)
        flash('Account created successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('signup.html', site_key=app.config['RECAPTCHA_SITE_KEY'])

@app.route('/professor-signup', methods=['GET', 'POST'])
def professor_signup():
    if current_user.is_authenticated:
        return redirect(url_for('professor_dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name')
        employee_id = request.form.get('employee_id')
        department = request.form.get('department')
        designation = request.form.get('designation')
        captcha_response = request.form.get('g-recaptcha-response')
        
        if not verify_recaptcha(captcha_response):
            flash('Please complete the reCAPTCHA verification', 'error')
            return render_template('professor_signup.html', 
                                 site_key=app.config['RECAPTCHA_SITE_KEY'],
                                 email=email, full_name=full_name, employee_id=employee_id,
                                 department=department, designation=designation)
        
        if not all([email, password, confirm_password, full_name, employee_id, department, designation]):
            flash('Please fill in all fields', 'error')
            return render_template('professor_signup.html', 
                                 site_key=app.config['RECAPTCHA_SITE_KEY'],
                                 email=email, full_name=full_name, employee_id=employee_id,
                                 department=department, designation=designation)
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('professor_signup.html', 
                                 site_key=app.config['RECAPTCHA_SITE_KEY'],
                                 email=email, full_name=full_name, employee_id=employee_id,
                                 department=department, designation=designation)
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('professor_signup.html', 
                                 site_key=app.config['RECAPTCHA_SITE_KEY'],
                                 email=email, full_name=full_name, employee_id=employee_id,
                                 department=department, designation=designation)
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            conn.close()
            flash('An account with this email already exists. Please login instead.', 'error')
            return render_template('professor_signup.html', 
                                 site_key=app.config['RECAPTCHA_SITE_KEY'],
                                 email=email, full_name=full_name, employee_id=employee_id,
                                 department=department, designation=designation)
        
        password_hash = generate_password_hash(password)
        cursor.execute('''
            INSERT INTO users (email, password_hash, full_name, student_id, role, department, designation)
            VALUES (%s, %s, %s, %s, 'professor', %s, %s) RETURNING id
        ''', (email, password_hash, full_name, employee_id, department, designation))
        conn.commit()
        user_id = cursor.fetchone()[0]
        conn.close()
        
        user = User(user_id, email, full_name, employee_id, 'professor')
        login_user(user, remember=True)
        flash('Professor account created successfully!', 'success')
        return redirect(url_for('professor_dashboard'))
    
    return render_template('professor_signup.html', site_key=app.config['RECAPTCHA_SITE_KEY'])

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_authenticated:
        if getattr(current_user, 'role', '') == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.is_professor():
            return redirect(url_for('professor_dashboard'))
    return render_template('dashboard.html', user=current_user)

@app.route('/professor-dashboard')
@login_required
def professor_dashboard():
    conn = get_db()
    cursor = conn.cursor()
    
    # Get chamber hours count
    cursor.execute('SELECT COUNT(*) as count FROM chamber_hours WHERE professor_id = %s', 
                  (current_user.id,))
    chamber_hours_count = cursor.fetchone()['count']
    
    # Get pending appointments count
    cursor.execute('''SELECT COUNT(*) as count FROM appointments 
                     WHERE professor_id = %s AND status = 'pending' ''', 
                  (current_user.id,))
    pending_count = cursor.fetchone()['count']
    
    conn.close()
    
    return render_template('professor_dashboard.html', 
                         user=current_user,
                         chamber_hours_count=chamber_hours_count,
                         pending_appointments=pending_count)

@app.route('/chamber-hours', methods=['GET', 'POST'])
@login_required
def chamber_hours():
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        date = request.form.get('date')
        start_hour = int(request.form.get('start_hour'))
        start_minute = int(request.form.get('start_minute'))
        start_period = request.form.get('start_period')
        end_hour = int(request.form.get('end_hour'))
        end_minute = int(request.form.get('end_minute'))
        end_period = request.form.get('end_period')
        room_number = request.form.get('room_number')
        
        # Convert 12-hour to 24-hour format for storage
        if start_period == 'PM' and start_hour != 12:
            start_hour += 12
        elif start_period == 'AM' and start_hour == 12:
            start_hour = 0
            
        if end_period == 'PM' and end_hour != 12:
            end_hour += 12
        elif end_period == 'AM' and end_hour == 12:
            end_hour = 0
        
        start_time = f"{start_hour:02d}:{start_minute:02d}"
        end_time = f"{end_hour:02d}:{end_minute:02d}"
        
        # Validate that end time is after start time
        start_total_minutes = start_hour * 60 + start_minute
        end_total_minutes = end_hour * 60 + end_minute
        
        if end_total_minutes <= start_total_minutes:
            flash('End time must be after start time!', 'error')
            conn.close()
            return redirect(url_for('chamber_hours'))
        
        cursor.execute('''
            INSERT INTO chamber_hours (professor_id, day_of_week, start_time, end_time, room_number)
            VALUES (%s, %s, %s, %s, %s)
        ''', (current_user.id, date, start_time, end_time, room_number))
        conn.commit()
        flash('Chamber hour added successfully!', 'success')
        return redirect(url_for('chamber_hours'))
    
    cursor.execute('''SELECT * FROM chamber_hours 
                     WHERE professor_id = %s ORDER BY day_of_week, start_time''', (current_user.id,))
    hours = cursor.fetchall()
    conn.close()
    
    return render_template('chamber_hours.html', user=current_user, hours=hours)

@app.route('/delete-chamber-hour/<int:hour_id>')
@login_required
def delete_chamber_hour(hour_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        # First delete associated appointments
        cursor.execute('DELETE FROM appointments WHERE chamber_hour_id = %s', (hour_id,))
        # Then delete the chamber hour
        cursor.execute('DELETE FROM chamber_hours WHERE id = %s AND professor_id = %s', 
                      (hour_id, current_user.id))
        conn.commit()
        flash('Chamber hour deleted successfully!', 'success')
    except Exception as e:
        conn.rollback()
        print(f"Error deleting chamber hour: {e}")
        flash('An error occurred while deleting the chamber hour.', 'error')
    finally:
        conn.close()
    return redirect(url_for('chamber_hours'))

@app.route('/book-appointment', methods=['GET', 'POST'])
@login_required
def book_appointment():
    if current_user.is_professor():
        flash('Professors cannot book appointments', 'error')
        return redirect(url_for('professor_dashboard'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        professor_id = request.form.get('professor_id')
        chamber_hour_id = request.form.get('chamber_hour_id')
        purpose = request.form.get('purpose')
        
        # Auto-set appointment date to current date
        from datetime import date
        appointment_date = date.today().isoformat()
        
        cursor.execute('''
            INSERT INTO appointments (student_id, professor_id, chamber_hour_id, appointment_date, purpose)
            VALUES (%s, %s, %s, %s, %s)
        ''', (current_user.id, professor_id, chamber_hour_id, appointment_date, purpose))
        conn.commit()
        conn.close()
        flash('Appointment request sent successfully!', 'success')
        return redirect(url_for('my_appointments'))
    
    # Get all professors
    cursor.execute('''SELECT id, full_name, department, designation 
                     FROM users WHERE role = 'professor' ORDER BY full_name''')
    professors = cursor.fetchall()
    
    conn.close()
    return render_template('book_appointment.html', user=current_user, professors=professors)

@app.route('/api/professor-hours/<int:professor_id>')
@login_required
def get_professor_hours(professor_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''SELECT id, day_of_week, start_time, end_time, room_number 
                     FROM chamber_hours WHERE professor_id = %s AND is_available = 1
                     ORDER BY day_of_week, start_time''', (professor_id,))
    hours = cursor.fetchall()
    conn.close()
    
    return jsonify([dict(h) for h in hours])

@app.route('/my-appointments')
@login_required
def my_appointments():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT a.*, u.full_name as professor_name, u.department, u.designation,
               ch.day_of_week, ch.start_time, ch.end_time, ch.room_number
        FROM appointments a
        JOIN users u ON a.professor_id = u.id
        JOIN chamber_hours ch ON a.chamber_hour_id = ch.id
        WHERE a.student_id = %s
        ORDER BY a.appointment_date DESC, a.created_at DESC
    ''', (current_user.id,))
    appointments = cursor.fetchall()
    conn.close()
    
    return render_template('my_appointments.html', user=current_user, appointments=appointments)

@app.route('/professor-appointments')
@login_required
def professor_appointments():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT a.*, u.full_name as student_name, u.email as student_email, u.student_id,
               ch.day_of_week, ch.start_time, ch.end_time, ch.room_number
        FROM appointments a
        JOIN users u ON a.student_id = u.id
        JOIN chamber_hours ch ON a.chamber_hour_id = ch.id
        WHERE a.professor_id = %s
        ORDER BY a.status, a.appointment_date DESC, a.created_at DESC
    ''', (current_user.id,))
    appointments = cursor.fetchall()
    conn.close()
    
    return render_template('professor_appointments.html', user=current_user, appointments=appointments)

@app.route('/update-appointment/<int:appointment_id>/<action>')
@login_required
def update_appointment(appointment_id, action):
    if action not in ['accept', 'decline']:
        flash('Invalid action', 'error')
        return redirect(url_for('professor_appointments'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    status = 'accepted' if action == 'accept' else 'declined'
    cursor.execute('''UPDATE appointments SET status = %s 
                     WHERE id = %s AND professor_id = %s''', 
                  (status, appointment_id, current_user.id))
    conn.commit()
    conn.close()
    
    flash(f'Appointment {status} successfully!', 'success')
    return redirect(url_for('professor_appointments'))

@app.route('/attendance')
@login_required
def attendance():
    if current_user.is_professor():
        flash('Attendance is for students only', 'error')
        return redirect(url_for('professor_dashboard'))
    
    attendance_data = get_user_attendance(current_user.email)
    
    if not attendance_data:
        flash('No attendance data found for your account', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('attendance.html', 
                         user=current_user, 
                         attendance=attendance_data)

@app.route('/timetable')
@login_required
def timetable():
    if current_user.is_professor():
        flash('Timetable is for students only', 'error')
        return redirect(url_for('professor_dashboard'))
    
    timetable_data = get_timetable()
    # Filter timetable based on student's section (A -> E-301, B -> E-303)
    try:
        user_section = getattr(current_user, 'section', None)
        room_map = {'A': 'E-301', 'B': 'E-303'}
        if timetable_data and user_section:
            desired_room = room_map.get(user_section.strip().upper())
            if desired_room:
                # Create filtered copy
                filtered_schedule = {}
                for day, slots in timetable_data['schedule'].items():
                    for slot, entries in slots.items():
                        for entry in entries:
                            if entry.get('room') == desired_room:
                                filtered_schedule.setdefault(day, {}).setdefault(slot, []).append(entry)
                timetable_data = {
                    'time_slots': timetable_data.get('time_slots', []),
                    'schedule': filtered_schedule
                }
    except Exception as e:
        print(f"Error filtering timetable by section: {e}")
    
    if not timetable_data:
        flash('No timetable data available', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('timetable.html', 
                         user=current_user, 
                         timetable=timetable_data)


@app.route('/feedback')
@login_required
def feedback():
    if current_user.is_professor():
        flash('Feedback is for students only', 'error')
        return redirect(url_for('professor_dashboard'))

    # Try to load courses metadata from `courses.csv`; fallback to curated list of names
    courses = []
    csv_path = os.path.join(os.path.dirname(__file__), 'courses.csv')
    try:
        if os.path.exists(csv_path):
            with open(csv_path, newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # normalize keys/values: strip whitespace
                    cleaned = {k.strip(): (v.strip() if v is not None else '') for k, v in row.items()}
                    courses.append(cleaned)
    except Exception as e:
        print(f"Failed to read courses CSV: {e}")

    if not courses:
        courses = [
            'Multivariate Statistics', 'Web Development', 'Applied Ethics',
            'Contemporary Social Issues', 'Econometrics', 'Linear Programming',
            'Spanish', 'French', 'Law'
        ]

    return render_template('feedback_courses.html', user=current_user, courses=courses)


@app.route('/feedback/<path:course>', methods=['GET', 'POST'])
@login_required
def feedback_course(course):
    # normalize course selection to one of the curated list
    valid_courses = [
        'Multivariate Statistics', 'Web Development', 'Applied Ethics',
        'Contemporary Social Issues', 'Econometrics', 'Linear Programming',
        'Spanish', 'French', 'Law'
    ]
    # If course not in list (possibly URL-encoded), try to match case-insensitively
    matched = None
    for c in valid_courses:
        if c.lower() == course.replace('+', ' ').lower() or c.lower() == course.lower():
            matched = c
            break
    if not matched:
        # try unquoting
        from urllib.parse import unquote_plus
        uq = unquote_plus(course)
        for c in valid_courses:
            if c.lower() == uq.lower():
                matched = c
                break

    if not matched:
        flash('Unknown course selected', 'error')
        return redirect(url_for('feedback'))

    course_name = matched

    questions = [
        'Rate the overall quality of the course.',
        'Rate how effectively the professor explained concepts.',
        'Rate how engaging the class sessions and activities were.',
        'Rate how well the course was structured in terms of pace, clarity, and content flow.',
        'Rate how likely you are to recommend this course to future students.'
    ]

    if request.method == 'POST':
        try:
            q1 = int(request.form.get('q1') or 0)
            q2 = int(request.form.get('q2') or 0)
            q3 = int(request.form.get('q3') or 0)
            q4 = int(request.form.get('q4') or 0)
            q5 = int(request.form.get('q5') or 0)
        except Exception:
            flash('Please provide valid ratings for all questions.', 'error')
            return render_template('feedback_form.html', course=course_name, questions=questions)

        remarks = request.form.get('remarks', '').strip()

        # Save to CSV
        csv_path = os.path.join(os.path.dirname(__file__), 'feedback_responses.csv')
        header = ['timestamp', 'user_id', 'email', 'full_name', 'course', 'q1', 'q2', 'q3', 'q4', 'q5', 'remarks']
        row = [datetime.now().isoformat(), current_user.id, current_user.email, current_user.full_name, course_name, q1, q2, q3, q4, q5, remarks]

        write_header = not os.path.exists(csv_path)
        try:
            with open(csv_path, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                if write_header:
                    writer.writerow(header)
                writer.writerow(row)
        except Exception as e:
            print(f"Failed to write feedback CSV: {e}")

        # Also insert into DB feedbacks table for internal use (optional)
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO feedbacks (user_id, course, q1, q2, q3, q4, q5, remarks) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)',
                           (current_user.id, course_name, q1, q2, q3, q4, q5, remarks))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Failed to insert feedback into DB: {e}")

        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('feedback_form.html', course=course_name, questions=questions)


@app.route('/venue-booking', methods=['GET', 'POST'])
@login_required
def venue_booking():
    try:
        if current_user.is_professor():
            # allow professors too? keep same behavior: allow students and professors
            pass

        if request.method == 'POST':
            venue_type = request.form.get('venue_type')
            block = request.form.get('block')
            room_number = request.form.get('room_number')
            purpose = request.form.get('purpose')
            date = request.form.get('date')
            
            # Get 12-hour time format inputs
            try:
                start_hour = int(request.form.get('start_hour'))
                start_minute = int(request.form.get('start_minute'))
                start_period = request.form.get('start_period')
                end_hour = int(request.form.get('end_hour'))
                end_minute = int(request.form.get('end_minute'))
                end_period = request.form.get('end_period')
            except (ValueError, TypeError):
                flash('Invalid time format provided.', 'error')
                return redirect(url_for('venue_booking'))
            
            # Convert 12-hour to 24-hour format for storage
            if start_period == 'PM' and start_hour != 12:
                start_hour += 12
            elif start_period == 'AM' and start_hour == 12:
                start_hour = 0
                
            if end_period == 'PM' and end_hour != 12:
                end_hour += 12
            elif end_period == 'AM' and end_hour == 12:
                end_hour = 0
            
            start_time = f"{start_hour:02d}:{start_minute:02d}"
            end_time = f"{end_hour:02d}:{end_minute:02d}"
            
            # Validate that end time is after start time
            start_total_minutes = start_hour * 60 + start_minute
            end_total_minutes = end_hour * 60 + end_minute
            
            if end_total_minutes <= start_total_minutes:
                flash('End time must be after start time!', 'error')
                return redirect(url_for('venue_booking'))

            if not venue_type or not date or not purpose:
                flash('Please fill all required booking fields.', 'error')
                return redirect(url_for('venue_booking'))

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO bookings (user_id, venue_type, block, room_number, purpose, date, start_time, end_time, status) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)',
                           (current_user.id, venue_type, block, room_number, purpose, date, start_time, end_time, 'pending'))
            conn.commit()
            conn.close()

            flash('Booking submitted successfully. Status: pending', 'success')
            return redirect(url_for('venue_booking'))

        # GET: provide blocks and room numbers for classrooms and fetch user's booking history
        blocks = ['D', 'E', 'F', 'G']
        room_numbers = ['101','103','201','203','301','303']
        venue_types = ['Classroom', 'Music Room', 'Auditorium', 'SAC Room']
        
        # Fetch user's bookings
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM bookings WHERE user_id = %s ORDER BY created_at DESC', (current_user.id,))
            bookings = cursor.fetchall()
            conn.close()
        except Exception as e:
            print(f"Error fetching bookings: {e}")
            bookings = []
        
        return render_template('venue_booking.html', user=current_user, blocks=blocks, room_numbers=room_numbers, venue_types=venue_types, bookings=bookings)
    except Exception as e:
        print(f"CRITICAL Error in venue_booking: {e}")
        return render_template('venue_booking.html', user=current_user, blocks=[], room_numbers=[], venue_types=[], bookings=[], error="An internal error occurred.")

@app.route('/api/attendance-data')
@login_required
def attendance_data_api():
    attendance_data = get_user_attendance(current_user.email)
    
    if not attendance_data:
        return jsonify({'error': 'No data found'}), 404
    
    return jsonify(attendance_data['subjects'])

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/leave-management')
@login_required
def leave_management():
    # Ensure leaves table exists and fetch user's leave records
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM leaves WHERE user_id = %s ORDER BY created_at DESC', (current_user.id,))
    leaves = cursor.fetchall()

    # Compute counts
    counts = {'approved': 0, 'pending': 0, 'disapproved': 0}
    history = []
    for r in leaves:
        status = (r['status'] or 'pending').lower()
        if status == 'approved':
            counts['approved'] += 1
        elif status in ('disapproved', 'declined', 'rejected'):
            counts['disapproved'] += 1
        else:
            counts['pending'] += 1

        history.append({
            'id': r['id'],
            'leave_type': r['leave_type'],
            'start_date': r['start_date'],
            'end_date': r['end_date'],
            'contact': r['contact'],
            'reason': r['reason'],
            'status': status,
            'approver_notes': r['approver_notes'] if 'approver_notes' in r.keys() else None,
            'created_at': r['created_at']
        })

    conn.close()
    return render_template('leave_management.html', counts=counts, history=history)


@app.route('/apply-leave', methods=['POST'])
@login_required
def apply_leave():
    # Collect form data
    leave_type = request.form.get('leaveType')
    start_date = request.form.get('startDate')
    end_date = request.form.get('endDate')
    contact = request.form.get('contactNumber')
    reason = request.form.get('reason')

    # Simple validation (contact is optional / removed from form)
    if not leave_type or not start_date or not end_date or not reason:
        flash('Please fill all required fields for leave application.', 'error')
        return redirect(url_for('leave_management'))

    # Server-side date validation: ensure year parts are exactly 4 digits, start >= today and end >= start
    try:
        s_year = start_date.split('-')[0]
        e_year = end_date.split('-')[0]
    except Exception:
        flash('Invalid date format provided.', 'error')
        return redirect(url_for('leave_management'))

    if not (s_year.isdigit() and e_year.isdigit() and len(s_year) == 4 and len(e_year) == 4):
        flash('Year must be exactly 4 digits (YYYY) for start and end dates.', 'error')
        return redirect(url_for('leave_management'))

    try:
        start_dt = datetime.strptime(start_date, '%Y-%m-%d').date()
        end_dt = datetime.strptime(end_date, '%Y-%m-%d').date()
    except Exception:
        flash('Invalid date format provided.', 'error')
        return redirect(url_for('leave_management'))

    today_date = datetime.now().date()
    if start_dt < today_date:
        flash('Start date cannot be before today.', 'error')
        return redirect(url_for('leave_management'))
    if end_dt < start_dt:
        flash('End date cannot be before the start date.', 'error')
        return redirect(url_for('leave_management'))

    # Save to database (create table if not exists)
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO leaves (user_id, leave_type, start_date, end_date, contact, reason, status, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    ''', (current_user.id, leave_type, start_date, end_date, contact, reason, 'pending', datetime.now().isoformat()))
    conn.commit()
    conn.close()

    flash('Leave request submitted successfully.', 'success')
    return redirect(url_for('dashboard'))


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if getattr(current_user, 'role', '') != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard'))
        return func(*args, **kwargs)
    return wrapper


def professor_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if getattr(current_user, 'role', '') != 'professor':
            flash('Professor access required', 'error')
            return redirect(url_for('dashboard'))
        return func(*args, **kwargs)
    return wrapper


@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    # provide a short list of recent announcements for admin overview
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, title, substr(body,1,240) as snippet, created_at FROM announcements ORDER BY created_at DESC LIMIT 6')
    recent = cursor.fetchall()
    conn.close()
    return render_template('admin_dashboard.html', user=current_user, recent_announcements=recent)


@app.route('/admin/post-announcement', methods=['POST'])
@login_required
@admin_required
def admin_post_announcement():
    title = request.form.get('title', '').strip()
    body = request.form.get('body', '').strip()

    if not title or not body:
        flash('Please provide both title and message to publish announcement.', 'error')
        return redirect(url_for('admin_dashboard'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO announcements (title, body, created_by) VALUES (%s, %s, %s)',
                   (title, body, current_user.id))
    conn.commit()
    conn.close()

    flash('Announcement published successfully.', 'success')
    return redirect(url_for('admin_announcements'))


@app.route('/api/announcements')
@login_required
def api_announcements():
    """Return JSON list of announcements with read/unread flag for current user."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, title, body, created_by, created_at FROM announcements ORDER BY created_at DESC LIMIT 50')
    rows = cursor.fetchall()

    # Check read statuses
    results = []
    for r in rows:
        aid = r['id']
        cursor.execute('SELECT 1 FROM announcement_reads WHERE announcement_id = %s AND user_id = %s', (aid, current_user.id))
        is_read = True if cursor.fetchone() else False
        body = r['body'] or ''
        preview = (body[:160] + '...') if len(body) > 160 else body
        results.append({
            'id': aid,
            'title': r['title'],
            'preview': preview,
            'body': body,
            'created_at': r['created_at'],
            'is_read': is_read
        })
    conn.close()
    return jsonify(results)


@app.route('/admin/announcements')
@login_required
@admin_required
def admin_announcements():
    """Admin-only page to list and publish announcements."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, title, body, created_by, created_at FROM announcements ORDER BY created_at DESC')
    rows = cursor.fetchall()
    conn.close()
    return render_template('admin_announcements.html', announcements=rows, user=current_user)


@app.route('/admin/announcements/delete/<int:aid>', methods=['POST'])
@login_required
@admin_required
def admin_delete_announcement(aid):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT id FROM announcements WHERE id = %s', (aid,))
    if not cursor.fetchone():
        conn.close()
        flash('Announcement not found.', 'error')
        return redirect(url_for('admin_announcements'))

    # remove read-tracking entries first, then the announcement
    try:
        cursor.execute('DELETE FROM announcement_reads WHERE announcement_id = %s', (aid,))
        cursor.execute('DELETE FROM announcements WHERE id = %s', (aid,))
        conn.commit()
    except Exception:
        conn.rollback()
        flash('Failed to delete announcement.', 'error')
        conn.close()
        return redirect(url_for('admin_announcements'))

    conn.close()
    flash('Announcement deleted successfully.', 'success')
    return redirect(url_for('admin_announcements'))


@app.route('/announcement/<int:aid>')
@login_required
def view_announcement(aid):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, title, body, created_by, created_at FROM announcements WHERE id = %s', (aid,))
    row = cursor.fetchone()
    if not row:
        flash('Announcement not found', 'error')
        return redirect(url_for('dashboard') if not current_user.is_professor() else url_for('professor_dashboard'))

    # mark read
    try:
        cursor.execute('INSERT INTO announcement_reads (announcement_id, user_id) VALUES (%s, %s) ON CONFLICT DO NOTHING', (aid, current_user.id))
        conn.commit()
    except Exception:
        pass

    conn.close()
    return render_template('announcement_detail.html', announcement=row, user=current_user)


@app.route('/api/announcements/mark_read/<int:aid>', methods=['POST'])
@login_required
def api_mark_announcement_read(aid):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO announcement_reads (announcement_id, user_id) VALUES (%s, %s) ON CONFLICT DO NOTHING', (aid, current_user.id))
        conn.commit()
    except Exception:
        pass
    conn.close()
    return jsonify({'ok': True})


@app.route('/announcements')
@login_required
def announcements_list():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, title, body, created_by, created_at FROM announcements ORDER BY created_at DESC')
    rows = cursor.fetchall()

    # Attach read status
    ann = []
    for r in rows:
        cursor.execute('SELECT 1 FROM announcement_reads WHERE announcement_id = %s AND user_id = %s', (r['id'], current_user.id))
        is_read = True if cursor.fetchone() else False
        ann.append({'id': r['id'], 'title': r['title'], 'body': r['body'], 'created_at': r['created_at'], 'is_read': is_read})
    conn.close()
    return render_template('announcements.html', announcements=ann, user=current_user)


@app.route('/admin/timetable')
@login_required
@admin_required
def admin_timetable():
    timetable_data = get_timetable() or {'time_slots': [], 'schedule': {}}
    return render_template('admin_timetable.html', user=current_user, timetable=timetable_data)


@app.route('/admin/attendance')
@login_required
@admin_required
def admin_attendance():
    # Read attendance CSV and prepare a table of students vs subjects
    import csv as _csv
    subject_names = []
    students = []
    csv_path = app.config['ATTENDANCE_CSV']
    try:
        with open(csv_path, newline='', encoding='utf-8') as fh:
            reader = _csv.reader(fh)
            # First row contains subject short names starting at column 7
            header1 = next(reader)
            # skip second header row (types like 'Attendance %') and third header (column names)
            try:
                header2 = next(reader)
            except StopIteration:
                header2 = []
            try:
                header3 = next(reader)
            except StopIteration:
                header3 = []

            # subjects are in header1 from index 7 onwards
            raw_subjects = header1[7:]
            for s in raw_subjects:
                if s and not str(s).strip().lower().startswith('unnamed'):
                    subject_names.append(str(s).strip())

        # Now load the data rows using pandas skipping the first two meta rows
        df = pd.read_csv(csv_path, skiprows=2)
        df.columns = df.columns.str.strip()

        # find name/email/section columns
        name_col = next((c for c in df.columns if 'name' in c.lower()), None)
        email_col = next((c for c in df.columns if 'email' in c.lower()), None)
        section_col = next((c for c in df.columns if 'section' in c.lower()), None)

        # subject columns are assumed to be df.columns[7:7+len(subject_names)]
        subj_start = 7
        subj_cols = df.columns[subj_start:subj_start+len(subject_names)].tolist() if subject_names else df.columns[7:].tolist()

        for _, row in df.iterrows():
            student = {
                'name': row.get(name_col, '') if name_col else '',
                'email': row.get(email_col, '') if email_col else '',
                'section': row.get(section_col, '') if section_col else ''
            }
            scores = []
            for c in subj_cols:
                val = row.get(c, '')
                sval = '' if pd.isna(val) else str(val).strip()
                if sval and sval != '#N/A' and sval.lower() != 'nan':
                    # extract numeric portion
                    try:
                        if '%' in sval:
                            num = float(sval.replace('%',''))
                        else:
                            num = float(sval)
                        scores.append(min(max(round(num,2),0),100))
                    except Exception:
                        scores.append(None)
                else:
                    scores.append(None)
            student['scores'] = scores
            students.append(student)
    except Exception as e:
        print(f"Error reading attendance CSV for admin view: {e}")

    return render_template('admin_attendance.html', user=current_user, subjects=subject_names, students=students)


@app.route('/admin/requests')
@login_required
@admin_required
def admin_requests():
    conn = get_db()
    cursor = conn.cursor()
    # Bookings
    cursor.execute('''SELECT b.*, u.full_name as student_name, u.email as student_email
                      FROM bookings b LEFT JOIN users u ON b.user_id = u.id
                      ORDER BY b.created_at DESC''')
    bookings = cursor.fetchall()

    # Leaves
    cursor.execute('''SELECT l.*, u.full_name as student_name, u.email as student_email
                      FROM leaves l LEFT JOIN users u ON l.user_id = u.id
                      ORDER BY l.created_at DESC''')
    leaves = cursor.fetchall()
    conn.close()
    return render_template('admin_requests.html', user=current_user, bookings=bookings, leaves=leaves)


@app.route('/admin/approve-booking/<int:bid>')
@login_required
@admin_required
def approve_booking(bid):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE bookings SET status = %s WHERE id = %s', ('approved', bid))
    conn.commit()
    conn.close()
    flash('Booking approved', 'success')
    return redirect(url_for('admin_requests'))


@app.route('/admin/deny-booking/<int:bid>')
@login_required
@admin_required
def deny_booking(bid):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE bookings SET status = %s WHERE id = %s', ('denied', bid))
    conn.commit()
    conn.close()
    flash('Booking denied', 'success')
    return redirect(url_for('admin_requests'))


@app.route('/admin/approve-leave/<int:lid>')
@login_required
@admin_required
def approve_leave(lid):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE leaves SET status = %s WHERE id = %s', ('approved', lid))
    conn.commit()
    conn.close()
    flash('Leave approved', 'success')
    return redirect(url_for('admin_requests'))


@app.route('/admin/deny-leave/<int:lid>')
@login_required
@admin_required
def deny_leave(lid):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE leaves SET status = %s WHERE id = %s', ('disapproved', lid))
    conn.commit()
    conn.close()
    flash('Leave denied', 'success')
    return redirect(url_for('admin_requests'))


@app.route('/admin/feedbacks')
@login_required
@admin_required
def admin_feedbacks():
    # Read feedback responses from CSV and organize by student and course
    import csv as _csv
    csv_path = os.path.join(os.path.dirname(__file__), 'feedback_responses.csv')
    
    # Data structure: {student_email: {student_name: str, feedbacks: {course: {q1, q2, q3, q4, q5, remarks}}}}
    students_feedback = {}
    courses = set()
    
    try:
        if os.path.exists(csv_path):
            with open(csv_path, newline='', encoding='utf-8') as fh:
                reader = _csv.DictReader(fh)
                for row in reader:
                    email = row.get('email', '').strip()
                    name = row.get('full_name', '').strip()
                    course = row.get('course', '').strip()
                    
                    if not email or not course:
                        continue
                    
                    courses.add(course)
                    
                    if email not in students_feedback:
                        students_feedback[email] = {
                            'name': name,
                            'email': email,
                            'feedbacks': {}
                        }
                    
                    students_feedback[email]['feedbacks'][course] = {
                        'q1': row.get('q1', ''),
                        'q2': row.get('q2', ''),
                        'q3': row.get('q3', ''),
                        'q4': row.get('q4', ''),
                        'q5': row.get('q5', ''),
                        'remarks': row.get('remarks', '')
                    }
        else:
            # Fallback to DB if CSV is missing/empty
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT f.*, u.full_name, u.email 
                FROM feedbacks f 
                JOIN users u ON f.user_id = u.id
            ''')
            rows = cursor.fetchall()
            conn.close()
            
            for row in rows:
                email = row['email']
                name = row['full_name']
                course = row['course']
                
                courses.add(course)
                if email not in students_feedback:
                    students_feedback[email] = {
                        'name': name,
                        'email': email,
                        'feedbacks': {}
                    }
                students_feedback[email]['feedbacks'][course] = {
                    'q1': row['q1'],
                    'q2': row['q2'],
                    'q3': row['q3'],
                    'q4': row['q4'],
                    'q5': row['q5'],
                    'remarks': row['remarks']
                }

    except Exception as e:
        print(f"Error reading feedback: {e}")
    
    # Convert to list and sort by student name
    students_list = sorted(students_feedback.values(), key=lambda x: x['name'].lower())
    courses_list = sorted(list(courses))
    
    return render_template('admin_feedbacks.html', user=current_user, students=students_list, courses=courses_list)


# Study Materials routes

def get_courses_from_attendance():
    """Get course list from attendance.csv header"""
    try:
        if not os.path.exists(app.config['ATTENDANCE_CSV']):
            print("Attendance CSV not found.")
            return []
            
        with open(app.config['ATTENDANCE_CSV'], 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            # Skip first row (title)
            try:
                next(reader)
                # Get header row with subjects
                header = next(reader)
            except StopIteration:
                return []
                
            # Extract course codes starting from column 8 (index 7)
            courses = []
            if len(header) > 7:
                for i, col in enumerate(header[7:], 7):
                    if col and col.strip() not in ['Mobile Number', 'Attendance %', 'Attendance updated up to No. of Sessions']:
                        code = col.strip()
                        # Map course codes to full names
                        course_names = {
                            'ECOM': 'Econometrics',
                            'CSI': 'Contemporary Social Issues',
                            'LAW': 'Law',
                            'LP': 'Linear Programming',
                            'MVS': 'Multivariate Statistics',
                            'AETH': 'Applied Ethics',
                            'WD': 'Web Development',
                            'LSF-II': 'French II',
                            'LSS-II': 'Spanish II'
                        }
                        full_name = course_names.get(code, code)
                        courses.append({'code': code, 'name': full_name})
            return courses
    except Exception as e:
        print(f"Error reading courses: {e}")
        return []

@app.route('/study-materials')
@login_required
def study_materials():
    try:
        # Start from attendance-derived courses (enrolled courses shown to students)
        courses = get_courses_from_attendance()
        if courses is None:
            courses = []

        # Also include any course codes that professors have uploaded materials for
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT course_code, course_name FROM study_materials WHERE course_code IS NOT NULL AND TRIM(course_code) != ''")
            rows = cursor.fetchall()
            conn.close()

            existing_codes = {c.get('code').upper() for c in courses if isinstance(c, dict) and 'code' in c}
            for r in rows:
                code = (r['course_code'] or '').strip()
                name = (r['course_name'] or '').strip()
                if not code:
                    continue
                if code.upper() not in existing_codes:
                    courses.append({'code': code, 'name': name or code})
                    existing_codes.add(code.upper())
        except Exception as e:
            print(f"Error fetching study materials from DB: {e}")
            # if DB read fails, fall back to attendance-only list
            pass
        return render_template('study_materials.html', user=current_user, courses=courses)
    except Exception as e:
        print(f"CRITICAL Error in study_materials route: {e}")
        # Return a valid page even if empty
        return render_template('study_materials.html', user=current_user, courses=[], error=f"Unable to load courses: {str(e)}")

@app.route('/study-materials/<course_code>')
@login_required
def course_materials(course_code):
    """Display all study materials for a specific course"""
    try:
        print(f"=== Loading materials for course: {course_code} ===")
        
        # Get sorting parameter
        sort_by = request.args.get('sort', 'date_desc')
        
        # Connect to database
        conn = get_db()
        cursor = conn.cursor()
        
        # Build query with proper sorting
        base_query = '''
            SELECT 
                sm.id,
                sm.course_code,
                sm.course_name,
                sm.title,
                sm.description,
                sm.file_path,
                sm.created_at,
                u.full_name as uploader_name
            FROM study_materials sm
            LEFT JOIN users u ON sm.uploaded_by = u.id
            WHERE UPPER(TRIM(sm.course_code)) = UPPER(TRIM(%s))
        '''
        
        # Add sorting
        if sort_by == 'date_asc':
            base_query += ' ORDER BY sm.created_at ASC'
        elif sort_by == 'date_desc':
            base_query += ' ORDER BY sm.created_at DESC'
        elif sort_by == 'name_asc':
            base_query += ' ORDER BY sm.title ASC'
        elif sort_by == 'name_desc':
            base_query += ' ORDER BY sm.title DESC'
        else:
            base_query += ' ORDER BY sm.created_at DESC'
        
        # Execute query
        cursor.execute(base_query, (course_code,))
        materials = cursor.fetchall()
        conn.close()
        
        print(f"Found {len(materials)} materials for {course_code}")
        
        # Log materials for debugging
        for mat in materials:
            print(f"  - {mat['title']}: {mat['file_path']}")
        
        # Determine course name
        course_name = course_code
        
        # Try to get course name from attendance file
        try:
            courses = get_courses_from_attendance()
            if courses:
                for course in courses:
                    if isinstance(course, dict) and course.get('code', '').upper() == course_code.upper():
                        course_name = course.get('name', course_code)
                        break
        except Exception as e:
            print(f"Warning: Could not get courses from attendance: {e}")
        
        # If not found, try to get from database
        if course_name == course_code and materials:
            try:
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT DISTINCT course_name FROM study_materials WHERE UPPER(TRIM(course_code)) = UPPER(TRIM(%s)) LIMIT 1",
                    (course_code,)
                )
                row = cursor.fetchone()
                conn.close()
                if row and row['course_name']:
                    course_name = row['course_name']
            except Exception as e:
                print(f"Warning: Could not get course name from DB: {e}")
        
        print(f"Course name resolved to: {course_name}")
        
        # Render template with materials
        return render_template(
            'course_materials.html',
            user=current_user,
            materials=materials,
            course_code=course_code,
            course_name=course_name,
            sort_by=sort_by
        )
        
    except Exception as e:
        print(f"=== CRITICAL ERROR in course_materials route ===")
        print(f"Course code: {course_code}")
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        print(f"=== END ERROR ===")
        return render_template(
            'course_materials.html',
            user=current_user,
            materials=[],
            course_code=course_code,
            course_name=course_code,
            error=f"Error loading materials: {str(e)}"
        )
        
        flash(f'Error loading materials: {str(e)}', 'error')
        return redirect(url_for('study_materials'))

@app.route('/admin/study-materials')
@login_required
@admin_required
def admin_study_materials():
    courses = get_courses_from_attendance()
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''SELECT sm.*, u.full_name as uploader_name 
                      FROM study_materials sm 
                      LEFT JOIN users u ON sm.uploaded_by = u.id 
                      ORDER BY sm.created_at DESC''')
    materials = cursor.fetchall()
    conn.close()
    
    return render_template('admin_study_materials.html', user=current_user, 
                         courses=courses, materials=materials)

@app.route('/admin/upload-material', methods=['POST'])
@login_required
@admin_required
def upload_material():
    course_code = request.form.get('course_code')
    course_name = request.form.get('course_name')
    title = request.form.get('title')
    description = request.form.get('description')
    file_url = request.form.get('file_url')
    
    if not all([course_code, course_name, title]):
        flash('Please fill all required fields', 'error')
        return redirect(url_for('admin_study_materials'))
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO study_materials 
                      (course_code, course_name, title, description, file_path, uploaded_by)
                      VALUES (%s, %s, %s, %s, %s, %s)''',
                   (course_code, course_name, title, description, file_url, current_user.id))
    conn.commit()
    conn.close()
    
    flash('Material uploaded successfully', 'success')
    return redirect(url_for('admin_study_materials'))

@app.route('/professor/upload-material', methods=['GET', 'POST'])
@login_required
@professor_required
def professor_upload_material():
    if request.method == 'POST':
        try:
            course_code = request.form.get('course_code')
            course_name = request.form.get('course_name')
            title = request.form.get('title')
            description = request.form.get('description')
            file_url = request.form.get('file_url')
            
            if not all([course_code, course_name, title]):
                flash('Please fill all required fields', 'error')
                return redirect(url_for('professor_upload_material'))
            
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO study_materials 
                              (course_code, course_name, title, description, file_path, uploaded_by)
                              VALUES (%s, %s, %s, %s, %s, %s)''',
                           (course_code, course_name, title, description, file_url, current_user.id))
            conn.commit()
            conn.close()
            
            flash('Material uploaded successfully', 'success')
            return redirect(url_for('professor_upload_material'))
        except Exception as e:
            print(f"Error uploading material: {e}")
            import traceback
            traceback.print_exc()
            flash(f'Error uploading material: {str(e)}', 'error')
            return redirect(url_for('professor_upload_material'))
    
    # GET request: show upload form with professor's courses
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT DISTINCT course_code, course_name FROM study_materials WHERE uploaded_by = %s ORDER BY course_name', 
                       (current_user.id,))
        course_rows = cursor.fetchall()
        conn.close()
        
        # Get unique courses from materials
        courses = []
        seen = set()
        for material in course_rows:
            key = (material['course_code'], material['course_name'])
            if key not in seen:
                courses.append(key)
                seen.add(key)
        
        # Add hardcoded courses from courses.csv mapping
        default_courses = [
            ('WD', 'Web Development'),
            ('LSS-II', 'Language Skills Spanish II'),
            ('ECOM', 'Econometrics'),
            ('CSI', 'Contemporary Social Issues'),
            ('AETH', 'Applied Ethics'),
            ('LAW', 'Law'),
            ('LP', 'Linear Programming'),
            ('MVS', 'Multivariate Statistics'),
            ('LSF-II', 'Language Skills French II'),
        ]
        
        # Combine and deduplicate
        for course in default_courses:
            if course not in courses:
                courses.append(course)
        
        courses.sort(key=lambda x: x[1])  # Sort by course name
        
        # Also fetch the professor's uploaded materials (for listing and potential delete)
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM study_materials WHERE uploaded_by = %s ORDER BY created_at DESC', (current_user.id,))
        materials = cursor.fetchall()
        conn.close()

        return render_template('professor_study_materials.html', user=current_user, courses=courses, materials=materials)
    except Exception as e:
        print(f"Error loading professor materials page: {e}")
        import traceback
        traceback.print_exc()
        flash(f'Error loading study materials: {str(e)}', 'error')
        return render_template('professor_study_materials.html', user=current_user, courses=[], materials=[])

@app.route('/admin/delete-material/<int:material_id>')
@login_required
@admin_required
def delete_material(material_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM study_materials WHERE id = %s', (material_id,))
    conn.commit()
    conn.close()
    
    flash('Material deleted successfully', 'success')
    return redirect(url_for('admin_study_materials'))


@app.route('/professor/delete-material/<int:material_id>', methods=['POST'])
@login_required
@professor_required
def professor_delete_material(material_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT uploaded_by FROM study_materials WHERE id = %s', (material_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        flash('Material not found', 'error')
        return redirect(url_for('professor_upload_material'))

    if row['uploaded_by'] != current_user.id:
        conn.close()
        flash('You are not allowed to delete this material', 'error')
        return redirect(url_for('professor_upload_material'))

    cursor.execute('DELETE FROM study_materials WHERE id = %s AND uploaded_by = %s', (material_id, current_user.id))
    conn.commit()
    conn.close()
    flash('Material deleted successfully', 'success')
    return redirect(url_for('professor_upload_material'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
