import os
import io
import uuid
import bcrypt
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
import boto3
from botocore.client import Config
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import stripe
from datetime import datetime, timedelta, timezone
import re
import logging
from logging.handlers import RotatingFileHandler
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import smtplib
from email.message import EmailMessage
import threading

load_dotenv()

app = Flask(__name__)

# 1. SECRET_KEY Enforcement
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    raise RuntimeError("CRITICAL: SECRET_KEY environment variable is missing.")

# 3. Session Management (24 hours)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['MAX_CONTENT_LENGTH'] = 15 * 1024 * 1024 

# 2. CSRF Protection
csrf = CSRFProtect(app)

# 4. Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per minute"],
    storage_uri="memory://"
)

# 12. Logging Infrastructure (Updated for Dragon HMS)
logger = logging.getLogger('dragon_hms')
logger.setLevel(logging.INFO)
log_handler = RotatingFileHandler('dragon_hms.log', maxBytes=10000000, backupCount=5)
log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(log_handler)

# 8. Fernet Key Safety
FERNET_KEY = os.environ.get('FERNET_KEY')
if not FERNET_KEY:
    raise RuntimeError("CRITICAL: FERNET_KEY environment variable is missing.")
fernet = Fernet(FERNET_KEY.encode())

# 9. Database Connection Pooling
DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    raise RuntimeError("CRITICAL: DATABASE_URL missing.")
try:
    db_pool = psycopg2.pool.SimpleConnectionPool(1, 10, DATABASE_URL)
    if db_pool:
        logger.info("Database connection pool created successfully.")
except Exception as e:
    logger.error(f"Failed to create DB pool: {e}")
    raise

# Stripe & MinIO Configuration
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')
SESSION_PRICES = {15: 15000} # Initial Consultation ($150)

s3_client = boto3.client('s3',
    endpoint_url=os.environ.get('MINIO_ENDPOINT'),
    aws_access_key_id=os.environ.get('MINIO_ACCESS_KEY'),
    aws_secret_access_key=os.environ.get('MINIO_SECRET_KEY'),
    config=Config(signature_version='s3v4')
)
# Updated Default Bucket Name
MINIO_BUCKET = os.environ.get('MINIO_BUCKET_NAME', 'dragon-hms-resources')

DAY_MAP = {
    'Monday': 'Mon', 'Tuesday': 'Tue', 'Wednesday': 'Wed',
    'Thursday': 'Thu', 'Friday': 'Fri', 'Saturday': 'Sat', 'Sunday': 'Sun',
    'Mon': 'Mon', 'Tue': 'Tue', 'Wed': 'Wed', 'Thu': 'Thu', 'Fri': 'Fri', 'Sat': 'Sat', 'Sun': 'Sun'
}

ALLOWED_MIME_TYPES = {
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'image/png', 'image/jpeg', 'image/jpg',
    'video/mp4', 'video/webm'
}

# ==========================================
# EMAIL CONFIGURATION & THREADING
# ==========================================
MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', MAIL_USERNAME)

def send_email_async(to_email, subject, body):
    if not MAIL_USERNAME or not MAIL_PASSWORD:
        logger.warning("Email credentials missing. Email not sent.")
        return

    def send():
        try:
            msg = EmailMessage()
            msg['Subject'] = subject
            msg['From'] = MAIL_DEFAULT_SENDER
            msg['To'] = to_email
            msg.set_content(body)

            with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
                server.starttls()
                server.login(MAIL_USERNAME, MAIL_PASSWORD)
                server.send_message(msg)
            logger.info(f"Email sent successfully to {to_email}")
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {e}")

    # Process in the background so the website doesn't freeze
    thread = threading.Thread(target=send)
    thread.start()

# ==========================================
# MIDDLEWARE & HELPERS
# ==========================================
@app.before_request
def enforce_https_and_activity():
    if os.environ.get('FLASK_ENV') == 'production':
        if not request.is_secure and request.headers.get('X-Forwarded-Proto', 'http') != 'https':
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)
            
    if 'user_id' in session:
        conn = None
        try:
            conn = db_pool.getconn()
            cur = conn.cursor()
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_active TIMESTAMP WITH TIME ZONE")
            cur.execute("UPDATE users SET last_active = %s WHERE id = %s", (datetime.now(timezone.utc), session['user_id']))
            conn.commit()
            cur.close()
        except Exception:
            if conn: conn.rollback()
        finally:
            if conn: db_pool.putconn(conn)

@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Added cdn.jsdelivr.net to script-src to allow Chart.js to load
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; frame-src 'self' https://js.stripe.com;"
    if os.environ.get('FLASK_ENV') == 'production':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

def is_ajax():
    return request.headers.get('Accept') == 'application/json' or request.is_json

def json_response(status, message, data=None, status_code=200):
    response = {'status': status, 'message': message}
    if data:
        response['data'] = data
    return jsonify(response), status_code

def is_strong_password(password):
    if len(password) < 12: return False
    if not re.search(r"[A-Z]", password): return False
    if not re.search(r"[a-z]", password): return False
    if not re.search(r"[0-9]", password): return False
    return True

def log_action(user_id, action):
    conn = None
    try:
        conn = db_pool.getconn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO audit_log (user_id, action, ip_address, created_at) VALUES (%s, %s, %s, %s)",
            (user_id, action, request.remote_addr, datetime.now(timezone.utc))
        )
        conn.commit()
        cur.close()
    except Exception as e:
        logger.error(f"Audit log failed: {e}")
    finally:
        if conn: db_pool.putconn(conn)

def get_available_slots(days_ahead=14, duration_minutes=30):
    conn = None
    try:
        conn = db_pool.getconn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT day_of_week, start_time, end_time FROM availability")
        avail_rows = cur.fetchall()
        cur.execute("SELECT start_time, end_time FROM appointments WHERE status IN ('confirmed', 'pending')")
        existing_appts = cur.fetchall()
        cur.close()
    except Exception as e:
        logger.error(f"Database error in get_available_slots: {e}")
        return []
    finally:
        if conn: db_pool.putconn(conn)
        
    available_slots = []
    now = datetime.now() 
    slot_step = timedelta(minutes=15)
    required_duration = timedelta(minutes=duration_minutes)
    
    avail_by_day = {}
    for row in avail_rows:
        raw_day = row['day_of_week'].strip().capitalize()
        mapped_day = DAY_MAP.get(raw_day, raw_day)
        if mapped_day not in avail_by_day:
            avail_by_day[mapped_day] = []
        avail_by_day[mapped_day].append(row)
        
    for day_offset in range(days_ahead):
        current_date = now.date() + timedelta(days=day_offset)
        day_short = current_date.strftime('%a')
        
        if day_short in avail_by_day:
            for block in avail_by_day[day_short]:
                start_t = datetime.strptime(str(block['start_time']), '%H:%M:%S').time() if isinstance(block['start_time'], str) else block['start_time']
                end_t = datetime.strptime(str(block['end_time']), '%H:%M:%S').time() if isinstance(block['end_time'], str) else block['end_time']
                
                start_dt = datetime.combine(current_date, start_t)
                end_dt = datetime.combine(current_date, end_t)
                
                slot_start = start_dt
                while slot_start + required_duration <= end_dt:
                    slot_end = slot_start + required_duration
                    
                    if slot_start > now:
                        collision = False
                        for appt in existing_appts:
                            if appt['end_time'] and appt['start_time']:
                                appt_start = appt['start_time'].replace(tzinfo=None)
                                
                                # ENFORCE ONE-PER-HOUR RULE:
                                # Expand the booked appointment to cover the entire clock hour
                                blocked_hour_start = appt_start.replace(minute=0, second=0, microsecond=0)
                                blocked_hour_end = blocked_hour_start + timedelta(hours=1)
                                
                                # Check if the current 15-minute slot falls inside this blocked hour
                                if (slot_start < blocked_hour_end) and (slot_end > blocked_hour_start):
                                    collision = True
                                    break
                        
                        if not collision:
                            available_slots.append({
                                'value': slot_start.strftime('%Y-%m-%d %H:%M:%S'),
                                'label': slot_start.strftime('%a, %b %d @ %I:%M %p') + ' - ' + slot_end.strftime('%I:%M %p')
                            })
                    
                    slot_start += slot_step
                    
    return available_slots

# ==========================================
# ROUTES
# ==========================================
@app.route('/health')
@limiter.exempt
def health():
    conn = None
    try:
        conn = db_pool.getconn()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        return json_response('healthy', 'Database connected')
    except Exception as e:
        logger.critical(f"Health check failed: {e}")
        return json_response('unhealthy', 'Database disconnected', status_code=500)
    finally:
        if conn: db_pool.putconn(conn)

@app.route('/ready')
@limiter.exempt
def ready():
    return json_response('ready', 'Application is ready')

@app.route('/')
def home():
    conn = None
    agent = None
    try:
        conn = db_pool.getconn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM agent_profile LIMIT 1")
        agent = cur.fetchone()
        cur.close()
    except Exception as e:
        logger.error(f"Home route error: {e}")
    finally:
        if conn: db_pool.putconn(conn)
    return render_template('index.html', agent=agent)

@app.route('/contact', methods=['POST'])
@limiter.limit("5 per minute")
def contact():
    name = request.form.get('name')
    email = request.form.get('email')
    message = request.form.get('message')
    
    conn = None
    try:
        conn = db_pool.getconn()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS inquiries (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255), email VARCHAR(255), message TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute(
            "INSERT INTO inquiries (name, email, message, created_at) VALUES (%s, %s, %s, %s)",
            (name, email, message, datetime.now(timezone.utc))
        )
        conn.commit()
        cur.close()
    except Exception as e:
        logger.error(f"Contact form error: {e}")
        flash("An error occurred. Please try again later.", "danger")
        return redirect(url_for('home'))
    finally:
        if conn: db_pool.putconn(conn)
    
    # Notify Admin
    admin_body = f"New Inquiry from {name} ({email}):\n\n{message}"
    send_email_async(MAIL_DEFAULT_SENDER, f"NEW LEAD: {name}", admin_body)
    
    # Auto-reply to User
    user_body = f"Hi {name},\n\nWe received your message and will be in touch shortly.\n\nYour Message:\n{message}"
    send_email_async(email, "We received your inquiry", user_body)

    flash("Inquiry sent successfully. The Dragon HMS team will be in touch shortly.", "success")
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    # Pre-fill email if they were redirected here from a successful Stripe checkout
    email_prefill = request.args.get('email', '')
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not is_strong_password(password):
            flash("Password must be at least 12 characters and include an uppercase letter, a lowercase letter, and a number.", "danger")
            return render_template('register.html', email=email)

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        conn = None
        try:
            conn = db_pool.getconn()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT COUNT(*) as count FROM users")
            is_first_user = cur.fetchone()['count'] == 0
            role = 'agent' if is_first_user else 'client'
            
            try:
                cur.execute(
                    "INSERT INTO users (email, password_hash, role) VALUES (%s, %s, %s) RETURNING id",
                    (email, hashed_pw, role)
                )
                user_id = cur.fetchone()['id']
                
                # LINK-UP: Retroactively assign any pending guest bookings to this new account
                cur.execute(
                    "UPDATE appointments SET client_id = %s WHERE guest_email = %s AND client_id IS NULL", 
                    (user_id, email)
                )
                
                conn.commit()
                log_action(user_id, "user_registered")
                logger.info(f"New user registered: {email}")
                
                welcome_body = f"Welcome to The Dragon HMS!\n\nYour account for {email} has been securely created. You can now log into your portal."
                send_email_async(email, "Welcome to The Dragon HMS", welcome_body)
                
                flash("Account created! Log in below to access your client dashboard.", "success")
                return redirect(url_for('login'))
            except psycopg2.IntegrityError:
                conn.rollback()
                flash("Email already registered.", "danger")
                return render_template('register.html', email=email) 
            finally:
                cur.close()
        except Exception as e:
            logger.error(f"Registration error: {e}")
            flash("Registration failed.", "danger")
            return render_template('register.html', email=email)
        finally:
            if conn: db_pool.putconn(conn)
            
    return render_template('register.html', email=email_prefill)

@app.route('/avatar/<int:user_id>')
def get_avatar(user_id):
    if 'user_id' not in session: 
        return redirect(url_for('login'))
        
    conn = None
    try:
        conn = db_pool.getconn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT selfie_path FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        cur.close()
        
        if user and user['selfie_path']:
            file_obj = s3_client.get_object(Bucket=MINIO_BUCKET, Key=user['selfie_path'])
            file_data = io.BytesIO(file_obj['Body'].read())
            return send_file(file_data, mimetype='image/jpeg')
    except Exception as e:
        logger.error(f"Avatar fetch error: {e}")
    finally:
        if conn: db_pool.putconn(conn)
        
    return "Avatar not found", 404

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        conn = None
        user = None
        try:
            conn = db_pool.getconn()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT id, password_hash, role FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
            cur.close()
        except Exception as e:
            logger.error(f"Login error: {e}")
        finally:
            if conn: db_pool.putconn(conn)
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            session.clear()
            session.permanent = True
            session['user_id'] = user['id']
            session['role'] = user['role']
            log_action(user['id'], "user_logged_in")
            logger.info(f"User logged in successfully (ID: {user['id']})")
            return redirect(url_for('dashboard'))
        else:
            logger.warning(f"Failed login attempt for email: {email}")
            flash("Invalid email or password.", "danger")
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_action(session['user_id'], "user_logged_out")
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('login'))
        
    conn = None
    try:
        conn = db_pool.getconn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        user_role = session.get('role', 'client')
        
        cur.execute("SELECT * FROM availability ORDER BY day_of_week, start_time")
        availability = cur.fetchall()
        
        if user_role == 'agent':
            cur.execute("SELECT id, email FROM users WHERE role = 'client'")
            clients = cur.fetchall()
            cur.execute("""
                SELECT a.*, u.email as client_email FROM appointments a
                JOIN users u ON a.client_id = u.id
                WHERE a.status != 'pending_payment' ORDER BY a.start_time ASC
            """)
            appointments = cur.fetchall()
            cur.execute("""
                SELECT d.*, u.email as uploader_email, c.email as client_email FROM documents d
                LEFT JOIN users u ON d.uploader_id = u.id
                LEFT JOIN users c ON d.client_id = c.id
                ORDER BY d.uploaded_at DESC
            """)
            documents = cur.fetchall()
            cur.execute("SELECT * FROM inquiries ORDER BY created_at DESC")
            inquiries = cur.fetchall()
        else:
            clients, inquiries = [], []
            cur.execute("SELECT * FROM appointments WHERE client_id = %s AND status != 'pending_payment' ORDER BY start_time ASC", (session['user_id'],))
            appointments = cur.fetchall()
            cur.execute("""
                SELECT d.*, u.email as uploader_email FROM documents d
                LEFT JOIN users u ON d.uploader_id = u.id
                WHERE d.client_id = %s ORDER BY d.uploaded_at DESC
            """, (session['user_id'],))
            documents = cur.fetchall()
            
        cur.close()
    except Exception as e:
        logger.error(f"Dashboard load error: {e}")
        flash("An error occurred loading the dashboard.", "danger")
        return redirect(url_for('home'))
    finally:
        if conn: db_pool.putconn(conn)
    
    return render_template('dashboard.html', user_role=user_role, availability=availability, clients=clients, appointments=appointments, documents=documents, inquiries=inquiries, available_slots=[])

@app.route('/api/available-slots')
def api_available_slots():
    duration = int(request.args.get('duration', 30))
    flat_slots = get_available_slots(days_ahead=14, duration_minutes=duration)
    
    grouped_slots = {}
    for slot in flat_slots:
        date_str = slot['value'].split(' ')[0]
        if date_str not in grouped_slots:
            grouped_slots[date_str] = []
        grouped_slots[date_str].append(slot)
        
    return json_response('success', 'Slots retrieved', data={'slots': grouped_slots})

@app.route('/api/my-appointments')
def my_appointments():
    if 'user_id' not in session:
        return json_response('error', 'Unauthorized', status_code=401)
        
    conn = None
    formatted_appts = []
    try:
        conn = db_pool.getconn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        user_role = session.get('role', 'client')
        
        if user_role == 'agent':
            cur.execute("""
                SELECT a.*, u.email as client_email 
                FROM appointments a
                JOIN users u ON a.client_id = u.id
                WHERE a.status != 'pending_payment'
                ORDER BY a.start_time ASC
            """)
        else:
            cur.execute("""
                SELECT * FROM appointments 
                WHERE client_id = %s AND status != 'pending_payment' 
                ORDER BY start_time ASC
            """, (session['user_id'],))
            
        appointments = cur.fetchall()
        cur.close()
        
        for appt in appointments:
            start_str = appt['start_time'].strftime('%b %d, %Y @ %I:%M %p') if appt.get('start_time') else 'Pending'
            formatted_appts.append({
                'id': appt['id'],
                'start_time': start_str,
                'session_type': appt.get('session_type', 'Regular Session (30m)'),
                'client_email': appt.get('client_email', ''),
                'status': appt.get('status', 'pending')
            })
    except Exception as e:
        logger.error(f"Appointments API error: {e}")
        return json_response('error', 'Database error', status_code=500)
    finally:
        if conn: db_pool.putconn(conn)
        
    return json_response('success', 'Appointments retrieved', data={'appointments': formatted_appts})

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return json_response('error', 'Unauthorized', status_code=401) if is_ajax() else redirect(url_for('login'))
        
    file = request.files.get('file')
    if not file or file.filename == '':
        return json_response('error', 'No file selected', status_code=400) if is_ajax() else redirect(url_for('dashboard'))
        
    if file.mimetype not in ALLOWED_MIME_TYPES:
        logger.warning(f"Rejected upload attempt. Invalid MIME type: {file.mimetype}")
        if is_ajax():
            return json_response('error', 'Invalid file type. Only PDF, DOCX, PNG, JPG allowed.', status_code=400)
        flash('Invalid file type.', 'danger')
        return redirect(url_for('dashboard'))
        
    filename = secure_filename(file.filename)
    object_key = f"{uuid.uuid4()}_{filename}"
    
    client_id = request.form.get('client_id') if session.get('role') == 'agent' else session['user_id']
    if session.get('role') == 'agent' and not client_id:
        return json_response('error', 'Must assign file to a client', status_code=400) if is_ajax() else redirect(url_for('dashboard'))
        
    conn = None
    try:
        s3_client.upload_fileobj(file, MINIO_BUCKET, object_key)
        
        conn = db_pool.getconn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            "INSERT INTO documents (uploader_id, client_id, filename, storage_path, uploaded_at) VALUES (%s, %s, %s, %s, %s) RETURNING id, uploaded_at",
            (session['user_id'], client_id, filename, object_key, datetime.now(timezone.utc))
        )
        new_doc = cur.fetchone()
        conn.commit()
        cur.close()
        
        log_action(session['user_id'], f"uploaded_document_{object_key}")
        logger.info(f"File uploaded to vault: {filename}")
        
        uploader_label = "Admin" if session.get('role') == 'agent' else "Client"
        
        if is_ajax():
            return json_response('success', 'Document securely uploaded to vault!', data={
                'doc': {
                    'id': new_doc['id'],
                    'filename': filename,
                    'uploaded_by': uploader_label,
                    'uploaded_at': new_doc['uploaded_at'].strftime('%b %d')
                }
            })
    except Exception as e:
        logger.error(f"S3 Upload Error: {e}")
        if is_ajax():
            return json_response('error', 'Upload failed', status_code=500)
        flash("Upload failed.", "danger")
    finally:
        if conn: db_pool.putconn(conn)
        
    return redirect(url_for('dashboard'))

@app.route('/download/<int:doc_id>')
def download_file(doc_id):
    if 'user_id' not in session: return redirect(url_for('login'))
        
    conn = None
    try:
        conn = db_pool.getconn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT filename, storage_path, client_id FROM documents WHERE id = %s", (doc_id,))
        document = cur.fetchone()
        cur.close()
    except Exception as e:
        logger.error(f"DB Error on download: {e}")
        return redirect(url_for('dashboard'))
    finally:
        if conn: db_pool.putconn(conn)
    
    if not document:
        flash("Document not found.", "danger")
        return redirect(url_for('dashboard'))
        
    if session.get('role') != 'agent' and session['user_id'] != document['client_id']:
        log_action(session['user_id'], f"unauthorized_download_attempt_{doc_id}")
        flash("Unauthorized access.", "danger")
        return redirect(url_for('dashboard'))
        
    try:
        file_obj = s3_client.get_object(Bucket=MINIO_BUCKET, Key=document['storage_path'])
        file_data = io.BytesIO(file_obj['Body'].read())
        log_action(session['user_id'], f"downloaded_document_{doc_id}")
        return send_file(file_data, download_name=document['filename'], as_attachment=True)
    except Exception as e:
        logger.error(f"S3 Download Error: {e}")
        flash("Error retrieving document from vault.", "danger")
        return redirect(url_for('dashboard'))

@app.route('/preview/<int:doc_id>')
def preview_file(doc_id):
    if 'user_id' not in session: return redirect(url_for('login'))
        
    conn = None
    try:
        conn = db_pool.getconn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT filename, storage_path, client_id FROM documents WHERE id = %s", (doc_id,))
        document = cur.fetchone()
        cur.close()
    except Exception:
        return redirect(url_for('dashboard'))
    finally:
        if conn: db_pool.putconn(conn)
    
    if not document:
        flash("Document not found.", "danger")
        return redirect(url_for('dashboard'))
        
    if session.get('role') != 'agent' and session['user_id'] != document['client_id']:
        log_action(session['user_id'], f"unauthorized_preview_attempt_{doc_id}")
        flash("Unauthorized access.", "danger")
        return redirect(url_for('dashboard'))
        
    try:
        file_obj = s3_client.get_object(Bucket=MINIO_BUCKET, Key=document['storage_path'])
        file_data = io.BytesIO(file_obj['Body'].read())
        log_action(session['user_id'], f"previewed_document_{doc_id}")
        return send_file(file_data, download_name=document['filename'], as_attachment=False)
    except Exception as e:
        logger.error(f"S3 Preview Error: {e}")
        flash("Error retrieving document.", "danger")
        return redirect(url_for('dashboard'))

@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    # Authentication check removed to allow public bookings via index.html

    if not stripe.api_key:
        return json_response('error', 'Payments are currently disabled while we configure our gateway.', status_code=503)
        
    slot = request.form.get('slot_timestamp')
    session_type = request.form.get('session_type', 'Initial Consultation (15m)')
    duration_minutes = int(request.form.get('duration_minutes', 15))
    
    # NEW: Capture guest info and the scoping wizard results
    guest_name = request.form.get('guest_name', 'Guest')
    guest_email = request.form.get('guest_email', '')
    project_scope = request.form.get('project_scope', '')
    
    if not slot or not guest_email:
        return json_response('error', 'Please provide an email and select a session slot.', status_code=400)
        
    client_id = session.get('user_id') # Will naturally be None for public guests
    price_cents = SESSION_PRICES.get(duration_minutes, 15000)
    domain_url = request.host_url.rstrip('/')
    
    try:
        start_dt = datetime.strptime(slot, '%Y-%m-%d %H:%M:%S')
        end_dt = start_dt + timedelta(minutes=duration_minutes)
    except Exception as e:
        return json_response('error', 'Invalid time format.', status_code=400)
    
    conn = None
    try:
        conn = db_pool.getconn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Auto-update database schema to support unauthenticated guest bookings
        try:
            cur.execute("ALTER TABLE appointments ADD COLUMN IF NOT EXISTS guest_name VARCHAR(255)")
            cur.execute("ALTER TABLE appointments ADD COLUMN IF NOT EXISTS guest_email VARCHAR(255)")
            cur.execute("ALTER TABLE appointments ADD COLUMN IF NOT EXISTS project_scope TEXT")
            cur.execute("ALTER TABLE appointments ALTER COLUMN client_id DROP NOT NULL")
            conn.commit()
        except Exception:
            conn.rollback()
        
        cur.execute(
            """INSERT INTO appointments (client_id, guest_name, guest_email, project_scope, start_time, end_time, session_type, status, payment_status) 
               VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending_payment', 'unpaid') RETURNING id""",
            (client_id, guest_name, guest_email, project_scope, start_dt, end_dt, session_type)
        )
        appt_id = cur.fetchone()['id']
        conn.commit()

        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': f"The Dragon HMS - {session_type}",
                        'description': f"Consultation block: {start_dt.strftime('%b %d @ %I:%M %p')}",
                    },
                    'unit_amount': price_cents,
                },
                'quantity': 1,
            }],
            mode='payment',
            # Redirects to register instead of dashboard, passing their email in the URL
            success_url=domain_url + url_for('register') + f'?email={guest_email}&checkout=success',
            cancel_url=domain_url + '/?checkout=canceled',
            client_reference_id=str(appt_id)
        )
        
        cur.execute("UPDATE appointments SET stripe_session_id = %s WHERE id = %s", (checkout_session.id, appt_id))
        conn.commit()
        cur.close()
        
        return json_response('success', 'Checkout created', data={'url': checkout_session.url})
        
    except Exception as e:
        logger.error(f"Stripe Checkout Error: {e}")
        return json_response('error', 'Payment gateway error.', status_code=500)
    finally:
        if conn: db_pool.putconn(conn)

@app.route('/stripe-webhook', methods=['POST'])
@csrf.exempt
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except ValueError as e:
        logger.warning("Stripe webhook error: Invalid payload")
        return json_response('error', 'Invalid payload', status_code=400)
    except stripe.error.SignatureVerificationError as e:
        logger.warning(f"Stripe webhook error: Invalid signature from IP {request.remote_addr}")
        return json_response('error', 'Invalid signature', status_code=400)

    if event['type'] == 'checkout.session.completed':
        session_obj = event['data']['object']
        appt_id = session_obj.client_reference_id
        amount_total = (session_obj.amount_total or 0) / 100.0

        if appt_id:
            conn = None
            try:
                conn = db_pool.getconn()
                cur = conn.cursor()
                cur.execute(
                    """UPDATE appointments 
                       SET status = 'pending', payment_status = 'paid', amount_paid = %s 
                       WHERE id = %s""",
                    (amount_total, appt_id)
                )
                conn.commit()
                cur.close()
                logger.info(f"Payment successful! Appt ID {appt_id} updated to pending.")
            except Exception as e:
                logger.error(f"Webhook database update failed: {e}")
            finally:
                if conn: db_pool.putconn(conn)

    return json_response('success', 'Webhook received')

@app.route('/accept-session/<int:appt_id>', methods=['POST'])
def accept_session(appt_id):
    if session.get('role') != 'agent':
        return json_response('error', 'Unauthorized', status_code=401)
        
    conn = None
    try:
        conn = db_pool.getconn()
        cur = conn.cursor()
        cur.execute("UPDATE appointments SET status = 'confirmed' WHERE id = %s", (appt_id,))
        conn.commit()
        cur.close()
    except Exception as e:
        logger.error(f"Error accepting session: {e}")
        return json_response('error', 'Database error', status_code=500)
    finally:
        if conn: db_pool.putconn(conn)
    
    if is_ajax():
        return json_response('success', 'Session accepted & confirmed!')
    return redirect(url_for('dashboard'))

@app.route('/deny-session/<int:appt_id>', methods=['POST'])
def deny_session(appt_id):
    if session.get('role') != 'agent':
        return json_response('error', 'Unauthorized', status_code=401)
        
    conn = None
    try:
        conn = db_pool.getconn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT stripe_session_id, payment_status FROM appointments WHERE id = %s", (appt_id,))
        appt = cur.fetchone()
        
        if appt and appt['payment_status'] == 'paid' and appt['stripe_session_id']:
            try:
                checkout_session = stripe.checkout.Session.retrieve(appt['stripe_session_id'])
                if checkout_session.payment_intent:
                    stripe.Refund.create(payment_intent=checkout_session.payment_intent)
                    logger.info(f"Refunded appointment {appt_id}")
            except Exception as e:
                logger.error(f"Stripe Refund Error: {e}")
                
        cur.execute("UPDATE appointments SET status = 'denied', payment_status = 'refunded' WHERE id = %s", (appt_id,))
        conn.commit()
        cur.close()
    except Exception as e:
        logger.error(f"Error denying session: {e}")
        return json_response('error', 'Database error', status_code=500)
    finally:
        if conn: db_pool.putconn(conn)
    
    return json_response('success', 'Session denied and client refunded.')

@app.route('/cancel-session/<int:appt_id>', methods=['POST'])
def cancel_session(appt_id):
    if 'user_id' not in session:
        return json_response('error', 'Unauthorized', status_code=401)
        
    conn = None
    try:
        conn = db_pool.getconn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT client_id, stripe_session_id, payment_status FROM appointments WHERE id = %s", (appt_id,))
        appt = cur.fetchone()
        
        if not appt:
            return json_response('error', 'Session not found', status_code=404)
            
        if session.get('role') != 'agent' and appt['client_id'] != session.get('user_id'):
            logger.warning(f"Unauthorized cancel attempt by user {session['user_id']}")
            return json_response('error', 'Unauthorized', status_code=401)
            
        if appt['payment_status'] == 'paid' and appt['stripe_session_id']:
            try:
                checkout_session = stripe.checkout.Session.retrieve(appt['stripe_session_id'])
                if checkout_session.payment_intent:
                    stripe.Refund.create(payment_intent=checkout_session.payment_intent)
                    logger.info(f"Refunded appointment {appt_id}")
            except Exception as e:
                logger.error(f"Stripe Refund Error: {e}")
                
        cur.execute("UPDATE appointments SET status = 'cancelled', payment_status = 'refunded' WHERE id = %s", (appt_id,))
        conn.commit()
        cur.close()
    except Exception as e:
        logger.error(f"Error cancelling session: {e}")
        return json_response('error', 'Database error', status_code=500)
    finally:
        if conn: db_pool.putconn(conn)
    
    return json_response('success', 'Session cancelled and client refunded.')

@app.route('/set-availability', methods=['POST'])
def set_availability():
    if session.get('role') != 'agent':
        return json_response('error', 'Unauthorized', status_code=401)
        
    day = request.form.get('day_of_week')
    start_time = request.form.get('start_time')
    end_time = request.form.get('end_time')
    
    if day and start_time and end_time:
        conn = None
        try:
            conn = db_pool.getconn()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO availability (day_of_week, start_time, end_time) VALUES (%s, %s, %s) RETURNING id",
                (day, start_time, end_time)
            )
            new_id = cur.fetchone()[0]
            conn.commit()
            cur.close()
            
            start_fmt = datetime.strptime(start_time, '%H:%M').strftime('%I:%M %p')
            end_fmt = datetime.strptime(end_time, '%H:%M').strftime('%I:%M %p')
            
            if is_ajax():
                return json_response('success', 'Working availability added!', data={
                    'id': new_id, 'day_of_week': day, 'start_time': start_fmt, 'end_time': end_fmt
                })
        except Exception as e:
            logger.error(f"Error setting availability: {e}")
            if is_ajax(): return json_response('error', 'Failed to add', status_code=500)
        finally:
            if conn: db_pool.putconn(conn)
            
    return redirect(url_for('dashboard'))

@app.route('/delete-availability/<int:avail_id>', methods=['POST'])
def delete_availability(avail_id):
    if session.get('role') != 'agent':
        return json_response('error', 'Unauthorized', status_code=401)
        
    conn = None
    try:
        conn = db_pool.getconn()
        cur = conn.cursor()
        cur.execute("DELETE FROM availability WHERE id = %s", (avail_id,))
        conn.commit()
        cur.close()
        if is_ajax():
            return json_response('success', 'Availability block removed.')
    except Exception as e:
        logger.error(f"Error deleting availability: {e}")
        if is_ajax(): return json_response('error', 'Failed to delete', status_code=500)
    finally:
        if conn: db_pool.putconn(conn)
    return redirect(url_for('dashboard'))

@app.route('/delete-inquiry/<int:inq_id>', methods=['POST'])
def delete_inquiry(inq_id):
    if session.get('role') != 'agent':
        return json_response('error', 'Unauthorized', status_code=401)
    
    conn = None
    try:
        conn = db_pool.getconn()
        cur = conn.cursor()
        cur.execute("DELETE FROM inquiries WHERE id = %s", (inq_id,))
        conn.commit()
        cur.close()
        return json_response('success', 'Inquiry dismissed.')
    except Exception as e:
        logger.error(f"Error deleting inquiry: {e}")
        return json_response('error', 'Failed to dismiss inquiry', status_code=500)
    finally:
        if conn: db_pool.putconn(conn)

@app.route('/feed')
def feed():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = None
    posts = []
    clients = []
    selected_client_id = request.args.get('client_id')
    user_role = session.get('role', 'client')
    
    try:
        conn = db_pool.getconn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Auto-update table to support client-specific feeds
        try:
            cur.execute("ALTER TABLE feed_posts ADD COLUMN IF NOT EXISTS client_id INTEGER REFERENCES users(id)")
            conn.commit()
        except Exception:
            conn.rollback()
            
        if user_role == 'agent':
            cur.execute("SELECT id, email FROM users WHERE role = 'client'")
            clients = cur.fetchall()
            
            if selected_client_id:
                cur.execute("""
                    SELECT f.*, u.email as client_email 
                    FROM feed_posts f
                    LEFT JOIN users u ON f.client_id = u.id
                    WHERE f.client_id = %s
                    ORDER BY f.uploaded_at DESC
                """, (selected_client_id,))
            else:
                cur.execute("""
                    SELECT f.*, u.email as client_email 
                    FROM feed_posts f
                    LEFT JOIN users u ON f.client_id = u.id
                    ORDER BY f.uploaded_at DESC
                """)
            posts = cur.fetchall()
        else:
            cur.execute("SELECT * FROM feed_posts WHERE client_id = %s ORDER BY uploaded_at DESC", (session['user_id'],))
            posts = cur.fetchall()
            
        cur.close()
    except Exception as e:
        logger.error(f"Feed load error: {e}")
    finally:
        if conn: db_pool.putconn(conn)
    
    return render_template('feed.html', posts=posts, user_role=user_role, clients=clients, selected_client_id=selected_client_id)

@app.route('/upload_feed_post', methods=['POST'])
def upload_feed_post():
    if session.get('role') != 'agent':
        return json_response('error', 'Unauthorized', status_code=401)
        
    text_content = request.form.get('text_content', '').strip()
    client_id = request.form.get('client_id')
    media = request.files.get('media')
    
    if not client_id:
        return json_response('error', 'You must assign the post to a client project.', status_code=400)
        
    if not text_content and (not media or media.filename == ''):
        return json_response('error', 'Post must contain text or media', status_code=400)
        
    object_key = None
    media_type = None
    
    if media and media.filename != '':
        if media.mimetype not in ALLOWED_MIME_TYPES or ('image' not in media.mimetype and 'video' not in media.mimetype):
            return json_response('error', 'Invalid media type.', status_code=400)
        
        media_type = 'video' if 'video' in media.mimetype else 'image'
        filename = secure_filename(media.filename)
        object_key = f"feed_{uuid.uuid4()}_{filename}"
    
    conn = None
    try:
        if object_key:
            s3_client.upload_fileobj(media, MINIO_BUCKET, object_key)
            
        conn = db_pool.getconn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            "INSERT INTO feed_posts (uploader_id, client_id, text_content, media_type, storage_path, uploaded_at) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
            (session['user_id'], client_id, text_content, media_type, object_key, datetime.now(timezone.utc))
        )
        new_id = cur.fetchone()['id']
        conn.commit()
        cur.close()
        
        log_action(session['user_id'], f"uploaded_feed_post_{new_id}")
        
        if is_ajax():
            return json_response('success', 'Post published to client timeline!')
    except Exception as e:
        logger.error(f"Feed Upload Error: {e}")
        if is_ajax(): return json_response('error', 'Upload failed', status_code=500)
    finally:
        if conn: db_pool.putconn(conn)
        
    return redirect(url_for('feed'))

@app.route('/feed-media/<int:post_id>')
def feed_media(post_id):
    conn = None
    try:
        conn = db_pool.getconn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT storage_path, media_type FROM feed_posts WHERE id = %s", (post_id,))
        post = cur.fetchone()
        cur.close()
    except Exception as e:
        logger.error(f"Feed media fetch error: {e}")
        return "Database Error", 500
    finally:
        if conn: db_pool.putconn(conn)
    
    if not post or not post['storage_path']:
        return "Media not found in database", 404
        
    try:
        file_obj = s3_client.get_object(Bucket=MINIO_BUCKET, Key=post['storage_path'])
        mime = 'video/mp4' if post['media_type'] == 'video' else 'image/jpeg'
        
        filename = post['storage_path'].split('_')[-1] if '_' in post['storage_path'] else 'media'
        return send_file(io.BytesIO(file_obj['Body'].read()), mimetype=mime, download_name=filename)
        
    except Exception as e:
        logger.warning(f"S3 Media Missing or Error: {e}")
        return "Media file not found in storage", 404

@app.route('/delete-feed-post/<int:post_id>', methods=['POST'])
def delete_feed_post(post_id):
    if session.get('role') != 'agent':
        return json_response('error', 'Unauthorized', status_code=401)
        
    conn = None
    try:
        conn = db_pool.getconn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT storage_path FROM feed_posts WHERE id = %s", (post_id,))
        post = cur.fetchone()
        
        if post:
            if post['storage_path']:
                try:
                    s3_client.delete_object(Bucket=MINIO_BUCKET, Key=post['storage_path'])
                except Exception as e:
                    logger.warning(f"S3 Delete Warning: {e}")
                
            cur.execute("DELETE FROM feed_posts WHERE id = %s", (post_id,))
            conn.commit()
            
        cur.close()
        if is_ajax():
            return json_response('success', 'Post removed.')
    except Exception as e:
        logger.error(f"Feed delete error: {e}")
        if is_ajax(): return json_response('error', 'Failed to delete', status_code=500)
    finally:
        if conn: db_pool.putconn(conn)
        
    return redirect(url_for('feed'))

@app.route('/messages', methods=['GET'])
def messages():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = None
    chat_history = []
    target_id = None
    partner_name = "Secure Chat"
    is_online = False
    clients = []

    try:
        conn = db_pool.getconn()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        try:
            cur.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_read BOOLEAN DEFAULT FALSE")
            conn.commit()
        except Exception:
            conn.rollback()

        if session['role'] == 'agent':
            cur.execute("SELECT id, email FROM users WHERE role = 'client'")
            clients = cur.fetchall()
            
            client_id = request.args.get('client_id')
            if client_id:
                target_id = client_id
                cur.execute("SELECT email, last_active FROM users WHERE id = %s", (client_id,))
                res = cur.fetchone()
                if res:
                    partner_name = res['email']
                    if res['last_active'] and (datetime.now(timezone.utc) - res['last_active']) < timedelta(minutes=5):
                        is_online = True
        else:
            cur.execute("SELECT id, last_active FROM users WHERE role = 'agent' LIMIT 1")
            agent = cur.fetchone()
            if agent:
                target_id = agent['id']
                partner_name = "System Admin"
                if agent['last_active'] and (datetime.now(timezone.utc) - agent['last_active']) < timedelta(minutes=5):
                    is_online = True

        if target_id:
            cur.execute("UPDATE messages SET is_read = TRUE WHERE sender_id = %s AND receiver_id = %s", (target_id, session['user_id']))
            conn.commit()

            cur.execute("""
                SELECT sender_id, encrypted_content, is_read, to_char(created_at, 'Mon DD, YYYY HH:MI AM') as timestamp
                FROM messages
                WHERE (sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s)
                ORDER BY created_at ASC
            """, (session['user_id'], target_id, target_id, session['user_id']))
            
            raw_msgs = cur.fetchall()
            
            for row in raw_msgs:
                try:
                    decrypted_text = fernet.decrypt(row['encrypted_content'].encode()).decode()
                except Exception:
                    decrypted_text = "[Decryption Failed]"
                    
                chat_history.append({
                    'is_mine': row['sender_id'] == session['user_id'],
                    'text': decrypted_text,
                    'timestamp': row['timestamp'],
                    'is_read': row.get('is_read', True)
                })

        cur.close()
    except Exception as e:
        logger.error(f"Messages load error: {e}")
    finally:
        if conn: db_pool.putconn(conn)
    
    return render_template('messages.html', 
                           chat_history=chat_history, 
                           target_id=target_id, 
                           partner_name=partner_name, 
                           is_online=is_online,
                           clients=clients)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return json_response('error', 'Unauthorized', status_code=401)
        
    receiver_id = request.form.get('receiver_id')
    content = request.form.get('content')
    
    if receiver_id and content and fernet:
        encrypted_content = fernet.encrypt(content.encode()).decode()
        conn = None
        try:
            conn = db_pool.getconn()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute(
                "INSERT INTO messages (sender_id, receiver_id, encrypted_content, created_at) VALUES (%s, %s, %s, %s) RETURNING created_at",
                (session['user_id'], receiver_id, encrypted_content, datetime.now(timezone.utc))
            )
            res = cur.fetchone()
            conn.commit()
            cur.close()
            
            formatted_ts = res['created_at'].strftime('%b %d, %Y %I:%M %p') if res else ''
            
            if is_ajax():
                return json_response('success', 'Message sent', data={
                    'text': content,
                    'timestamp': formatted_ts
                })
        except Exception as e:
            logger.error(f"Message send error: {e}")
            if is_ajax(): return json_response('error', 'Failed to send message', status_code=500)
        finally:
            if conn: db_pool.putconn(conn)
            
    return redirect(url_for('messages'))

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=5006, debug=debug_mode)
