from flask import Flask, request, render_template, redirect, url_for, flash, send_file, jsonify, session, abort
import os
import secrets
import qrcode
import json
import socket
import logging
import hashlib
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Custom Modules
import requests
from encryption_utils import EncryptionManager
from email_utils import send_email, send_email_with_qr, send_alert_email
from file_utils import extract_text_content, detect_mime_type, estimate_page_count
from audit_logger import log_audit_event, export_audit_logs_csv, get_logs_for_token
from token_manager import generate_secure_token, hash_token, save_token_metadata, get_token_metadata, is_token_valid, invalidate_token
import security_config

app = Flask(__name__)
# Use a stable key for development to avoid session invalidation on restarts
app.secret_key = os.environ.get('SECRET_KEY', 'default-vulnerable-dev-key-7712')

# PRODUCTION CONFIG
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax', # Required for cross-site links from email
    PERMANENT_SESSION_LIFETIME=timedelta(seconds=security_config.SESSION_LIFETIME),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024 # 16MB
)

# Global Security Headers
talisman = Talisman(app, **security_config.SECURE_HEADERS)

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=security_config.GLOBAL_LIMITS,
    storage_uri="memory://",
)

# CSRF Protection
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# Configurations
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
STATIC_FOLDER = os.path.join(BASE_DIR, 'static')
DATA_FOLDER = os.path.join(BASE_DIR, 'data')
ALERTS_LOG_FILE = os.path.join(BASE_DIR, 'security_alerts.log')

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(STATIC_FOLDER, exist_ok=True)
os.makedirs(DATA_FOLDER, exist_ok=True)

# Constants
MAX_PASSWORD_LENGTH = 64
SESSION_LIFETIME_MINUTES = 30

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

# --- Routes ---

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/encrypt', methods=['GET', 'POST'])
@limiter.limit(security_config.ROUTE_LIMITS['encrypt'])
def encrypt():
    if request.method == 'POST':
        try:
            # 1. Inputs
            file = request.files.get('file')
            password = request.form.get('password')
            sender_email = request.form.get('email')
            receiver_email = request.form.get('receiver_email')
            encryption_methods = request.form.getlist('encryption_methods')
            qr_expiry_minutes = int(request.form.get('qr_expiry_minutes', 10))
            
            # 2. Validation
            if not file or file.filename == '':
                flash('No file selected')
                return redirect(request.url)
            if not password or not sender_email or not receiver_email:
                flash('All fields (Password, Sender Email, Receiver Email) are required.')
                return redirect(request.url)
            if len(password) < 8 or len(password) > MAX_PASSWORD_LENGTH:
                flash(f'Password must be between 8 and {MAX_PASSWORD_LENGTH} characters.')
                return redirect(request.url)
            
            # Default to Fernet if none selected (though UI should enforce)
            if not encryption_methods:
                encryption_methods = ['fernet']

            # 3. Read & Detect
            file_bytes = file.read()
            if not file_bytes:
                flash('Empty file uploaded.')
                return redirect(request.url)
                
            # Detect type for metadata
            ext, mime = detect_mime_type(file_bytes)
            # Use original extension if detection is generic, but trust mime for logic
            orig_ext = os.path.splitext(file.filename)[1].lower() if '.' in file.filename else ''
            final_ext = ext if ext else orig_ext
            
            # 4. Encrypt
            # 4. Encrypt
            try:
                result = EncryptionManager.encrypt_data(file_bytes, password, encryption_methods)
                encrypted_content = result['ciphertext']
                crypto_meta = result['meta']
            except Exception as e:
                flash(f"Encryption failed: {str(e)}")
                return redirect(request.url)
            
            # 5. Save Encrypted File with HASHED token
            raw_token = generate_secure_token()
            token_hash = hash_token(raw_token)
            
            encrypted_filename = f"{token_hash}.enc"
            encrypted_path = os.path.join(STATIC_FOLDER, encrypted_filename)
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_content)
                
            # 6. Generate QR with RAW token
            local_ip = get_local_ip()
            share_url = f"https://{local_ip}:5050/open/{raw_token}"
            
            qr = qrcode.QRCode(version=1, box_size=10, border=4)
            qr.add_data(share_url)
            qr.make(fit=True)
            qr_image = qr.make_image(fill_color="black", back_color="white")
            qr_filename = f"qr_{token_hash}.png"
            qr_path = os.path.join(STATIC_FOLDER, qr_filename)
            qr_image.save(qr_path)
            
            # 7. Metadata Store (JSON)
            expires_at = datetime.now() + timedelta(minutes=qr_expiry_minutes)
            meta = {
                'token_hash': token_hash,
                'sender_email': sender_email,
                'receiver_email': receiver_email,
                'original_filename': secure_filename(file.filename),
                'content_type': mime,
                'extension': final_ext,
                'encryption_methods': encryption_methods,
                'password_check': hashlib.sha256(password.encode()).hexdigest(),
                'created_at': datetime.now().isoformat(),
                'expires_at': expires_at.isoformat(),
                'crypto_evidence': crypto_meta,
                'status': 'active',
                'bound_ip': None,
                'views': 0
            }
            save_token_metadata(token_hash, meta)
            
            # Audit log
            log_audit_event("TOKEN_CREATED", token_hash=token_hash, receiver_email=receiver_email, ip=request.remote_addr, status="SUCCESS")
                
            # 8. Send Emails
            # 8a: To Sender (Confirmation)
            send_email(
                sender_email, 
                "File Secured & Sent", 
                f"Your file has been encrypted and sent to {receiver_email}.\nFile ID: {token_hash}\nExpires: {expires_at}"
            )
            
            # 8b: To Receiver (QR Code)
            send_email_with_qr(
                receiver_email,
                "You have received a Secure File",
                f"A secure file has been shared with you by {sender_email}.\nScan the attached QR code or use the link below to access it.\nPassword is provided separately by the sender.",
                qr_path,
                share_url
            )
            
            flash('File encrypted and sent successfully!')
            return render_template('qr_code.html', 
                                   qr_code=qr_filename, 
                                   file_id=token_hash, 
                                   receiver_email=receiver_email,
                                   expires_at=meta['expires_at'],
                                   sender_email=sender_email)
        except Exception as e:
            flash(f"An error occurred: {str(e)}")
            return redirect(request.url)

    return render_template('encrypt.html')

@app.route('/open/<token>')
@limiter.limit(security_config.ROUTE_LIMITS['open'])
def open_token(token):
    token_hash = hash_token(token)
    valid, msg = is_token_valid(token_hash, client_ip=request.remote_addr)
    
    if not valid:
        log_audit_event("INVALID_TOKEN_ACCESS", token_hash=token_hash, ip=request.remote_addr, status="DENIED", reason=msg)
        return render_template('error.html', message=f"Access Denied: {msg}")
    
    # Store token hash in session and bind to IP if not already
    session['active_token_hash'] = token_hash
    session.permanent = True
    
    # Audit log
    log_audit_event("TOKEN_OPENED", token_hash=token_hash, ip=request.remote_addr, device=str(request.user_agent), status="SUCCESS")
    
    return redirect(url_for('verify_password', file_id=token_hash))

@app.route('/verify-password/<file_id>', methods=['GET', 'POST'])
@limiter.limit(security_config.ROUTE_LIMITS['verify'])
def verify_password(file_id):
    # Security Check: Ensure token from session matches URL
    if session.get('active_token_hash') != file_id:
        log_audit_event("SESSION_MISMATCH", token_hash=file_id, ip=request.remote_addr, status="DENIED", reason="Session token mismatch")
        return render_template('error.html', message="Session Error: Invalid Access attempt.")

    meta = get_token_metadata(file_id)
    if not meta:
        return render_template('error.html', message="File not found or expired.")
    
    # Check Expiry
    if datetime.now() > datetime.fromisoformat(meta['expires_at']):
        # Auto-cleanup could go here
        return render_template('expired.html', file_id=file_id)
        
    if request.method == 'POST':
        password = request.form.get('password')
        
        # Max Attempts per session
        attempts_key = f'attempts_{file_id}'
        session[attempts_key] = session.get(attempts_key, 0) + 1
        
        if session[attempts_key] > 3:
            log_audit_event("BRUTE_FORCE_TRIGGER", token_hash=file_id, ip=request.remote_addr, status="DESTROYED", reason="Max password attempts exceeded")
            handle_destruction(file_id, "Max password attempts exceeded")
            return render_template('error.html', message="File blocked due to too many failed attempts.")

        # Check password against stored hash
        stored_hash = meta.get('password_check')
        if stored_hash and hashlib.sha256(password.encode()).hexdigest() != stored_hash:
            log_audit_event("PASSWORD_FAIL", token_hash=file_id, ip=request.remote_addr, status="FAIL", reason=f"Attempt {session[attempts_key]}")
            flash(f'Incorrect Password (Attempt {session[attempts_key]}/3)')
            return redirect(request.url)
            
        # Success
        session[f'verified_{file_id}'] = True
        session[f'temp_password_{file_id}'] = password
        
        log_audit_event("PASSWORD_SUCCESS", token_hash=file_id, ip=request.remote_addr, status="SUCCESS")
        
        return redirect(url_for('view_file', file_id=file_id))
        
    return render_template('verify_password.html', file_id=file_id)

@app.route('/view/<file_id>', methods=['GET'])
@limiter.limit(security_config.ROUTE_LIMITS['decrypt'])
def view_file(file_id):
    # Security Check: Ensure session matches URL and is verified
    if session.get('active_token_hash') != file_id or not session.get(f'verified_{file_id}'):
        log_audit_event("UNAUTHORIZED_VIEW", token_hash=file_id, ip=request.remote_addr, status="DENIED")
        return redirect(url_for('verify_password', file_id=file_id))
        
    meta = get_token_metadata(file_id)
    if not meta: return render_template('error.html', message="File not found.")
    
    # ONE-TIME VIEW ENFORCEMENT
    if meta.get('views', 0) > 0:
        log_audit_event("REACCESS_ATTEMPT", token_hash=file_id, ip=request.remote_addr, status="DENIED")
        handle_destruction(file_id, "Attempt to re-access one-time valid link")
        return render_template('error.html', message="Link Expired: Secure files can only be viewed once.")

    password = session.get(f'temp_password_{file_id}')
    if not password:
         return redirect(url_for('verify_password', file_id=file_id))

    encrypted_path = os.path.join(STATIC_FOLDER, f"{file_id}.enc")
    if not os.path.exists(encrypted_path):
        return render_template('error.html', message="Encrypted file missing.")
        
    # 3. Decrypt
    try:
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
            
        decrypted_bytes = EncryptionManager.decrypt_data(
            encrypted_data, 
            password, 
            meta.get('encryption_methods', ['fernet'])
        )
        
        # Mark as viewed ONLY if decryption succeeded
        meta['views'] = meta.get('views', 0) + 1
        save_token_metadata(file_id, meta)
        
        # 4. Prepare for View
        ext, mime = detect_mime_type(decrypted_bytes)
        text_content = extract_text_content(decrypted_bytes, meta.get('extension', ''))
        
        preview_url = None
        import base64
        if mime.startswith('image/'):
            b64 = base64.b64encode(decrypted_bytes).decode('ascii')
            preview_url = f"data:{mime};base64,{b64}"
        elif mime == 'application/pdf':
            b64 = base64.b64encode(decrypted_bytes).decode('ascii')
            preview_url = f"data:application/pdf;base64,{b64}"
            
        if not text_content and not preview_url:
            text_content = f"[Binary File] Display not supported.\nHex: {decrypted_bytes[:256].hex()}"
        
        # Smart Idle Logic
        page_count = estimate_page_count(decrypted_bytes, meta.get('extension', ''), text_content)
        disable_idle = page_count > 2.0
        
        log_audit_event("CONTENT_VIEWED", token_hash=file_id, ip=request.remote_addr, status="SUCCESS")
            
        return render_template(
            'view_decrypted.html',
            file_id=file_id,
            temp_file_id=file_id,
            content=text_content,
            preview_url=preview_url,
            mime_type=mime,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            disable_idle=disable_idle
        )
        
    except ValueError as e:
        msg = str(e)
        if "Integrity Check Failed" in msg:
            log_audit_event("TAMPER_DETECTED", token_hash=file_id, ip=request.remote_addr, status="CRITICAL", reason="HMAC Failure")
            handle_destruction(file_id, "TAMPER DETECTED: Integrity Signature Mismatch")
            return render_template('error.html', message="CRITICAL SECURITY ALERT: File integrity check failed.")
        else:
            handle_destruction(file_id, f"Decryption Error: {msg}")
            return render_template('error.html', message="Decryption Error: Data corruption.")
    except Exception as e:
        return render_template('error.html', message=f"System Error: {str(e)}")

@app.route('/delete-file/<file_id>', methods=['POST'])
@csrf.exempt # Exempt from CSRF because it's often called via sendBeacon/unload
def delete_file(file_id):
    data = request.get_json(silent=True) or {}
    reason = data.get('reason', 'Client Trigger (Manual/Close)')
    handle_destruction(file_id, reason)
    return jsonify({'status': 'destroyed'})

@app.route("/alert", methods=["POST"])
@csrf.exempt # Exempt from CSRF for security signal reliability
def alert():
    data = request.get_json(silent=True) or {}
    file_id = data.get('file_id')
    alert_type = data.get('type', 'GENERIC')
    reason = data.get('reason', 'No Reason Provided')
    
    # Log to Audit Log
    log_audit_event(f"CLIENT_ALERT_{alert_type.upper()}", token_hash=file_id, ip=request.remote_addr, status="TRIGGERED", reason=reason)
        
    if alert_type in ['destruction', 'copy', 'screenshot', 'visibility', 'idle', 'camera']:
        handle_destruction(file_id, f"{alert_type}: {reason}")
        
    return jsonify({'status': 'logged'})

# --- Proof Mode Routes ---

@app.route('/proof/<file_id>')
def proof_dashboard(file_id):
    meta = get_token_metadata(file_id)
    if not meta:
        return render_template('error.html', message="Evidence file not found.")
        
    return render_template('proof_dashboard.html', 
                           file_id=file_id,
                           meta=meta,
                           crypto=meta.get('crypto_evidence', {}),
                           created_at=meta.get('created_at'))

@app.route('/audit-log/<file_id>')
def get_audit_log(file_id):
    logs = get_logs_for_token(file_id)
    return jsonify(logs)

@app.route('/export-logs')
@limiter.limit("5 per minute")
def export_logs():
    csv_path = export_audit_logs_csv()
    if csv_path and os.path.exists(csv_path):
        return send_file(csv_path, as_attachment=True)
    return "No logs available or error exporting.", 404

@app.route('/download_encrypted/<file_id>')
def download_encrypted(file_id):
    filename = f"{file_id}.enc"
    path = os.path.join(STATIC_FOLDER, filename)
    if os.path.exists(path):
        return send_file(path, as_attachment=True, download_name=f"encrypted_{file_id[:8]}.bin")
    else:
        abort(404)

@app.route('/test-decryption/<file_id>', methods=['POST'])
@csrf.exempt
def test_decryption(file_id):
    try:
        data = request.get_json(silent=True) or {}
        password = data.get('password')
        
        meta = get_token_metadata(file_id)
        if not meta:
            return jsonify({'status': 'error', 'message': 'File not found'}), 404

        # Load Encrypted File
        encrypted_filename = f"{file_id}.enc"
        encrypted_path = os.path.join(STATIC_FOLDER, encrypted_filename)
        
        if not os.path.exists(encrypted_path):
             return jsonify({'status': 'error', 'message': 'File missing'})

        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()

        # Try Decrypt
        methods = meta['crypto_evidence'].get('methods', ['fernet']) # Use saved methods
        
        # We don't care about the content, just if it throws
        EncryptionManager.decrypt_data(encrypted_data, password, methods)
        
        # Log Success
        log_audit_event("DECRYPTION_TEST", token_hash=file_id, ip=request.remote_addr, status="SUCCESS")
        return jsonify({'status': 'success'})

    except ValueError as e:
        msg = str(e)
        if "Integrity Check Failed" in msg:
            log_audit_event("DECRYPTION_TEST_FAIL", token_hash=file_id, ip=request.remote_addr, status="TAMPER_DETECTED", reason="HMAC Signature Mismatch")
            return jsonify({'status': 'integrity_fail', 'message': 'HMAC Signature Mismatch. File tampered or password incorrect.'})
        else:
            log_audit_event("DECRYPTION_TEST_FAIL", token_hash=file_id, ip=request.remote_addr, status="ERROR", reason=msg)
            return jsonify({'status': 'fail', 'message': msg})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

def handle_expiry_cleanup(file_id):
    handle_destruction(file_id, "Expired")

def get_client_forensics(req):
    """
    Extracts IP, Location, Device info from request.
    """
    ip = req.remote_addr
    ua = req.user_agent
    
    # Device / Platform
    device_type = "Desktop"
    if ua.platform in ['android', 'iphone', 'ipad']:
        device_type = "Mobile/Tablet"
    
    # Geolocation
    loc_data = {}
    try:
        # 3s timeout to avoid hanging
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        if resp.status_code == 200:
            loc_data = resp.json()
    except:
        pass
        
    return {
        'ip': ip,
        'ua_parsed': f"{ua.browser} {ua.version} on {ua.platform}",
        'device': device_type,
        'city': loc_data.get('city', 'Unknown'),
        'region': loc_data.get('regionName', 'Unknown'),
        'country': loc_data.get('country', 'Unknown'),
        'isp': loc_data.get('isp', 'Unknown'),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'receiver_email': "N/A" # Will fit in later
    }

def handle_destruction(file_id, reason):
    """
    Deletes all traces of the file and notifies the sender.
    Ensures alerts are sent only once per file destruction.
    """
    if not file_id: return
    
    # Use session to prevent duplicate destruction logic for the same file in one session
    if session.get(f'destroyed_{file_id}'):
        return

    # 1. Gather info BEFORE deletion
    meta = get_token_metadata(file_id)
    sender_email = meta.get('sender_email') if meta else session.get(f'email_{file_id}')
    receiver_email = meta.get('receiver_email') if meta else "Unknown"
    
    # 2. Delete Files
    enc_path = os.path.join(STATIC_FOLDER, f"{file_id}.enc")
    qr_path = os.path.join(STATIC_FOLDER, f"qr_{file_id}.png")
    meta_path = os.path.join(DATA_FOLDER, f"{file_id}.json")
    
    any_deleted = False
    for p in [enc_path, qr_path, meta_path]:
        if os.path.exists(p):
            try: 
                os.remove(p)
                any_deleted = True
            except Exception as e:
                print(f"Error removing {p}: {e}")
            
    # Mark as destroyed in session to avoid double-processing
    session[f'destroyed_{file_id}'] = True
    
    # 3. Clear verification flags
    session.pop(f'verified_{file_id}', None)
    session.pop(f'temp_password_{file_id}', None)
    
    # 4. Notify & Audit (Only if we actually deleted something or it's a logical trigger)
    # We always audit if it's the first time (session check passed).
    if sender_email:
        try:
            forensics = get_client_forensics(request)
            forensics['receiver_email'] = receiver_email
            
            send_alert_email(
                sender_email,
                file_id,
                "CONTENT DESTROYED",
                reason,
                forensics
            )
            # Log the formal destruction event
            log_audit_event("CONTENT_DESTROYED", token_hash=file_id, ip=request.remote_addr, status="COMPLETED", reason=reason)
        except Exception as e:
            print(f"Failed to send destruction alert: {e}")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5050, ssl_context='adhoc')
