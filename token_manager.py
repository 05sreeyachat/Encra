import secrets
import hashlib
import json
import os
from datetime import datetime, timedelta

DATA_FOLDER = 'data'

def generate_secure_token():
    return secrets.token_urlsafe(32)

def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()

def get_token_metadata(token_hash):
    path = os.path.join(DATA_FOLDER, f"{token_hash}.json")
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return None

def save_token_metadata(token_hash, meta):
    if not os.path.exists(DATA_FOLDER):
        os.makedirs(DATA_FOLDER)
    path = os.path.join(DATA_FOLDER, f"{token_hash}.json")
    with open(path, 'w') as f:
        json.dump(meta, f)

def is_token_valid(token_hash, client_ip=None, user_agent=None):
    meta = get_token_metadata(token_hash)
    if not meta:
        return False, "Token not found"
    
    # Check Expiry
    expires_at = datetime.fromisoformat(meta.get('expires_at'))
    if datetime.now() > expires_at:
        return False, "Token expired"
    
    # Check One-time use
    if meta.get('status') == 'used':
        return False, "Token already used"
    
    # Optional IP/Binding check (Strict Mode)
    # If the token has a bound IP, it must match
    bound_ip = meta.get('bound_ip')
    if bound_ip and client_ip and bound_ip != client_ip:
        return False, "Token bound to different IP"
        
    return True, "Valid"

def invalidate_token(token_hash):
    meta = get_token_metadata(token_hash)
    if meta:
        meta['status'] = 'used'
        meta['used_at'] = datetime.now().isoformat()
        save_token_metadata(token_hash, meta)
