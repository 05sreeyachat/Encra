from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class EncryptedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.String(36), unique=True, nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    encryption_key = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer)
    mime_type = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    access_count = db.Column(db.Integer, default=0)
    last_accessed = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    download_count = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<EncryptedFile {self.file_name}>'
    
    def increment_access(self):
        self.access_count += 1
        self.last_accessed = datetime.utcnow()
        self.download_count += 1

class FileAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.String(36), nullable=False)
    access_type = db.Column(db.String(50))
    success = db.Column(db.Boolean, default=False)
    ip_address = db.Column(db.String(45))
    accessed_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_agent = db.Column(db.String(255))
    device_info = db.Column(db.String(255))
    location = db.Column(db.String(255))
    
    def __repr__(self):
        return f'<FileAccess {self.file_id} at {self.accessed_at}>'
    
    def log_access(self, success=True):
        self.success = success
        self.accessed_at = datetime.utcnow()

class UserSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.String(36), unique=True, nullable=False)
    max_downloads = db.Column(db.Integer, default=-1)
    expiry_date = db.Column(db.DateTime)
    notification_email = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    auto_delete = db.Column(db.Boolean, default=False)
    password_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<UserSettings for {self.file_id}>'
    
    def check_validity(self):
        if self.expiry_date and datetime.utcnow() > self.expiry_date:
            return False
        if self.max_downloads != -1 and self.max_downloads <= 0:
            return False
        if self.is_locked:
            return False
        return True
    
    def increment_attempts(self):
        self.password_attempts += 1
        if self.password_attempts >= 5:
            self.is_locked = True