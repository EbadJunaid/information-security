"""
Authentication utilities for password hashing and session management
"""
import bcrypt
import secrets
from datetime import datetime, timedelta


def hash_password(password):
    """Hash password using bcrypt with automatic salt generation"""
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=12)  # Cost factor 12
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def verify_password(password, password_hash):
    """Verify password against stored hash"""
    password_bytes = password.encode('utf-8')
    hash_bytes = password_hash.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hash_bytes)


def generate_session_token():
    """Generate cryptographically secure session token"""
    return secrets.token_urlsafe(32)


class SessionManager:
    """Manage user sessions with expiration"""
    
    def __init__(self, expiration_hours=24):
        self.sessions = {}
        self.expiration_hours = expiration_hours
    
    def create_session(self, username):
        """Create new session for user"""
        token = generate_session_token()
        expiry = datetime.now() + timedelta(hours=self.expiration_hours)
        self.sessions[token] = {
            'username': username,
            'expires': expiry
        }
        return token
    
    def validate_session(self, token):
        """Check if session is valid and not expired"""
        if token not in self.sessions:
            return None
        
        session = self.sessions[token]
        if datetime.now() > session['expires']:
            del self.sessions[token]
            return None
        
        return session['username']
    
    def remove_session(self, token):
        """Remove session (logout)"""
        if token in self.sessions:
            del self.sessions[token]
            return True
        return False
    
    def cleanup_expired(self):
        """Remove all expired sessions"""
        now = datetime.now()
        expired = [token for token, session in self.sessions.items() 
                   if now > session['expires']]
        for token in expired:
            del self.sessions[token]
        return len(expired)
