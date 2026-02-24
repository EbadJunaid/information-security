"""
Secure Flask server with HTTPS, password hashing, and end-to-end encryption
"""
from flask import Flask, request, jsonify
from functools import wraps
import os
from utils.auth import hash_password, verify_password, SessionManager

app = Flask(__name__)

# Storage
users = {}  # username -> {password_hash, public_key}
messages = []  # list of encrypted messages
session_manager = SessionManager(expiration_hours=24)


def require_auth(f):
    """Decorator to require valid session for endpoint"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No authorization token'}), 401
        
        username = session_manager.validate_session(token)
        if not username:
            return jsonify({'error': 'Invalid or expired session'}), 401
        
        # Pass username to the endpoint
        return f(username, *args, **kwargs)
    
    return decorated_function


@app.route('/register', methods=['POST'])
def register():
    """Register new user with hashed password"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    public_key = data.get('public_key')
    
    if not username or not password or not public_key:
        return jsonify({'error': 'Missing required fields'}), 400
    
    if username in users:
        return jsonify({'error': 'User already exists'}), 400
    
    # Hash password before storing
    password_hash = hash_password(password)
    
    users[username] = {
        'password_hash': password_hash,
        'public_key': public_key
    }
    
    print(f"[SERVER] User registered: {username}")
    return jsonify({'status': 'registered'}), 200


@app.route('/login', methods=['POST'])
def login():
    """Login with password verification and session creation"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Missing credentials'}), 400
    
    user = users.get(username)
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Verify password against stored hash
    if not verify_password(password, user['password_hash']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Create session
    token = session_manager.create_session(username)
    
    print(f"[SERVER] User logged in: {username}")
    return jsonify({'session_token': token}), 200


@app.route('/logout', methods=['POST'])
@require_auth
def logout(username):
    """Logout and invalidate session"""
    token = request.headers.get('Authorization')
    session_manager.remove_session(token)
    print(f"[SERVER] User logged out: {username}")
    return jsonify({'status': 'logged out'}), 200


@app.route('/send', methods=['POST'])
@require_auth
def send_message(username):
    """
    Store encrypted message (server cannot decrypt)
    Message must include: to, encrypted_key, ciphertext, nonce
    """
    data = request.json
    recipient = data.get('to')
    encrypted_key = data.get('encrypted_key')
    ciphertext = data.get('ciphertext')
    nonce = data.get('nonce')
    
    if not all([recipient, encrypted_key, ciphertext, nonce]):
        return jsonify({'error': 'Missing message fields'}), 400
    
    if recipient not in users:
        return jsonify({'error': 'Recipient not found'}), 404
    
    # Store encrypted message (server sees only encrypted data)
    message = {
        'sender': username,
        'recipient': recipient,
        'encrypted_key': encrypted_key,
        'ciphertext': ciphertext,
        'nonce': nonce
    }
    messages.append(message)
    
    print(f"[SERVER] Encrypted message stored (from {username} to {recipient})")
    print(f"[SERVER] Ciphertext preview: {ciphertext[:50]}...")
    return jsonify({'status': 'message stored'}), 200


@app.route('/messages', methods=['GET'])
@require_auth
def fetch_messages(username):
    """
    Fetch messages for authenticated user (authorization check)
    Only returns messages where recipient matches session user
    """
    # Authorization: only return messages for this user
    user_messages = [msg for msg in messages if msg['recipient'] == username]
    
    print(f"[SERVER] User {username} fetched {len(user_messages)} message(s)")
    return jsonify(user_messages), 200


@app.route('/public_key/<username>', methods=['GET'])
def get_public_key(username):
    """Get public key for a user (needed for encryption)"""
    user = users.get(username)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({'public_key': user['public_key']}), 200


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'running',
        'users': len(users),
        'messages': len(messages),
        'active_sessions': len(session_manager.sessions)
    }), 200


if __name__ == '__main__':
    # Check if TLS certificates exist
    cert_file = 'certs/server.crt'
    key_file = 'certs/server.key'
    
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print("Starting SECURE server with HTTPS/TLS")
        app.run(
            host='127.0.0.1',
            port=5000,
            ssl_context=(cert_file, key_file),
            debug=False
        )
    else:
        
        print("WARNING: TLS certificates not found!")
        print("Run 'python generate_certs.py' first to create certificates")
        print("Starting server without TLS (insecure)")
        app.run(host='127.0.0.1', port=5000, debug=True)
