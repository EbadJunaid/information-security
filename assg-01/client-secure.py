"""
Secure messaging client with end-to-end encryption
"""
import requests
import os
import urllib3
from utils.crypto import (
    generate_rsa_keypair, 
    save_private_key, 
    load_private_key,
    public_key_to_pem,
    pem_to_public_key,
    encrypt_message_hybrid,
    decrypt_message_hybrid
)

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SERVER = "https://127.0.0.1:5000"
session_token = None
private_key = None
username = None


def setup_user_keys(user):
    """Generate or load RSA key pair for user"""
    global private_key
    
    key_file = f"keys/{user}_private.pem"
    
    if os.path.exists(key_file):
        # Load existing key
        password = input("Enter key password (or press Enter for none): ")
        password = password if password else None
        private_key = load_private_key(key_file, password)
        
        if private_key is None:
            print("✗ Failed to load key. Please try again or delete the key file.")
            return None
        
        public_key = private_key.public_key()
        print(f" Loaded existing keys for {user}")
    else:
        # Generate new key pair
        os.makedirs('keys', exist_ok=True)
        private_key, public_key = generate_rsa_keypair()
        
        password = input("Set key password (or press Enter for none): ")
        password = password if password else None
        save_private_key(private_key, key_file, password)
        print(f" Generated new key pair for {user}")
    
    return public_key


def register(user, password):
    """Register new user with public key"""
    public_key = setup_user_keys(user)
    
    if public_key is None:
        return
    
    public_key_pem = public_key_to_pem(public_key)
    
    payload = {
        'username': user,
        'password': password,
        'public_key': public_key_pem
    }
    
    try:
        r = requests.post(f"{SERVER}/register", json=payload, verify=False, timeout=500)
        response = r.json()
        
        if r.status_code == 200:
            print(f" Registration successful: {response.get('status')}")
        else:
            print(f" Registration failed: {response.get('error')}")
    except Exception as e:
        print(f" Error: {e}")


def login(user, password):
    """Login and create session"""
    global session_token, username
    
    # Load user's private key
    public_key = setup_user_keys(user)
    
    if public_key is None:
        return
    
    payload = {'username': user, 'password': password}
    
    try:
        r = requests.post(f"{SERVER}/login", json=payload, verify=False, timeout=500)
        response = r.json()
        
        if r.status_code == 200:
            session_token = response.get('session_token')
            username = user
            print(f" Login successful")
            print(f"  Session token: {session_token[:20]}...")
        else:
            print(f" Login failed: {response.get('error')}")
    except Exception as e:
        print(f" Error: {e}")


def logout():
    """Logout and clear session"""
    global session_token, username
    
    if not session_token:
        print(" Not logged in")
        return
    
    headers = {'Authorization': session_token}
    
    try:
        r = requests.post(f"{SERVER}/logout", headers=headers, verify=False, timeout=500)
        if r.status_code == 200:
            print(f" Logged out successfully")
            session_token = None
            username = None
        else:
            print(f" Logout failed: {r.json().get('error')}")
    except Exception as e:
        print(f" Error: {e}")


def send_message(recipient, message):
    """Encrypt and send message using hybrid encryption"""
    if not session_token:
        print(" Please login first")
        return
    
    try:
        # Get recipient's public key
        r = requests.get(f"{SERVER}/public_key/{recipient}", verify=False, timeout=500)
        if r.status_code != 200:
            print(f" Recipient not found: {recipient}")
            return
        
        recipient_key_pem = r.json()['public_key']
        recipient_public_key = pem_to_public_key(recipient_key_pem)
        
        # Perform hybrid encryption
        encrypted = encrypt_message_hybrid(message, recipient_public_key)
        
        # Send encrypted message to server
        payload = {
            'to': recipient,
            'encrypted_key': encrypted['encrypted_key'],
            'ciphertext': encrypted['ciphertext'],
            'nonce': encrypted['nonce']
        }
        
        headers = {'Authorization': session_token}
        r = requests.post(f"{SERVER}/send", json=payload, headers=headers, verify=False, timeout=500)
        
        if r.status_code == 200:
            print(f" Encrypted message sent to {recipient}")
            print(f"  [Your plaintext was: '{message}']")
            print(f"  [Server sees only: {encrypted['ciphertext'][:50]}...]")
        else:
            print(f" Failed to send: {r.json().get('error')}")
            
    except Exception as e:
        print(f" Error: {e}")


def fetch_messages():
    """Fetch and decrypt messages"""
    if not session_token:
        print(" Please login first")
        return
    
    if not private_key:
        print(" Private key not loaded")
        return
    
    try:
        headers = {'Authorization': session_token}
        r = requests.get(f"{SERVER}/messages", headers=headers, verify=False, timeout=500)
        
        if r.status_code != 200:
            print(f"✗ Failed to fetch: {r.json().get('error')}")
            return
        
        messages = r.json()
        
        if not messages:
            print(" No messages")
            return
        
        
        print(f" You have {len(messages)} message(s)")
        
        for i, msg in enumerate(messages, 1):
            try:
                # Decrypt message using hybrid decryption
                plaintext = decrypt_message_hybrid(
                    msg['encrypted_key'],
                    msg['ciphertext'],
                    msg['nonce'],
                    private_key
                )
                
                print(f"Message {i}:")
                print(f"  From: {msg['sender']}")
                print(f"  Content: {plaintext}")
                print(f"  [Encrypted form: {msg['ciphertext'][:40]}...]")
                print()
                
            except Exception as e:
                print(f"Message {i}: Failed to decrypt - {e}")
                print()
        
    except Exception as e:
        print(f" Error: {e}")


def show_status():
    """Show current connection status"""
    print("Current Status:")
    print(f"  Server: {SERVER}")
    print(f"  Logged in as: {username if username else 'Not logged in'}")
    print(f"  Session active: {'Yes' if session_token else 'No'}")
    print(f"  Private key loaded: {'Yes' if private_key else 'No'}")


if __name__ == '__main__':
    
    print(" Secure End-to-End Encrypted Messaging Client")
    
    
    while True:
        print("\nCommands: register | login | send | inbox | logout | status | quit")
        cmd = input(">>> ").strip().lower()
        
        if cmd == 'register':
            user = input("Username: ").strip()
            pwd = input("Password: ").strip()
            if user and pwd:
                register(user, pwd)
        
        elif cmd == 'login':
            user = input("Username: ").strip()
            pwd = input("Password: ").strip()
            if user and pwd:
                login(user, pwd)
        
        elif cmd == 'send':
            if not session_token:
                print(" Please login first")
                continue
            recipient = input("To: ").strip()
            message = input("Message: ").strip()
            if recipient and message:
                send_message(recipient, message)
        
        elif cmd == 'inbox':
            fetch_messages()
        
        elif cmd == 'logout':
            logout()
        
        elif cmd == 'status':
            show_status()
        
        elif cmd == 'quit':
            print("Goodbye!")
            break
        
        else:
            print("Invalid command")
