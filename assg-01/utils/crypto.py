"""
Cryptography utilities for hybrid encryption (RSA + AES-GCM)
"""
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_rsa_keypair():
    """Generate RSA key pair for a user"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key, filename, password=None):
    """Save private key to file with optional password protection"""
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    else:
        encryption = serialization.NoEncryption()
    
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    
    with open(filename, 'wb') as f:
        f.write(pem)


def load_private_key(filename, password=None):
    """Load private key from file"""
    with open(filename, 'rb') as f:
        pem = f.read()
    
    pwd = password.encode() if password else None
    
    try:
        private_key = serialization.load_pem_private_key(pem, password=pwd)
        return private_key
    except Exception as e:
        print(f"✗ Error loading private key: Wrong password or corrupted key file")
        return None


def public_key_to_pem(public_key):
    """Convert public key to PEM string for transmission"""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode()


def pem_to_public_key(pem_string):
    """Convert PEM string back to public key object"""
    pem_bytes = pem_string.encode()
    public_key = serialization.load_pem_public_key(pem_bytes)
    return public_key


def encrypt_aes_gcm(message, aes_key):
    """
    Encrypt message using AES-256-GCM
    Returns: (ciphertext, nonce)
    Note: GCM mode includes authentication tag in ciphertext
    """
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
    return ciphertext, nonce


def decrypt_aes_gcm(ciphertext, aes_key, nonce):
    """
    Decrypt message using AES-256-GCM
    Automatically verifies authentication tag
    """
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


def rsa_encrypt(data, public_key):
    """Encrypt data using RSA public key (for AES key exchange)"""
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def rsa_decrypt(encrypted_data, private_key):
    """Decrypt data using RSA private key"""
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted


def encrypt_message_hybrid(message, recipient_public_key):
    """
    Complete hybrid encryption flow:
    1. Generate random AES key
    2. Encrypt message with AES-GCM
    3. Encrypt AES key with RSA
    Returns: (encrypted_key, ciphertext, nonce) all as base64 strings
    """
    # Generate random AES-256 key
    aes_key = os.urandom(32)
    
    # Encrypt message with AES-GCM
    ciphertext, nonce = encrypt_aes_gcm(message, aes_key)
    
    # Encrypt AES key with recipient's RSA public key
    encrypted_key = rsa_encrypt(aes_key, recipient_public_key)
    
    # Encode to base64 for transmission
    return {
        'encrypted_key': base64.b64encode(encrypted_key).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'nonce': base64.b64encode(nonce).decode()
    }


def decrypt_message_hybrid(encrypted_key_b64, ciphertext_b64, nonce_b64, private_key):
    """
    Complete hybrid decryption flow:
    1. Decrypt AES key using RSA private key
    2. Decrypt message using AES-GCM
    Returns: plaintext message
    """
    # Decode from base64
    encrypted_key = base64.b64decode(encrypted_key_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    
    # Decrypt AES key using RSA
    aes_key = rsa_decrypt(encrypted_key, private_key)
    
    # Decrypt message using AES-GCM
    plaintext = decrypt_aes_gcm(ciphertext, aes_key, nonce)
    
    return plaintext
