# Secure Messaging Application

A client-server messaging system with HTTPS, password hashing, and end-to-end encryption.

## Features
- HTTPS with TLS certificates
- User registration and authentication
- Password hashing (bcrypt)
- End-to-end encryption with RSA keys
- Session management
- Encrypted messaging

## Requirements
- Python 3.7+
- OpenSSL

## Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Generate TLS Certificates
```bash
python generate-certs.py
```
This creates self-signed certificates in the `certs/` directory for HTTPS.

### 3. Start the Server
```bash
python server-secure.py
```
Server runs on `https://127.0.0.1:5000`

### 4. Start the Client
```bash
python client-secure.py
```

## Usage

### Client Menu Options
1. **Register** - Create a new user account
2. **Login** - Authenticate with credentials
3. **Send Message** - Send encrypted message to a user
4. **View Messages** - View encrypted messages sent to you
5. **Logout** - End your session
6. **Exit** - Close the client

### First Time Setup
1. Register a new user (generates RSA key pair)
2. Optionally set a password for your private key
3. Keys are stored in `keys/` directory

### Sending Messages
- Select a recipient from registered users
- Type your message
- Message is encrypted with recipient's public key
- Only recipient can decrypt with their private key

## Project Structure
```
assg-01/
├── server-secure.py        # Flask server with HTTPS
├── client-secure.py        # Interactive client
├── generate-certs.py       # Certificate generation
├── requirements.txt        # Python dependencies
├── certs/                  # TLS certificates
├── keys/                   # User RSA keys
└── utils/                  # Helper modules
    ├── auth.py             # Authentication & sessions
    └── crypto.py           # Encryption functions
```

## Security Features
- **Transport Security**: HTTPS with TLS 1.2+
- **Password Security**: bcrypt hashing with salt
- **End-to-End Encryption**: RSA + AES hybrid encryption
- **Session Management**: Token-based with expiration
- **Key Protection**: Optional password-protected private keys

## Notes
- Self-signed certificates will show security warnings (expected behavior)
- Client automatically accepts the self-signed certificate
- User keys are stored locally in `keys/` directory
- Sessions expire after 24 hours
