"""
Generate self-signed TLS certificates for HTTPS
"""
import os
import subprocess

def generate_certificates():
    """Generate self-signed SSL certificate using OpenSSL"""
    
    # Create certs directory
    os.makedirs('certs', exist_ok=True)
    
    print("Generating TLS certificates for localhost...")
    
    # Check if OpenSSL is available
    try:
        subprocess.run(['openssl', 'version'], capture_output=True, check=True)
    except Exception:
        print("ERROR: OpenSSL not found. Please install OpenSSL first.")
        return False
    
    cert_file = 'certs/server.crt'
    key_file = 'certs/server.key'
    
    # If certificates already exist, ask before overwriting
    if os.path.exists(cert_file) and os.path.exists(key_file):
        response = input("Certificates already exist. Overwrite? (yes/no): ")
        if response.lower() != 'yes':
            print("Keeping existing certificates.")
            return True
    
    # Generate private key
    print("1. Generating private key...")
    cmd1 = ['openssl', 'genrsa', '-out', key_file, '2048']
    subprocess.run(cmd1, check=True)
    print("   Private key generated")
    
    # Generate certificate signing request and self-signed certificate
    print("2. Generating self-signed certificate...")
    cmd2 = [
        'openssl', 'req', '-new', '-x509',
        '-key', key_file,
        '-out', cert_file,
        '-days', '365',
        '-subj', '/C=PK/ST=Punjab/L=Lahore/O=University/CN=localhost'
    ]
    subprocess.run(cmd2, check=True)
    print("   Certificate generated")
    
   
    print(" TLS certificates successfully generated!")
    print(f"  Certificate: {cert_file}")
    print(f"  Private key: {key_file}")
    print(f"  Valid for: 365 days")
    
    
    return True


if __name__ == '__main__':
    print("TLS Certificate Generator")
    
    if generate_certificates():
        print("\nYou can now run the secure server with HTTPS:")
        print("  python server_secure.py")
    else:
        print("\nFailed to generate certificates.")
        print("The server will run without TLS (HTTP only).")
