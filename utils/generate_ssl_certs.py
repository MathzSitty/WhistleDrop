# whistledrop/utils/generate_ssl_certs.py
import os
import sys
import datetime
# Import UTC for timezone-aware datetime objects
from datetime import timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# --- Path Adjustment ---
current_script_path = os.path.abspath(__file__)
utils_dir = os.path.dirname(current_script_path)
project_root_dir = os.path.dirname(utils_dir)

if project_root_dir not in sys.path:
    sys.path.insert(0, project_root_dir)
# --- End Path Adjustment ---

from whistledrop_server.config import Config # To get SSL_CERT_PATH and SSL_KEY_PATH

CERT_FILENAME = os.path.basename(Config.SSL_CERT_PATH) # e.g., "cert.pem"
KEY_FILENAME = os.path.basename(Config.SSL_KEY_PATH)   # e.g., "key.pem"
CERT_DIR = os.path.dirname(Config.SSL_CERT_PATH)       # e.g., "whistledrop_server/certs"

def generate_self_signed_cert(hostname="localhost"):
    """
    Generates a self-signed SSL certificate and private key.
    Saves them to the paths defined in Config.
    """
    print(f"Generating self-signed SSL certificate for hostname: {hostname}")
    print(f"Certificate will be saved to: {Config.SSL_CERT_PATH}")
    print(f"Private key will be saved to: {Config.SSL_KEY_PATH}")

    # Ensure the certs directory exists
    os.makedirs(CERT_DIR, exist_ok=True)

    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Write private key to file
    with open(Config.SSL_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"Private key saved: {Config.SSL_KEY_PATH}")

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"XX"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"N/A"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"N/A"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"WhistleDrop Development"),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])

    # Get current time in UTC
    now_utc = datetime.datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now_utc) # Use timezone-aware datetime
        .not_valid_after(
            # Certificate valid for 1 year
            now_utc + datetime.timedelta(days=365) # Use timezone-aware datetime
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
    )

    certificate = builder.sign(key, hashes.SHA256(), default_backend())

    with open(Config.SSL_CERT_PATH, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    print(f"Certificate saved: {Config.SSL_CERT_PATH}")
    print("\nSSL certificate and key generated successfully.")
    print("The Flask server can now be run with HTTPS if configured to use these files.")
    print("Note: This is a self-signed certificate, browsers will show a warning.")
    print("For Tor Hidden Services, the .onion address provides its own layer of authentication.")

if __name__ == "__main__":
    print("--- WhistleDrop: SSL Certificate Generation Utility ---")
    default_hostname = "localhost"
    hostname_input = input(f"Enter hostname for the certificate (e.g., localhost, your.onion.address) [default: {default_hostname}]: ").strip()
    hostname_to_use = hostname_input if hostname_input else default_hostname

    if os.path.exists(Config.SSL_CERT_PATH) or os.path.exists(Config.SSL_KEY_PATH):
        overwrite = input(
            f"Warning: '{CERT_FILENAME}' or '{KEY_FILENAME}' already exist in '{CERT_DIR}'.\n"
            "Overwrite? (yes/no) [default: no]: "
        ).lower()
        if overwrite not in ['yes', 'y']:
            print("Certificate generation aborted by user.")
            sys.exit(0)

    generate_self_signed_cert(hostname=hostname_to_use)