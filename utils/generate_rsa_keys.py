# whistledrop/utils/generate_rsa_keys.py
import os
import getpass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from pathlib import Path

KEY_SIZE = 4096
PUBLIC_EXPONENT = 65537

JOURNALIST_TOOL_BASE_DIR = Path(__file__).parent.parent / "journalist_tool"
PRIVATE_RSA_KEYS_OUTPUT_DIR = JOURNALIST_TOOL_BASE_DIR / "private_keys"
PUBLIC_RSA_KEYS_FOR_SERVER_OUTPUT_DIR = JOURNALIST_TOOL_BASE_DIR / "public_keys_for_server"


def generate_rsa_key_pair(key_id_prefix: str = "journalist_enc_key",
                          key_index: int = 1,
                          password: str | None = None,
                          private_key_dir: Path = PRIVATE_RSA_KEYS_OUTPUT_DIR,
                          public_key_dir: Path = PUBLIC_RSA_KEYS_FOR_SERVER_OUTPUT_DIR
                          ) -> tuple[str, str] | None:
    """
    Generates an RSA key pair for ENCRYPTING/DECRYPTING submission content.
    """
    print(f"\nGenerating RSA encryption key pair: {key_id_prefix}_{key_index}...")
    try:
        private_key = rsa.generate_private_key(
            public_exponent=PUBLIC_EXPONENT,
            key_size=KEY_SIZE,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        encryption_algorithm = serialization.NoEncryption()
        if password:
            if not isinstance(password, str) or len(password) < 8:
                print("Warning: Password is short. Consider a stronger password.")
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode('utf-8'))

        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        key_file_base_name = f"{key_id_prefix}_{key_index}_encryption"
        private_key_filename = f"{key_file_base_name}_private.pem"
        public_key_filename = f"{key_file_base_name}_public.pem"

        private_key_dir.mkdir(parents=True, exist_ok=True)
        public_key_dir.mkdir(parents=True, exist_ok=True)

        private_key_path = private_key_dir / private_key_filename
        public_key_path_for_server = public_key_dir / public_key_filename

        with open(private_key_path, 'wb') as f_priv:
            f_priv.write(pem_private)
        print(f"  Private RSA encryption key saved to: {private_key_path.resolve()}")

        with open(public_key_path_for_server, 'wb') as f_pub:
            f_pub.write(pem_public)
        print(f"  Public RSA encryption key (for server admin) saved to: {public_key_path_for_server.resolve()}")

        print(f"\n  --- Content of Public RSA Encryption Key ({key_file_base_name}) ---")
        print(pem_public.decode('utf-8').strip())
        print(f"  --- End of Public Key Content ---")

        return str(public_key_path_for_server.resolve()), str(private_key_path.resolve())

    except Exception as e:
        print(f"Error generating RSA key pair '{key_id_prefix}_{key_index}': {e}")
        return None


if __name__ == "__main__":
    print("WhistleDrop - RSA ENCRYPTION Key Pair Generation Utility")
    print("------------------------------------------------------")
    print("Generates RSA key pairs for journalists to decrypt submission content.")
    print("PUBLIC key part -> server admin. PRIVATE key part -> journalist (secret).")
    print("These are NOT for SSH/SFTP authentication.\n")

    num_keys_to_generate = 0
    while num_keys_to_generate <= 0:
        try:
            num_keys_str = input("Enter number of RSA encryption key pairs to generate (e.g., 1): ")
            num_keys_to_generate = int(num_keys_str)
            if num_keys_to_generate <= 0: print("Please enter a positive number.")
        except ValueError:
            print("Invalid input. Please enter a whole number.")

    key_id_prefix_input = ""
    while not key_id_prefix_input:
        key_id_prefix_input = input(
            f"Enter prefix for key identifiers (e.g., 'journoA', default: 'wd_enc_key'): ").strip()
        if not key_id_prefix_input: key_id_prefix_input = "wd_enc_key"
        if not (key_id_prefix_input.isalnum() or '_' in key_id_prefix_input or '-' in key_id_prefix_input):
            print("Prefix should be alphanumeric with underscores/hyphens. Try again.")
            key_id_prefix_input = ""

    password_input = None
    while True:
        use_password_choice = input("Password-protect private RSA keys? (yes/no, default: yes): ").lower().strip()
        if use_password_choice in ['', 'yes', 'y']:
            while True:
                password_input = getpass.getpass("Enter password for private RSA keys (min 8 chars recommended): ")
                if not password_input:
                    print("Password cannot be empty if protection is chosen.")
                    continue
                if len(password_input) < 8:
                    print("Warning: Password is less than 8 characters.")
                    confirm_weak = input("Continue with this password? (yes/no): ").lower().strip()
                    if confirm_weak not in ['yes', 'y']: continue
                password_confirm = getpass.getpass("Confirm password: ")
                if password_input == password_confirm:
                    break
                else:
                    print("Passwords do not match. Try again.")
            break
        elif use_password_choice in ['no', 'n']:
            print("Private RSA keys will NOT be password-protected. (Less Secure)")
            password_input = None
            break
        else:
            print("Invalid choice. Please enter 'yes' or 'no'.")

    generated_keys_count = 0
    for i in range(1, num_keys_to_generate + 1):
        if generate_rsa_key_pair(
                key_id_prefix=key_id_prefix_input, key_index=i, password=password_input
        ):
            generated_keys_count += 1

    print("\n=====================================================================")
    if generated_keys_count > 0:
        print(f"RSA Encryption Key Generation Summary ({generated_keys_count} pair(s)):")
        print(f"  - Private RSA keys in: {PRIVATE_RSA_KEYS_OUTPUT_DIR.resolve()}")
        print(f"  - Public RSA keys (for admin) in: {PUBLIC_RSA_KEYS_FOR_SERVER_OUTPUT_DIR.resolve()}")
        if password_input:
            print("  - Private RSA keys ARE password-protected.")
        else:
            print("  - Private RSA keys are NOT password-protected.")
        print("\n  Next Steps:")
        print(
            f"  1. Securely provide public keys from '{PUBLIC_RSA_KEYS_FOR_SERVER_OUTPUT_DIR.resolve()}' to server admin.")
        print(f"  2. Keep private keys from '{PRIVATE_RSA_KEYS_OUTPUT_DIR.resolve()}' secret and secure.")
    else:
        print("No RSA encryption key pairs were generated.")
    print("=====================================================================")