# whistledrop/utils/generate_rsa_keys.py
import os
import getpass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

KEY_SIZE = 4096
PUBLIC_EXPONENT = 65537

# Define standard output directories relative to this utils script
# This assumes utils/ is a sibling of journalist_tool/
current_script_dir = os.path.dirname(os.path.abspath(__file__))
project_base_dir = os.path.dirname(current_script_dir) # WhistleDrop-main
JOURNALIST_TOOL_DIR = os.path.join(project_base_dir, "journalist_tool")

PRIVATE_KEYS_OUTPUT_DIR = os.path.join(JOURNALIST_TOOL_DIR, "private_keys")
PUBLIC_KEYS_FOR_SERVER_OUTPUT_DIR = os.path.join(JOURNALIST_TOOL_DIR, "public_keys_for_server")


def generate_rsa_key_pair(key_id_prefix="key", key_index=1, password=None):
    """
    Generates an RSA key pair.
    Saves private key to PRIVATE_KEYS_OUTPUT_DIR.
    Saves public key to PUBLIC_KEYS_FOR_SERVER_OUTPUT_DIR.
    Returns paths to the public and private key files.
    """
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    encryption_algorithm = serialization.NoEncryption()
    if password:
        encryption_algorithm = serialization.BestAvailableEncryption(password.encode())

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    key_id = f"{key_id_prefix}_{key_index}"

    os.makedirs(PRIVATE_KEYS_OUTPUT_DIR, exist_ok=True)
    os.makedirs(PUBLIC_KEYS_FOR_SERVER_OUTPUT_DIR, exist_ok=True)

    private_key_path = os.path.join(PRIVATE_KEYS_OUTPUT_DIR, f"{key_id}_private.pem")
    public_key_path_for_server = os.path.join(PUBLIC_KEYS_FOR_SERVER_OUTPUT_DIR,
                                              f"{key_id}_public.pem")
    public_key_path_local_ref = os.path.join(PRIVATE_KEYS_OUTPUT_DIR, f"{key_id}_public.pem") # Local copy

    with open(private_key_path, 'wb') as f: f.write(pem_private)
    print(f"Private key saved to: {os.path.relpath(private_key_path, project_base_dir)}")

    with open(public_key_path_for_server, 'wb') as f: f.write(pem_public)
    print(f"Public key (for server) saved to: {os.path.relpath(public_key_path_for_server, project_base_dir)}")

    with open(public_key_path_local_ref, 'wb') as f: f.write(pem_public)
    # print(f"Public key (local reference) saved to: {os.path.relpath(public_key_path_local_ref, project_base_dir)}")

    print(f"\n--- PUBLIC KEY CONTENT ({key_id}) ---")
    print(pem_public.decode())
    print(f"--- END PUBLIC KEY CONTENT ({key_id}) ---\n")

    return public_key_path_for_server, private_key_path


if __name__ == "__main__":
    print("WhistleDrop - RSA Key Pair Generation Utility")
    print("---------------------------------------------")
    print(f"Private keys will be saved to: {os.path.relpath(PRIVATE_KEYS_OUTPUT_DIR, project_base_dir)}")
    print(f"Public keys (for server) will be saved to: {os.path.relpath(PUBLIC_KEYS_FOR_SERVER_OUTPUT_DIR, project_base_dir)}\n")


    num_keys = 0
    while num_keys <= 0:
        try:
            num_keys_str = input("Enter the number of key pairs to generate (e.g., 1, 5): ")
            num_keys = int(num_keys_str)
            if num_keys <= 0: print("Please enter a positive number.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    key_id_prefix_input = input(f"Enter a prefix for key identifiers (default: 'journalist_key'): ").strip()
    if not key_id_prefix_input: key_id_prefix_input = "journalist_key"

    use_password = input("Password-protect private keys? (yes/no, default: yes): ").lower()
    password = None
    if use_password in ['', 'yes', 'y']:
        while True:
            password = getpass.getpass("Enter password for private keys: ")
            password_confirm = getpass.getpass("Confirm password: ")
            if password == password_confirm:
                if not password: # Ensure password is not empty if protection is chosen
                    print("Password cannot be empty if protection is chosen. Please provide a password or choose 'no'.")
                else:
                    break
            else:
                print("Passwords do not match. Please try again.")
    elif use_password in ['no', 'n']:
        print("Private keys will NOT be password-protected.")
    else: # Default to password protection on invalid input, but prompt again
        print("Invalid choice for password protection. Assuming 'yes'.")
        while True:
            password = getpass.getpass("Enter password for private keys: ")
            password_confirm = getpass.getpass("Confirm password: ")
            if password == password_confirm:
                if not password:
                    print("Password cannot be empty if protection is chosen. Please provide a password or choose 'no'.")
                else:
                    break
            else:
                print("Passwords do not match. Please try again.")


    public_key_server_paths = []
    for i in range(1, num_keys + 1):
        print(f"\nGenerating key pair {i} of {num_keys}...")
        pub_path_server, _ = generate_rsa_key_pair(
            key_id_prefix=key_id_prefix_input,
            key_index=i,
            password=password
        )
        public_key_server_paths.append(pub_path_server)

    print("\n=====================================================================")
    print("Key generation complete.")
    print(f"{num_keys} private key(s) generated in: {os.path.relpath(PRIVATE_KEYS_OUTPUT_DIR, project_base_dir)}")
    print(f"{num_keys} public key(s) (for server) generated in: {os.path.relpath(PUBLIC_KEYS_FOR_SERVER_OUTPUT_DIR, project_base_dir)}")
    if password:
        print("Private keys are password-protected. REMEMBER YOUR PASSWORD!")
    else:
        print("Private keys are NOT password-protected.")
    print("\nNext steps:")
    print(
        f"1. The public keys in '{os.path.basename(PUBLIC_KEYS_FOR_SERVER_OUTPUT_DIR)}' need to be added to the WhistleDrop server's key database.")
    print("   You can use 'utils/add_public_key_to_db.py' script or the Journalist GUI function.")
    print(f"2. The private keys in '{os.path.basename(PRIVATE_KEYS_OUTPUT_DIR)}' MUST be kept secret by the journalist.")
    print("=====================================================================")