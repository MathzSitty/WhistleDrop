# whistledrop/whistledrop_server/app.py
import logging
from functools import wraps
from flask import Flask, request, render_template, flash, redirect, url_for, jsonify, Response
from .config import Config
from . import crypto_utils
from . import key_manager
from . import storage_manager  # Still used for saving and listing submissions internally
import threading
import os
import datetime  # For timestamps in journalist interface

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
key_manager.initialize_key_database()

# Lock for RSA Key acquisition and marking
rsa_key_operation_lock = threading.Lock()


# --- Authentication Decorator for Journalist Interface ---
def journalist_api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        api_key_from_config = Config.WHISTLEDROP_JOURNALIST_API_KEY

        if not api_key_from_config:  # Should not happen if config generates one
            logger.critical("CRITICAL: WHISTLEDROP_JOURNALIST_API_KEY is not configured on the server!")
            return jsonify({"error": "Server configuration error: API key not set"}), 500

        if not auth_header:
            logger.warning("Journalist Interface: Authorization header missing.")
            return jsonify({"error": "Authorization header missing. Expected 'Bearer <API_KEY>'"}), 401

        try:
            auth_type, provided_api_key = auth_header.split(None, 1)
        except ValueError:
            logger.warning("Journalist Interface: Invalid Authorization header format.")
            return jsonify({"error": "Invalid Authorization header format. Expected 'Bearer <API_KEY>'"}), 401

        if auth_type.lower() != 'bearer' or provided_api_key != api_key_from_config:
            logger.warning(
                f"Journalist Interface: Failed auth attempt. Provided key prefix: {provided_api_key[:10]}...")
            return jsonify({"error": "Invalid or missing API key"}), 403  # Forbidden

        return f(*args, **kwargs)

    return decorated_function


# --- Whistleblower Upload Routes ---
@app.route('/', methods=['GET'])
def index():
    return render_template('upload.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    # (Upload logic remains largely the same as in the previous SFTP version)
    # It saves to SUBMISSIONS_DIR using storage_manager.
    if 'file' not in request.files:
        flash('No file part in the request.', 'error')
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected for uploading.', 'error')
        return redirect(url_for('index'))

    if file:
        file_data = file.read()
        original_filename = file.filename

        if len(file_data) == 0:
            flash('Uploaded file is empty.', 'error')
            return redirect(url_for('index'))
        if len(file_data) > app.config['MAX_CONTENT_LENGTH']:
            flash(f'File exceeds maximum allowed size of {Config.MAX_UPLOAD_SIZE_MB}MB.', 'error')
            return redirect(url_for('index'))

        logger.info(f"Received file for upload: '{original_filename}', size: {len(file_data)} bytes")
        aes_key = crypto_utils.generate_aes_key()
        try:
            encrypted_file_data = crypto_utils.encrypt_aes_gcm(file_data, aes_key)
            encrypted_original_filename = crypto_utils.encrypt_aes_gcm(original_filename.encode('utf-8'), aes_key)
        except Exception as e:
            logger.error(f"AES encryption failed for '{original_filename}': {e}", exc_info=True)
            flash('Critical error during file encryption. Please try again.', 'error')
            return redirect(url_for('index'))
        finally:
            del file_data

        rsa_public_key_pem = None
        rsa_public_key_id = None
        rsa_public_key_hint_from_db = None
        key_successfully_acquired_and_marked = False

        with rsa_key_operation_lock:
            key_info_tuple = key_manager.get_available_public_key()
            if key_info_tuple:
                rsa_public_key_pem, rsa_public_key_id, rsa_public_key_hint_from_db = key_info_tuple
                if key_manager.mark_key_as_used(rsa_public_key_id):
                    key_successfully_acquired_and_marked = True
                else:
                    logger.error(f"Failed to mark RSA key ID {rsa_public_key_id} as used.")
                    rsa_public_key_pem = None  # Invalidate
            else:
                logger.error("No available RSA public keys in DB (within lock).")

        if not key_successfully_acquired_and_marked or not rsa_public_key_pem:
            del aes_key;
            del encrypted_file_data;
            del encrypted_original_filename
            flash('Server error: Could not secure an encryption key. Please try again later.', 'error')
            return redirect(url_for('index'))

        try:
            encrypted_aes_key = crypto_utils.encrypt_rsa(aes_key, rsa_public_key_pem)
        except Exception as e:
            logger.error(f"RSA encryption of AES key failed (RSA Key ID {rsa_public_key_id}): {e}", exc_info=True)
            logger.critical(f"RSA key ID {rsa_public_key_id} was marked used but AES key encryption failed.")
            del aes_key;
            del encrypted_file_data;
            del encrypted_original_filename
            flash('Critical server error: Failed to secure encryption key.', 'error')
            return redirect(url_for('index'))
        finally:
            del aes_key

        submission_id = storage_manager.save_submission(
            encrypted_file_data, encrypted_aes_key, rsa_public_key_id,
            encrypted_original_filename, rsa_public_key_hint_from_db
        )
        del encrypted_file_data;
        del encrypted_aes_key;
        del encrypted_original_filename

        if submission_id:
            logger.info(f"Submission successful. ID: {submission_id}, Hint: '{rsa_public_key_hint_from_db}'")
            flash(f'File uploaded securely! Submission ID: {submission_id}', 'success')
        else:
            logger.error("Failed to save submission to storage manager.")
            flash('Server error: Failed to save submission after encryption.', 'error')
        return redirect(url_for('index'))

    flash('An unexpected error occurred during upload preparation.', 'error')
    return redirect(url_for('index'))


# --- Journalist Interface Routes (for Metadaten-Abruf) ---
JOURNALIST_INTERFACE_PREFIX = "/wd-journalist"  # To avoid clashes with future user-facing routes


@app.route(f'{JOURNALIST_INTERFACE_PREFIX}/submissions', methods=['GET'])
@journalist_api_key_required
def journalist_list_submissions_metadata():
    """
    Provides a list of submission metadata for authenticated journalists.
    This does NOT provide the encrypted files themselves.
    """
    logger.info(f"Journalist Interface: Request received for submissions metadata by authenticated user.")
    submission_ids = storage_manager.list_submissions()  # Gets directory names from SUBMISSIONS_DIR

    submissions_metadata = []
    for sub_id_str in submission_ids:
        submission_path = os.path.join(Config.SUBMISSIONS_DIR, sub_id_str)
        key_hint = "N/A"
        timestamp_utc_str = "N/A"  # Use string for consistent JSON type

        # Try to get creation/modification time of the submission directory as a proxy for submission time
        try:
            # Check if path is a directory before stat-ing
            if os.path.isdir(submission_path):
                stat_info = os.stat(submission_path)
                # Use modification time (st_mtime) as it's more likely to reflect last content change/creation
                dt_object = datetime.datetime.fromtimestamp(stat_info.st_mtime, tz=datetime.timezone.utc)
                timestamp_utc_str = dt_object.isoformat(timespec='seconds')
            else:
                logger.warning(
                    f"Path '{submission_path}' for submission_id '{sub_id_str}' is not a directory. Skipping for metadata.")
                continue  # Skip this item if it's not a directory as expected
        except FileNotFoundError:
            logger.warning(f"Submission directory not found for '{sub_id_str}' while getting timestamp. Skipping.")
            continue
        except Exception as e_stat:
            logger.warning(f"Could not get timestamp for submission '{sub_id_str}': {e_stat}")

        # Read the key hint from the hint file within the submission directory
        hint_file_path = os.path.join(submission_path, storage_manager.RSA_PUBLIC_KEY_HINT_NAME)
        if os.path.exists(hint_file_path) and os.path.isfile(hint_file_path):
            try:
                with open(hint_file_path, 'r', encoding='utf-8') as hf:
                    hint_content = hf.read().strip()
                if hint_content:
                    key_hint = hint_content
            except Exception as e_hint:
                logger.warning(f"Could not read hint file for submission '{sub_id_str}': {e_hint}")

        submissions_metadata.append({
            "id": sub_id_str,
            "timestamp_utc": timestamp_utc_str,  # Approximate submission time
            "rsa_key_hint": key_hint,
            # Add other non-sensitive metadata if available/needed in future
        })

    # Sort by timestamp, newest first (optional but good for UI)
    try:
        # Ensure robust sorting even if some timestamps are "N/A"
        submissions_metadata.sort(key=lambda x: x.get("timestamp_utc", "0000-00-00T00:00:00Z"), reverse=True)
    except Exception as e_sort:
        logger.warning(f"Could not sort submissions metadata by timestamp: {e_sort}")

    return jsonify({"submissions": submissions_metadata})


@app.route(f'{JOURNALIST_INTERFACE_PREFIX}/status', methods=['GET'])
@journalist_api_key_required
def journalist_interface_status():
    logger.info("Journalist Interface: Status endpoint accessed.")
    # A more accurate count of available keys:
    num_available_keys_count = key_manager.count_available_public_keys()

    return jsonify({
        "status": "ok",
        "message": "Journalist Interface is operational.",
        "service_version": "1.1-secure-workflow",  # Example version
        "available_encryption_keys_count": num_available_keys_count
    })


# Simple HTML page for the journalist interface (can be expanded)
@app.route(f'{JOURNALIST_INTERFACE_PREFIX}/', methods=['GET'])
def journalist_interface_page():
    # This page would ideally use JavaScript to call the /submissions API endpoint
    # after the journalist enters their API key.
    # For simplicity here, it's just a placeholder.
    # The journalist_gui.py will be the primary way to interact with this API.
    return render_template('journalist_interface.html',
                           api_endpoint_url=url_for('journalist_list_submissions_metadata', _external=True),
                           status_endpoint_url=url_for('journalist_interface_status', _external=True)
                           )


# --- General Health Check ---
@app.route('/health', methods=['GET'])
def health_check():
    # Basic health check, can be expanded (e.g., check DB connection status)
    db_ok = False
    try:
        # A light check, e.g., count keys or try a simple query
        conn = key_manager.get_db_connection()
        if conn:
            conn.close()
            db_ok = True
    except Exception:
        db_ok = False  # Could not connect or query

    return jsonify({
        "status": "ok",
        "service_name": "WhistleDrop Upload & Journalist Interface",
        "database_status": "accessible" if db_ok else "error"
    }), 200


if __name__ == '__main__':
    logger.warning("Running Flask app directly using `python app.py` (SecureDrop-Workflow Edition).")
    logger.warning("This mode is for development testing of Uploads & Journalist Interface ONLY.")
    logger.warning("It does NOT manage Tor hidden services. Use `python utils/tor_manager.py` for full system.")

    ssl_context_to_use = None
    if os.path.exists(Config.SSL_CERT_PATH) and os.path.exists(Config.SSL_KEY_PATH):
        ssl_context_to_use = (Config.SSL_CERT_PATH, Config.SSL_KEY_PATH)
        print(f"INFO: Flask dev server starting with HTTPS on https://{Config.SERVER_HOST}:{Config.FLASK_HTTPS_PORT}")
    else:
        print(
            f"WARNING: SSL certs not found. Flask dev server starting WITHOUT HTTPS on http://{Config.SERVER_HOST}:{Config.FLASK_HTTPS_PORT}")
        print("         This is INSECURE. Generate SSL certs or use tor_manager.py.")

    app.run(
        host=Config.SERVER_HOST, port=Config.FLASK_HTTPS_PORT,
        debug=True, use_reloader=True, ssl_context=ssl_context_to_use
    )