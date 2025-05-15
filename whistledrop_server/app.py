# whistledrop/whistledrop_server/app.py
import logging
import os
import threading
from flask import Flask, request, render_template, flash, redirect, url_for, jsonify, Response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash

from .config import Config
from . import crypto_utils
from . import key_manager
from . import storage_manager
from .models import Journalist # New import for Journalist model

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
Config.ensure_dirs_exist() # Ensures data/ and certs/ dirs exist
# key_manager.initialize_key_database() is called on import of key_manager

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Route name for the login page
login_manager.login_message_category = "info" # Flash message category

@login_manager.user_loader
def load_user(user_id):
    """Flask-Login user loader callback."""
    return Journalist.get(int(user_id))

# --- Lock for RSA Key acquisition and marking (remains the same) ---
rsa_key_operation_lock = threading.Lock()

# --- Routes ---

@app.route('/', methods=['GET'])
def index():
    """Serves the whistleblower upload page."""
    return render_template('upload.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles journalist login."""
    if current_user.is_authenticated:
        return redirect(url_for('list_all_submissions')) # Or a journalist dashboard

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password are required.', 'error')
            return redirect(url_for('login'))

        journalist_db_data = key_manager.get_journalist_by_username(username)

        if journalist_db_data and check_password_hash(journalist_db_data['password_hash'], password):
            journalist_obj = Journalist(id=journalist_db_data['id'], username=journalist_db_data['username'])
            login_user(journalist_obj) # Create session
            logger.info(f"Journalist '{username}' logged in successfully.")
            # Redirect to a more appropriate page, e.g., submissions list
            next_page = request.args.get('next')
            return redirect(next_page or url_for('list_all_submissions'))
        else:
            logger.warning(f"Failed login attempt for username: '{username}'.")
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@login_required # Ensures only logged-in users can access this
def logout():
    """Handles journalist logout."""
    logger.info(f"Journalist '{current_user.username}' logging out.")
    logout_user() # Clear session
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/upload', methods=['POST'])
def upload_file():
    # This route is for whistleblowers and does not require login.
    # Logic remains largely the same as before.
    if 'file' not in request.files:
        flash('No file part in the request.', 'error');
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected for uploading.', 'error');
        return redirect(url_for('index'))

    if file:
        file_data = file.read()
        original_filename = file.filename
        if not file_data:
            flash('Uploaded file is empty.', 'error');
            return redirect(url_for('index'))

        # Check file size against MAX_CONTENT_LENGTH
        if len(file_data) > app.config['MAX_CONTENT_LENGTH']:
            flash(f"File exceeds maximum allowed size of {app.config['MAX_UPLOAD_SIZE_MB']} MB.", 'error')
            logger.warning(f"Upload rejected: File '{original_filename}' too large ({len(file_data)} bytes).")
            return redirect(url_for('index'))

        logger.info(f"Received file: {original_filename}, size: {len(file_data)} bytes")

        aes_key = crypto_utils.generate_aes_key()
        try:
            encrypted_file_data = crypto_utils.encrypt_aes_gcm(file_data, aes_key)
            encrypted_original_filename = crypto_utils.encrypt_aes_gcm(original_filename.encode('utf-8'), aes_key)
            logger.info("File data and original filename encrypted with AES-GCM.")
        except Exception as e:
            logger.error(f"AES encryption failed: {e}", exc_info=True)
            flash('File encryption failed on server.', 'error');
            return redirect(url_for('index'))
        del file_data # Free memory

        rsa_public_key_pem = None
        rsa_public_key_id = None
        rsa_public_key_hint_from_db = None
        key_successfully_acquired_and_marked = False

        with rsa_key_operation_lock:
            logger.debug("RSA key lock acquired for upload.")
            key_info_tuple = key_manager.get_available_public_key()
            if not key_info_tuple:
                logger.error("No available RSA public keys inside lock during upload.")
            else:
                rsa_public_key_pem, rsa_public_key_id, rsa_public_key_hint_from_db = key_info_tuple
                if key_manager.mark_key_as_used(rsa_public_key_id):
                    logger.info(
                        f"RSA public key ID {rsa_public_key_id} (Hint: {rsa_public_key_hint_from_db}) acquired and marked for upload.")
                    key_successfully_acquired_and_marked = True
                else:
                    logger.error(
                        f"Failed to mark RSA key ID {rsa_public_key_id} as used (upload). Potential contention or DB issue.")
                    rsa_public_key_pem = None
                    rsa_public_key_id = None
            logger.debug("RSA key lock released (upload).")

        if not key_successfully_acquired_and_marked or not rsa_public_key_pem:
            del aes_key; del encrypted_file_data; del encrypted_original_filename
            flash('Server error: Could not secure an encryption key. Please try again later.', 'error');
            return redirect(url_for('index'))

        try:
            encrypted_aes_key = crypto_utils.encrypt_rsa(aes_key, rsa_public_key_pem)
        except Exception as e:
            logger.error(f"RSA encryption of AES key failed (upload): {e}", exc_info=True)
            logger.critical(
                f"RSA encryption failed for key ID {rsa_public_key_id} (upload), already marked used. Manual review needed.")
            del aes_key; del encrypted_file_data; del encrypted_original_filename
            flash('Server error: Failed to secure encryption key components.', 'error');
            return redirect(url_for('index'))
        del aes_key # Free memory

        submission_id = storage_manager.save_submission(
            encrypted_file_data,
            encrypted_aes_key,
            rsa_public_key_id,
            encrypted_original_filename,
            rsa_public_key_hint_from_db # Pass the hint to storage
        )
        del encrypted_file_data; del encrypted_aes_key; del encrypted_original_filename # Free memory

        if submission_id:
            logger.info(f"Submission successful. ID: {submission_id}")
            flash(f'File uploaded securely! Submission ID: {submission_id}', 'success')
        else:
            logger.error("Failed to save submission to storage after encryption.")
            flash('Server error: Failed to save submission after processing.', 'error')

        return redirect(url_for('index'))

    flash('An unexpected error occurred during upload.', 'error');
    return redirect(url_for('index'))


# --- Journalist Endpoints (Now require login via @login_required) ---

@app.route('/journalist/submissions', methods=['GET'])
@login_required # Replaces the old API key decorator
def list_all_submissions():
    logger.info(f"Journalist '{current_user.username}' requested submissions list.")
    submission_ids = storage_manager.list_submissions()
    submissions_with_hints = []
    for sub_id_str in submission_ids:
        # get_submission_data returns a 5-tuple: (enc_file, enc_aes_key, rsa_id, enc_filename, rsa_hint)
        data_package = storage_manager.get_submission_data(sub_id_str)
        hint_to_display = "N/A"
        if data_package and len(data_package) == 5:
            rsa_hint_from_storage = data_package[4] # Fifth element is the hint
            if rsa_hint_from_storage:
                hint_to_display = rsa_hint_from_storage
        elif data_package: # Old format or error
             logger.warning(f"Unexpected data_package format for submission '{sub_id_str}' in list_all_submissions. Length: {len(data_package)}")
        submissions_with_hints.append({"id": sub_id_str, "key_hint": hint_to_display})
    return jsonify({"submissions": submissions_with_hints})


@app.route('/journalist/submission/<submission_id>/package', methods=['GET'])
@login_required
def get_submission_package_details(submission_id):
    logger.info(f"Journalist '{current_user.username}' requested package details for submission: {submission_id}")
    data_package = storage_manager.get_submission_data(submission_id)
    if not data_package or len(data_package) != 5:
        logger.warning(f"Submission package not found or malformed for ID '{submission_id}'.")
        return jsonify({"error": "Submission not found or data error"}), 404

    _enc_file, _enc_aes, rsa_public_key_id_on_server, _enc_fname, rsa_key_hint = data_package

    return jsonify({
        "submission_id": submission_id,
        "rsa_public_key_id_on_server": rsa_public_key_id_on_server,
        "rsa_public_key_hint": rsa_key_hint,
        "encrypted_file_url": url_for('download_encrypted_component', submission_id=submission_id, component='file', _external=True),
        "encrypted_aes_key_url": url_for('download_encrypted_component', submission_id=submission_id, component='key', _external=True),
        "encrypted_filename_url": url_for('download_encrypted_component', submission_id=submission_id, component='filename', _external=True),
    })


@app.route('/journalist/submission/<submission_id>/<component>', methods=['GET'])
@login_required
def download_encrypted_component(submission_id, component):
    logger.info(f"Journalist '{current_user.username}' requested component '{component}' for submission: {submission_id}")
    data_package = storage_manager.get_submission_data(submission_id)

    if not data_package or len(data_package) != 5:
        logger.warning(f"Submission data not found/malformed for ID '{submission_id}' (component: {component}).")
        return jsonify({"error": "Submission not found or data error"}), 404

    encrypted_file_data, encrypted_aes_key_data, _rsa_id, encrypted_original_filename, _rsa_hint = data_package

    content_to_send = None
    download_name = "encrypted_data.dat"

    if component == 'file':
        content_to_send = encrypted_file_data
        download_name = f"{submission_id}_encrypted_file.dat"
    elif component == 'key':
        content_to_send = encrypted_aes_key_data
        download_name = f"{submission_id}_encrypted_aes_key.dat"
    elif component == 'filename':
        content_to_send = encrypted_original_filename
        download_name = f"{submission_id}_encrypted_filename.dat"
    else:
        logger.warning(f"Invalid component '{component}' requested by '{current_user.username}' for submission {submission_id}")
        return jsonify({"error": "Invalid component requested"}), 400

    if content_to_send is None:
        logger.error(f"Content to send is None for component '{component}', submission {submission_id}. This is unexpected.")
        return jsonify({"error": "Internal server error: component data missing"}), 500

    logger.debug(f"Serving '{download_name}' for submission {submission_id} to '{current_user.username}'")
    return Response(
        content_to_send,
        mimetype='application/octet-stream',
        headers={"Content-Disposition": f"attachment;filename={download_name}"}
    )


@app.route('/journalist/admin/add-public-keys', methods=['POST'])
@login_required
def batch_add_public_keys():
    logger.info(f"Journalist '{current_user.username}' attempting to batch add public keys.")
    if not request.is_json:
        return jsonify({"error": "Invalid request: payload must be JSON"}), 400

    data = request.get_json()
    public_key_objects = data.get('public_keys')

    if not isinstance(public_key_objects, list) or not public_key_objects:
        return jsonify({"error": "Invalid payload: 'public_keys' must be a non-empty list of objects"}), 400

    results = []
    success_count = 0
    failure_count = 0

    for key_obj in public_key_objects:
        pem_string = key_obj.get('pem')
        hint_string_from_payload = key_obj.get('hint')

        logger.info(
            f"Processing key for batch add. PEM: {str(pem_string)[:40]}..., Hint: '{hint_string_from_payload}'")

        if not isinstance(pem_string, str) or not pem_string.strip().startswith("-----BEGIN PUBLIC KEY-----"):
            results.append({"key_preview": str(pem_string)[:30] + "...", "status": "failed",
                            "reason": "Invalid format or not a public key PEM"})
            failure_count += 1
            continue

        if key_manager.add_public_key(pem_string, identifier_hint=hint_string_from_payload):
            results.append({"key_preview": str(pem_string)[:30] + "...", "status": "success",
                            "reason": f"Added to database (Hint: {hint_string_from_payload})"})
            success_count += 1
        else:
            results.append({"key_preview": str(pem_string)[:30] + "...", "status": "failed",
                            "reason": f"Not added (Hint: {hint_string_from_payload}) - likely duplicate or invalid"})
            failure_count += 1

    logger.info(f"Batch add public keys by '{current_user.username}': {success_count} succeeded, {failure_count} failed.")
    return jsonify({
        "message": f"Processed {len(public_key_objects)} keys.",
        "success_count": success_count,
        "failure_count": failure_count,
        "details": results
    }), 200


if __name__ == '__main__':
    # For development, run with SSL if certs exist.
    # For production with Gunicorn, Gunicorn handles SSL.
    # tor_manager.py will also need to be aware of HTTPS.
    ssl_context = None
    if os.path.exists(Config.SSL_CERT_PATH) and os.path.exists(Config.SSL_KEY_PATH):
        ssl_context = (Config.SSL_CERT_PATH, Config.SSL_KEY_PATH)
        logger.info(f"SSL context loaded. Starting HTTPS server on port {Config.SERVER_HTTPS_PORT}.")
        # Run on HTTPS port if SSL is available
        app.run(host=Config.SERVER_HOST, port=Config.SERVER_HTTPS_PORT, debug=False, use_reloader=False, ssl_context=ssl_context)
    else:
        logger.warning(f"SSL certificate or key not found at {Config.SSL_CERT_PATH} / {Config.SSL_KEY_PATH}.")
        logger.warning("Starting HTTP server for development on port {Config.SERVER_PORT}. NOT SUITABLE FOR PRODUCTION.")
        # Fallback to HTTP if SSL certs are not found (for easier initial dev setup)
        app.run(host=Config.SERVER_HOST, port=Config.SERVER_PORT, debug=False, use_reloader=False)