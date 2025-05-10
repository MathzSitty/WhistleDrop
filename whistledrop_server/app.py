# whistledrop/whistledrop_server/app.py
import logging
from functools import wraps
from flask import Flask, request, render_template, flash, redirect, url_for, jsonify, send_from_directory, Response
from .config import Config
from . import crypto_utils
from . import key_manager
from . import storage_manager
import threading # New import

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
Config.ensure_dirs_exist()
key_manager.initialize_key_database()

# --- Lock for RSA Key acquisition and marking ---
rsa_key_operation_lock = threading.Lock() # New Lock

# --- Authentication Decorator for Journalist API (remains the same) ---
# ... (decorator code as before) ...
def journalist_api_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"error": "Authorization header missing"}), 401
        
        try:
            auth_type, api_key = auth_header.split(None, 1)
        except ValueError:
            return jsonify({"error": "Invalid Authorization header format. Expected 'Bearer <API_KEY>'"}), 401

        if auth_type.lower() != 'bearer' or api_key != Config.JOURNALIST_API_KEY:
            logger.warning(f"Failed journalist API auth attempt. Provided key: {api_key[:10]}...")
            return jsonify({"error": "Invalid or missing API key"}), 403
        
        return f(*args, **kwargs)
    return decorated_function


@app.route('/', methods=['GET'])
def index():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part in the request.', 'error'); return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected for uploading.', 'error'); return redirect(url_for('index'))

    if file:
        file_data = file.read()
        original_filename = file.filename
        if not file_data:
            flash('Uploaded file is empty.', 'error'); return redirect(url_for('index'))

        logger.info(f"Received file: {original_filename}, size: {len(file_data)} bytes")

        aes_key = crypto_utils.generate_aes_key()
        try:
            encrypted_file_data = crypto_utils.encrypt_aes_gcm(file_data, aes_key)
            encrypted_original_filename = crypto_utils.encrypt_aes_gcm(original_filename.encode('utf-8'), aes_key)
            logger.info("File data and original filename encrypted with AES-GCM.")
        except Exception as e:
            logger.error(f"AES encryption failed: {e}", exc_info=True)
            flash('File encryption failed.', 'error'); return redirect(url_for('index'))
        del file_data

        rsa_public_key_pem = None
        rsa_public_key_id = None
        rsa_public_key_hint_from_db = None
        key_successfully_acquired_and_marked = False

        with rsa_key_operation_lock:
            logger.debug("RSA key lock acquired.")
            key_info_tuple = key_manager.get_available_public_key() # Now returns a 3-tuple
            if not key_info_tuple:
                logger.error("No available RSA public keys inside lock.")
            else:
                rsa_public_key_pem, rsa_public_key_id, rsa_public_key_hint_from_db = key_info_tuple # Unpack hint
                if key_manager.mark_key_as_used(rsa_public_key_id):
                    logger.info(f"RSA public key ID {rsa_public_key_id} (Hint: {rsa_public_key_hint_from_db}) acquired and marked.")
                    key_successfully_acquired_and_marked = True
                else:
                    # This case means the key was likely used by another thread between get and mark,
                    # or DB error. The lock should prevent the former if get_available_public_key
                    # doesn't have internal race conditions for selection.
                    logger.error(f"Failed to mark RSA key ID {rsa_public_key_id} as used immediately after acquiring. Potential contention or DB issue.")
                    rsa_public_key_pem = None # Do not use this key
                    rsa_public_key_id = None  # Do not use this key
            logger.debug("RSA key lock released.")


        if not key_successfully_acquired_and_marked or not rsa_public_key_pem:
            del aes_key; del encrypted_file_data; del encrypted_original_filename
            flash('Server error: No encryption keys available or key contention. Please try again.', 'error'); return redirect(url_for('index'))
        
        try:
            encrypted_aes_key = crypto_utils.encrypt_rsa(aes_key, rsa_public_key_pem)
        except Exception as e:
            logger.error(f"RSA encryption of AES key failed: {e}", exc_info=True)
            # Since key was marked used, this is problematic. Ideally, un-mark it or flag for admin.
            # For now, we proceed to fail the upload.
            logger.critical(f"RSA encryption failed for key ID {rsa_public_key_id} which was already marked as used. Manual review may be needed for this key.")
            del aes_key; del encrypted_file_data; del encrypted_original_filename
            flash('Server error: Failed to secure encryption key.', 'error'); return redirect(url_for('index'))
        del aes_key

        submission_id = storage_manager.save_submission(
            encrypted_file_data,
            encrypted_aes_key,
            rsa_public_key_id,
            encrypted_original_filename,
            rsa_public_key_hint_from_db
        )
        del encrypted_file_data; del encrypted_aes_key; del encrypted_original_filename
        
        if submission_id:
            # Key was already marked as used within the lock
            logger.info(f"Submission ID: {submission_id}")
            flash(f'File uploaded securely! Submission ID: {submission_id}', 'success')
        else:
            logger.error("Failed to save submission to storage.")
            # If storage fails, the RSA key is still marked used. This is a "cost" but safer than reusing keys.
            flash('Server error: Failed to save submission.', 'error')
        
        return redirect(url_for('index'))

    flash('An unexpected error occurred.', 'error'); return redirect(url_for('index'))

# --- Journalist Endpoints ---
# ... (rest of app.py as before) ...
@app.route('/journalist/submissions', methods=['GET'])
@journalist_api_required
def list_all_submissions():
    submission_ids = storage_manager.list_submissions()
    submissions_with_hints = []
    for sub_id_str in submission_ids:
        data_package = storage_manager.get_submission_data(sub_id_str)
        hint_to_display = "N/A"
        if data_package:
            try:
                # Correct unpacking for 5 elements
                _enc_file, _enc_aes_key, _rsa_id, _enc_filename, rsa_hint_from_storage = data_package
                if rsa_hint_from_storage:
                    hint_to_display = rsa_hint_from_storage
            except ValueError as ve:
                logger.error(f"ValueError unpacking data_package in list_all_submissions for ID '{sub_id_str}': {ve}")
                # Continue, but this submission might have an issue or old format
        submissions_with_hints.append({"id": sub_id_str, "key_hint": hint_to_display})

    return jsonify({"submissions": submissions_with_hints})


@app.route('/journalist/submission/<submission_id>/package', methods=['GET'])
@journalist_api_required
def get_submission_package_details(submission_id):
    data_package = storage_manager.get_submission_data(submission_id)
    if not data_package:
        return jsonify({"error": "Submission not found"}), 404

    # Ensure this unpacking is also for 5 items
    try:
        _enc_file, _enc_aes, rsa_public_key_id_on_server, _enc_fname, rsa_key_hint = data_package
    except ValueError as ve:
        logger.error(f"ValueError unpacking data_package in /package for submission '{submission_id}': {ve}")
        return jsonify({"error": "Internal server error: data format issue"}), 500

    return jsonify({
        "submission_id": submission_id,
        "rsa_public_key_id_on_server": rsa_public_key_id_on_server,
        "rsa_public_key_hint": rsa_key_hint,  # Make sure this is being sent
        "encrypted_file_url": url_for('download_encrypted_component', submission_id=submission_id, component='file',
                                      _external=True),
        "encrypted_aes_key_url": url_for('download_encrypted_component', submission_id=submission_id, component='key',
                                         _external=True),
        "encrypted_filename_url": url_for('download_encrypted_component', submission_id=submission_id,
                                          component='filename', _external=True),
    })


@app.route('/journalist/submission/<submission_id>/<component>', methods=['GET'])
@journalist_api_required
def download_encrypted_component(submission_id, component):
    logger.debug(f"Request to download component '{component}' for submission '{submission_id}'")
    data_package = storage_manager.get_submission_data(submission_id)  # Returns 5 items now

    if not data_package:
        logger.warning(
            f"Submission data not found for ID '{submission_id}' when trying to download component '{component}'.")
        return jsonify({"error": "Submission not found"}), 404

    # ---- CORRECTED UNPACKING: Expect 5 items ----
    try:
        encrypted_file_data, encrypted_aes_key_data, _rsa_id, encrypted_original_filename, _rsa_hint = data_package
        # We use _rsa_id and _rsa_hint to acknowledge they exist, even if not used in this specific function.
    except ValueError as ve:
        logger.error(f"ValueError during unpacking data_package for submission '{submission_id}': {ve}")
        logger.error(f"Data package received was: {data_package}")  # Log what was actually received
        return jsonify({"error": "Internal server error: data format mismatch"}), 500
    # ---- END CORRECTED UNPACKING ----

    content_to_send = None
    download_name = "encrypted_data.dat"  # Default download name

    if component == 'file':
        content_to_send = encrypted_file_data
        download_name = "encrypted_file.dat"
        logger.debug(f"Serving encrypted_file.dat for submission {submission_id}")
    elif component == 'key':
        content_to_send = encrypted_aes_key_data
        download_name = "encrypted_aes_key.dat"
        logger.debug(f"Serving encrypted_aes_key.dat for submission {submission_id}")
    elif component == 'filename':
        content_to_send = encrypted_original_filename
        download_name = "encrypted_filename.dat"
        logger.debug(f"Serving encrypted_filename.dat for submission {submission_id}")
    else:
        logger.warning(f"Invalid component '{component}' requested for submission {submission_id}")
        return jsonify({"error": "Invalid component requested"}), 400

    if content_to_send is None:  # Should not happen if component is valid
        logger.error(
            f"Content to send is None for component '{component}', submission {submission_id}. This is unexpected.")
        return jsonify({"error": "Internal server error: component data missing"}), 500

    return Response(
        content_to_send,
        mimetype='application/octet-stream',
        headers={"Content-Disposition": f"attachment;filename={download_name}"}
    )


@app.route('/journalist/admin/add-public-keys', methods=['POST'])
@journalist_api_required
def batch_add_public_keys():
    if not request.is_json:
        return jsonify({"error": "Invalid request: payload must be JSON"}), 400

    data = request.get_json()
    public_key_objects = data.get('public_keys')

    if not isinstance(public_key_objects, list) or not public_key_objects:
        return jsonify({"error": "Invalid payload: 'public_keys' must be a non-empty list of objects"}), 400

    results = []
    success_count = 0
    failure_count = 0

    for key_obj in public_key_objects:  # key_obj should be {"pem": "...", "hint": "..."}
        pem_string = key_obj.get('pem')
        hint_string_from_payload = key_obj.get('hint')  # This is the hint extracted by the GUI

        # CRITICAL LOGGING: What hint does this endpoint extract from the payload?
        logger.info(
            f"APP.PY BATCH_ADD_PUBLIC_KEYS: Processing key. PEM starts: {str(pem_string)[:40]}, HINT from payload: '{hint_string_from_payload}'")

        if not isinstance(pem_string, str) or not pem_string.strip().startswith("-----BEGIN PUBLIC KEY-----"):
            results.append({"key_preview": str(pem_string)[:30] + "...", "status": "failed",
                            "reason": "Invalid format or not a public key PEM"})
            failure_count += 1
            continue

        # This hint_string_from_payload is passed to key_manager.add_public_key
        if key_manager.add_public_key(pem_string, identifier_hint=hint_string_from_payload):
            results.append({"key_preview": str(pem_string)[:30] + "...", "status": "success",
                            "reason": f"Added to database (Hint: {hint_string_from_payload})"})
            success_count += 1
        else:
            results.append({"key_preview": str(pem_string)[:30] + "...", "status": "failed",
                            "reason": f"Not added (Hint: {hint_string_from_payload}) - likely duplicate, invalid, or DB error"})
            failure_count += 1

    logger.info(f"Batch add public keys request: {success_count} succeeded, {failure_count} failed.")
    return jsonify({
        "message": f"Processed {len(public_key_objects)} keys.",
        "success_count": success_count,
        "failure_count": failure_count,
        "details": results
    }), 200


if __name__ == '__main__':
    app.run(host=Config.SERVER_HOST, port=Config.SERVER_PORT, debug=False, use_reloader=False)