# whistledrop/utils/tor_manager.py
import os
import sys
import logging
import subprocess  # For running Gunicorn
import time
from pathlib import Path

# --- Path Adjustment ---
current_script_path = Path(__file__).resolve()
utils_dir = current_script_path.parent
project_root_dir = utils_dir.parent
if str(project_root_dir) not in sys.path:
    sys.path.insert(0, str(project_root_dir))
# --- End Path Adjustment ---

from stem import Signal
from stem.control import Controller
from whistledrop_server.config import Config
from whistledrop_server import key_manager  # Ensures DB init

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("tor_manager")


def start_whistledrop_web_service_with_tor():
    """
    Manages the startup of WhistleDrop's web services (Flask app via Gunicorn):
    1. Initializes the key database.
    2. Starts Gunicorn for the Flask app (HTTPS for uploads & journalist interface).
    3. Connects to Tor ControlPort and creates an ephemeral hidden service for HTTPS.
       SFTP is no longer part of this managed startup.
    """
    logger.info("WhistleDrop Tor Manager starting web services (SecureDrop-Workflow Edition)...")

    try:
        key_manager.initialize_key_database()
    except Exception as e_db_init:
        logger.critical(f"Failed to initialize key database: {e_db_init}. Aborting.", exc_info=True)
        return

    if not (Path(Config.SSL_CERT_PATH).exists() and Path(Config.SSL_KEY_PATH).exists()):
        logger.error(f"SSL certificate ('{Config.SSL_CERT_PATH}') or key ('{Config.SSL_KEY_PATH}') not found.")
        logger.error("Cannot start HTTPS service. Please generate them as per README.")
        print("Error: SSL certificate/key missing. WhistleDrop cannot start securely. Check logs. Exiting.")
        return

    # Start Gunicorn for Flask app (HTTPS for uploads & journalist interface)
    gunicorn_command = [
        "gunicorn",
        "--bind", f"{Config.SERVER_HOST}:{Config.FLASK_HTTPS_PORT}",
        "--workers", "2",  # Adjust number of workers as needed
        "--certfile", str(Path(Config.SSL_CERT_PATH).resolve()),
        "--keyfile", str(Path(Config.SSL_KEY_PATH).resolve()),
        "whistledrop_server.wsgi:app"  # Points to the Flask app instance
    ]
    logger.info(f"Attempting to start Gunicorn with command: {' '.join(gunicorn_command)}")
    gunicorn_process = None
    try:
        gunicorn_process = subprocess.Popen(gunicorn_command, cwd=project_root_dir)
        logger.info(f"Gunicorn process initiated with PID: {gunicorn_process.pid}. Waiting for startup...")
        time.sleep(3)  # Give Gunicorn a moment to start up and bind.

        if gunicorn_process.poll() is not None:  # Check if Gunicorn exited prematurely
            logger.error(f"Gunicorn failed to start or exited prematurely. Exit code: {gunicorn_process.returncode}")
            print("Error: Gunicorn (web server) failed to start. Check logs above. Aborting.")
            return
        logger.info("Gunicorn (web server) appears to be running.")

    except FileNotFoundError:
        logger.error("Gunicorn command not found. Is Gunicorn installed and in your PATH?", exc_info=True)
        print("Error: Gunicorn not found. Please install Gunicorn (`pip install gunicorn`). Aborting.")
        return
    except Exception as e_gunicorn:
        logger.error(f"Failed to start Gunicorn: {e_gunicorn}", exc_info=True)
        print(f"Error: Failed to start Gunicorn (web server): {e_gunicorn}. Check logs. Aborting.")
        return

    # Connect to Tor ControlPort and set up Hidden Service
    logger.info(f"Attempting to connect to Tor control port {Config.TOR_CONTROL_PORT}...")
    tor_controller = None
    hidden_service_response = None
    try:
        tor_controller = Controller.from_port(port=Config.TOR_CONTROL_PORT)

        if Config.TOR_CONTROL_PASSWORD:
            try:
                tor_controller.authenticate(password=Config.TOR_CONTROL_PASSWORD)
                logger.info("Authenticated to Tor control port using password.")
            except Exception as auth_exc:
                logger.error(f"Password authentication to Tor control port failed: {auth_exc}", exc_info=True)
                if gunicorn_process: gunicorn_process.terminate()
                return
        else:
            try:
                tor_controller.authenticate()
                logger.info("Authenticated to Tor control port (cookie or no auth configured).")
            except Exception as auth_exc:
                logger.warning(f"Cookie/No-auth authentication to Tor control port failed: {auth_exc}")

        # Only HTTPS port is needed for the hidden service in this workflow
        hidden_service_ports_map = {
            443: f"{Config.SERVER_HOST}:{Config.FLASK_HTTPS_PORT}"
        }

        logger.info(
            f"Creating ephemeral Tor hidden service (HTTPS only) with port mappings: {hidden_service_ports_map}...")
        hidden_service_response = tor_controller.create_ephemeral_hidden_service(
            ports=hidden_service_ports_map,
            await_publication=True,
            key_type='ED25519-V3'
        )

        if not hidden_service_response or not hidden_service_response.service_id:
            logger.error("Failed to create Tor hidden service. Response from Tor was invalid or service_id missing.")
            if gunicorn_process: gunicorn_process.terminate()
            return

        onion_address = f"{hidden_service_response.service_id}.onion"
        logger.info("--------------------------------------------------------------------")
        logger.info(f"WhistleDrop Hidden Service successfully created!")
        logger.info(f"ONION ADDRESS (HTTPS): https://{onion_address}")
        logger.info(f"  (Used for Whistleblower Uploads AND Journalist Interface Metadaten-Abruf)")
        logger.info("This hidden service is EPHEMERAL and will be removed when this script exits.")
        logger.info("--------------------------------------------------------------------")
        print(f"\nWhistleDrop is now ACCESSIBLE via Tor Hidden Service:")
        print(f"  ONION ADDRESS (HTTPS): https://{onion_address}")
        print(f"    (For Whistleblower Uploads and Journalist Interface)")
        print(f"\nLocal Gunicorn (HTTPS) running at: https://{Config.SERVER_HOST}:{Config.FLASK_HTTPS_PORT}")
        print("\nPress Ctrl+C to stop all services and remove the ephemeral hidden service.")

        while gunicorn_process.poll() is None:
            time.sleep(1)

        logger.info(f"Gunicorn process ended with exit code: {gunicorn_process.returncode}. Shutting down.")

    except ConnectionRefusedError:
        logger.error(f"Connection to Tor control port {Config.TOR_CONTROL_PORT} refused.")
        logger.error("Ensure Tor is running and its ControlPort is enabled.")
    except Exception as e_tor_setup:
        logger.error(f"An error occurred during Tor hidden service setup: {e_tor_setup}", exc_info=True)
    finally:
        logger.info("Initiating shutdown of WhistleDrop services...")
        if gunicorn_process and gunicorn_process.poll() is None:
            logger.info("Terminating Gunicorn process...")
            gunicorn_process.terminate()
            try:
                gunicorn_process.wait(timeout=10)
                logger.info("Gunicorn process terminated.")
            except subprocess.TimeoutExpired:
                logger.warning("Gunicorn process did not terminate gracefully. Killing.")
                gunicorn_process.kill()

        if tor_controller and tor_controller.is_connected() and hidden_service_response and hidden_service_response.service_id:
            try:
                logger.info(f"Removing ephemeral hidden service: {hidden_service_response.service_id}")
                tor_controller.remove_ephemeral_hidden_service(hidden_service_response.service_id)
                logger.info("Ephemeral hidden service removed.")
            except Exception as e_remove_hs:
                logger.error(f"Failed to remove ephemeral hidden service: {e_remove_hs}", exc_info=True)

        if tor_controller and tor_controller.is_connected():
            tor_controller.close()
            logger.info("Tor controller connection closed.")

        logger.info("WhistleDrop Tor manager script finished.")


if __name__ == "__main__":
    print("--- WhistleDrop Secure Platform - Tor Manager (SecureDrop-Workflow Edition) ---")
    print("This script starts the WhistleDrop web service (HTTPS for Uploads & Journalist Interface)")
    print("and configures it as an ephemeral Tor Hidden Service.")
    print("\nPrerequisites:")
    print(f"  - Tor service running with ControlPort enabled (e.g., 127.0.0.1:{Config.TOR_CONTROL_PORT}).")
    print(f"  - SSL certificate/key in: {Path(Config.CERT_DIR).resolve()}")
    print("\nPress Ctrl+C to stop services and remove the hidden service.\n")

    start_whistledrop_web_service_with_tor()