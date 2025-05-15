# whistledrop/utils/tor_manager.py
import os
import sys
import logging
import time

# --- Path Adjustment ---
current_script_path = os.path.abspath(__file__)
utils_dir = os.path.dirname(current_script_path)
project_root_dir = os.path.dirname(utils_dir)

if project_root_dir not in sys.path:
    sys.path.insert(0, project_root_dir)
# --- End Path Adjustment ---

from stem import Signal
from stem.control import Controller
from whistledrop_server.config import Config
from whistledrop_server.app import app as flask_app
from whistledrop_server import key_manager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("tor_manager")

# --- GLOBAL CONFIGURATION FOR TESTING ---
# Set this to False to make the Hidden Service point to a local HTTP target (e.g., Flask on port 5000)
# Set this to True to make the Hidden Service point to a local HTTPS target (e.g., Flask on port 5001)
USE_LOCAL_HTTPS_TARGET = False  # << CHANGE THIS TO True FOR NORMAL HTTPS OPERATION


# ------------------------------------

def start_whistledrop_with_tor_hidden_service():
    # USE_LOCAL_HTTPS_TARGET wird jetzt global gelesen

    flask_host = Config.SERVER_HOST

    ssl_context_for_flask = None
    local_target_port = Config.SERVER_PORT  # Default to HTTP port
    local_target_protocol = "http"

    if USE_LOCAL_HTTPS_TARGET:
        if os.path.exists(Config.SSL_CERT_PATH) and os.path.exists(Config.SSL_KEY_PATH):
            local_target_protocol = "https"
            local_target_port = Config.SERVER_HTTPS_PORT  # e.g., 5001
            ssl_context_for_flask = (Config.SSL_CERT_PATH, Config.SSL_KEY_PATH)
            logger.info(f"Flask will run with SSL on port {local_target_port} and be the HS target.")
        else:
            logger.error(
                f"USE_LOCAL_HTTPS_TARGET is True, but SSL certificates not found at {Config.SSL_CERT_PATH} or {Config.SSL_KEY_PATH}.")
            logger.error(
                "Cannot start with HTTPS target. Please generate certs or set USE_LOCAL_HTTPS_TARGET to False.")
            return
    else:  # USE_LOCAL_HTTPS_TARGET is False
        local_target_protocol = "http"
        local_target_port = Config.SERVER_PORT  # e.g., 5000
        ssl_context_for_flask = None  # Flask runs on HTTP
        logger.info(
            f"Flask will run with HTTP on port {local_target_port} and be the HS target (USE_LOCAL_HTTPS_TARGET is False).")

    control_port = Config.TOR_CONTROL_PORT
    control_password = Config.TOR_CONTROL_PASSWORD

    logger.info(f"Attempting to connect to Tor control port {control_port}...")
    try:
        with Controller.from_port(port=control_port) as controller:
            if control_password:
                try:
                    controller.authenticate(password=control_password)
                    logger.info("Authenticated to Tor control port using password.")
                except Exception as auth_exc:
                    logger.error(f"Password authentication to Tor control port failed: {auth_exc}")
                    logger.error(
                        "Ensure TOR_CONTROL_PASSWORD env var is correct or Tor is configured for no auth/cookie auth.")
                    return
            else:
                try:
                    controller.authenticate()
                    logger.info("Authenticated to Tor control port (cookie or no auth).")
                except Exception as auth_exc:
                    logger.warning(
                        f"Cookie/No-auth to Tor control port failed: {auth_exc}. This might prevent service creation if auth is strictly required by Tor.")

            logger.info(
                f"Creating ephemeral hidden service for local target: {local_target_protocol}://{flask_host}:{local_target_port}...")

            response = controller.create_ephemeral_hidden_service(
                {80: f"{flask_host}:{local_target_port}"},
                await_publication=True,
            )

            if not response or not response.service_id:
                logger.error("Failed to create hidden service. Tor logs might have more details.")
                logger.error("Ensure Tor is running, ControlPort is accessible, and Tor can create services.")
                if response: logger.error(f"Tor response details: {response}")
                return

            onion_address = f"http://{response.service_id}.onion"

            logger.info("--------------------------------------------------------------------")
            logger.info(f"WhistleDrop Hidden Service ONION ADDRESS: {onion_address}")
            logger.info(
                f"(Service forwards from its port 80 to local: {local_target_protocol}://{flask_host}:{local_target_port})")
            logger.info("This service is EPHEMERAL and will be removed when this script exits.")
            logger.info("--------------------------------------------------------------------")
            print(f"\nWhistleDrop accessible at: {onion_address}")
            print(f"(Ensure Tor Browser is running and can connect to new .onion addresses)")
            print(f"Flask server running locally at: {local_target_protocol}://{flask_host}:{local_target_port}\n")

            logger.info(
                f"Starting WhistleDrop (Flask) server on {flask_host}:{local_target_port} (Protocol: {local_target_protocol.upper()})...")
            try:
                if not os.path.exists(Config.KEY_DB_PATH):
                    logger.warning(f"Key database at {Config.KEY_DB_PATH} not found. Attempting to initialize...")
                    key_manager.initialize_key_database()

                flask_app.run(
                    host=flask_host,
                    port=local_target_port,
                    debug=False,
                    use_reloader=False,
                    ssl_context=ssl_context_for_flask
                )
            except KeyboardInterrupt:
                logger.info("Flask app (run by tor_manager) stopped by user (KeyboardInterrupt).")
            except Exception as flask_e:
                logger.error(f"Flask app (run by tor_manager) crashed: {flask_e}", exc_info=True)
            finally:
                logger.info("Flask app (run by tor_manager) has shut down.")
                logger.info("Tor manager script finished. Ephemeral hidden service is being removed by Tor.")

    except ConnectionRefusedError:
        logger.error(f"Connection to Tor control port {control_port} refused.")
        logger.error(
            "Ensure Tor (Standalone Tor or Tor Browser with ControlPort enabled) is running and ControlPort is configured correctly in torrc.")
        logger.error(
            f"Expected ControlPort: {control_port}. Check for 'ControlPort {control_port}' and 'CookieAuthentication 1' in your torrc.")
    except Exception as e:
        logger.error(f"An error occurred in the Tor manager: {e}", exc_info=True)
        print("\nFailed to start WhistleDrop with Tor hidden service. Check logs and Tor configuration.")
        print(
            "Common issues: Tor not running, ControlPort misconfigured, permissions issues for Tor, stem library issues.")


if __name__ == "__main__":
    print("Starting WhistleDrop with Tor Hidden Service Management...")
    print("IMPORTANT: Ensure your Standalone Tor service is running and configured with:")
    print(f"           ControlPort {Config.TOR_CONTROL_PORT}")
    print(f"           CookieAuthentication 1")
    print(f"           (And that it has successfully bootstrapped to 100%)")

    # USE_LOCAL_HTTPS_TARGET ist jetzt global definiert
    if USE_LOCAL_HTTPS_TARGET:
        if os.path.exists(Config.SSL_CERT_PATH) and os.path.exists(Config.SSL_KEY_PATH):
            print(
                f"           Mode: Hidden Service will target local HTTPS Flask server on port {Config.SERVER_HTTPS_PORT}.")
        else:
            # Dieser Fall sollte durch die Logik in start_whistledrop_with_tor_hidden_service abgefangen werden,
            # aber eine zusätzliche Warnung hier schadet nicht.
            print(
                f"           ERROR: Mode set to HTTPS target, but SSL certs not found at {Config.SSL_CERT_PATH} or {Config.SSL_KEY_PATH}.")
            print(
                f"                  Please generate SSL certificates or set USE_LOCAL_HTTPS_TARGET to False in the script.")
            sys.exit(1)  # Beenden, da die Konfiguration inkonsistent ist
    else:
        print(f"           Mode: Hidden Service will target local HTTP Flask server on port {Config.SERVER_PORT}.")

    print("           This script will attempt to create an EPHEMERAL hidden service.")
    print("           Press Ctrl+C to stop the Flask server and remove the hidden service.\n")

    try:
        conn = key_manager.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM journalists")
        count = cursor.fetchone()[0]
        conn.close()
        if count == 0:
            print("=" * 70)
            print("WARNING: No journalist accounts found in the database.")
            print("         You will not be able to log in to the journalist interface.")
            print("         Run 'python utils/create_journalist_account.py' to create one.")
            print("=" * 70)
            time.sleep(2)
    except Exception as e:
        logger.error(f"Could not check for journalist accounts: {e}")
        print("WARNING: Could not verify journalist accounts in the database. Login might fail.")

    start_whistledrop_with_tor_hidden_service()