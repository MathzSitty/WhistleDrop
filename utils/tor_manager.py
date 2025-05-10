# whistledrop/utils/tor_manager.py
import os
import sys
import logging

# --- Path Adjustment ---
# This block ensures that Python can find modules in the parent directory (project root)
# when this script is run directly from the 'utils' subdirectory.
current_script_path = os.path.abspath(__file__)    # Full path to tor_manager.py
utils_dir = os.path.dirname(current_script_path)   # Full path to 'utils' directory
project_root_dir = os.path.dirname(utils_dir)      # Full path to 'whistledrop' directory

# Add the project root to the Python path
if project_root_dir not in sys.path:
    sys.path.insert(0, project_root_dir)
# --- End Path Adjustment ---

# Now, these imports should work because 'whistledrop' (project_root_dir) is in sys.path
from stem import Signal # stem is a third-party library, should be found via venv
from stem.control import Controller
from whistledrop_server.config import Config
from whistledrop_server.app import app as flask_app
# Ensure key_manager is initialized if app doesn't do it early enough for some reason,
# though app import should trigger it.
from whistledrop_server import key_manager # key_manager.initialize_key_database() runs on its import


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("tor_manager")

# ... (Rest of the tor_manager.py script remains the same) ...
def start_whistledrop_with_tor_hidden_service():
    # ... (Funktionsinhalt wie zuvor) ...
    # Example from a previous correct version:
    flask_host = Config.SERVER_HOST
    flask_port = Config.SERVER_PORT
    control_port = Config.TOR_CONTROL_PORT
    control_password = Config.TOR_CONTROL_PASSWORD

    logger.info("Attempting to connect to Tor control port...")
    try:
        with Controller.from_port(port=control_port) as controller:
            # ... (authentication logic) ...
            if control_password:
                try:
                    controller.authenticate(password=control_password)
                    logger.info("Authenticated to Tor control port using password.")
                except Exception as auth_exc:
                    logger.error(f"Password authentication to Tor control port failed: {auth_exc}")
                    # ... (error details) ...
                    return
            else:
                try:
                    controller.authenticate()
                    logger.info("Authenticated to Tor control port (likely cookie or no auth).")
                except Exception as auth_exc:
                    logger.warning(f"Cookie/No-auth authentication to Tor control port failed: {auth_exc}")
                    # ... (error details) ...
                    # For create_ephemeral_hidden_service, authentication is usually required.
                    # If it fails here, the create_ephemeral_hidden_service call will likely also fail.

            logger.info(f"Creating ephemeral hidden service for {flask_host}:{flask_port}...")
            response = controller.create_ephemeral_hidden_service(
                {80: f"{flask_host}:{flask_port}"},
                await_publication=True
            )

            if not response.service_id:
                logger.error("Failed to create hidden service. Tor logs might have more details.")
                return

            onion_address = f"{response.service_id}.onion"
            logger.info("--------------------------------------------------------------------")
            logger.info(f"WhistleDrop Hidden Service ONION ADDRESS: {onion_address}")
            logger.info("This service is EPHEMERAL and will be removed when this script exits.")
            logger.info("--------------------------------------------------------------------")
            print(f"\nWhistleDrop accessible at: {onion_address}\n(Ensure Tor Browser is running)")
            print(f"Also locally at http://{flask_host}:{flask_port} (for direct testing if needed)\n")

            logger.info(f"Starting WhistleDrop server on {flask_host}:{flask_port}...")
            try:
                # Ensure key_manager's DB initialization has run; importing app should do this
                # as app imports modules which import key_manager which calls initialize_key_database()
                if not os.path.exists(Config.KEY_DB_PATH):
                    logger.warning(f"Key database at {Config.KEY_DB_PATH} not found. Attempting to initialize...")
                    key_manager.initialize_key_database()

                flask_app.run(host=flask_host, port=flask_port, debug=False, use_reloader=False)
            except KeyboardInterrupt:
                logger.info("Flask app stopped by user (KeyboardInterrupt).")
            except Exception as flask_e:
                logger.error(f"Flask app crashed: {flask_e}", exc_info=True)
            finally:
                logger.info("Flask app has shut down.")
                logger.info("Tor manager script finished.")
    # ... (rest of exception handling for Tor connection) ...
    except ConnectionRefusedError:
        logger.error(f"Connection to Tor control port {control_port} refused.")
        logger.error("Ensure Tor is running and ControlPort is enabled and listening on the correct address/port.")
    except Exception as e:
        logger.error(f"An error occurred in the Tor manager: {e}", exc_info=True)
        # ... (troubleshooting tips) ...
        print("\nFailed to start with Tor hidden service. Check logs and Tor configuration.")


if __name__ == "__main__":
    # API Key Check (moved from config.py to be more visible when running this script)
    if not Config.JOURNALIST_API_KEY or Config.JOURNALIST_API_KEY.startswith("dev-journalist-api-key-CHANGE-ME") or len(
            Config.JOURNALIST_API_KEY) < 32:
        print("=" * 70)
        print("WARNUNG: WHISTLEDROP_JOURNALIST_API_KEY ist nicht sicher konfiguriert.")
        if not Config.JOURNALIST_API_KEY:
            print("         Die Umgebungsvariable ist NICHT gesetzt.")
        else:
            print(f"         Der aktuelle Wert ist: {Config.JOURNALIST_API_KEY[:10]}...")
        print("         Für den produktiven Betrieb oder persistente Nutzung setzen Sie bitte")
        print("         die Umgebungsvariable 'WHISTLEDROP_JOURNALIST_API_KEY' auf einen langen,")
        print("         zufälligen und geheimen Wert.")
        print("         Ein temporärer API-Key wird für diese Server-Sitzung verwendet, falls")
        print("         die Konfiguration in config.py einen Fallback-Mechanismus hat.")
        # Note: The current config.py generates one if not set, but it will be different each time.
        print("=" * 70)
        # Allow a moment for the user to see the warning
        # time.sleep(3)

    print("Starting WhistleDrop with Tor Hidden Service Management...")
    # ... (rest of the print statements) ...
    print("IMPORTANT: Ensure Tor is installed and running with its control port enabled.")
    print(f"           Default control port used by this script: {Config.TOR_CONTROL_PORT}")
    print("           This script will attempt to create an EPHEMERAL hidden service.")
    print("           Press Ctrl+C to stop the server and remove the hidden service.\n")

    start_whistledrop_with_tor_hidden_service()