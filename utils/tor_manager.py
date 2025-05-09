# whistledrop/utils/tor_manager.py
import subprocess
import time
import logging
import os # New import
import sys # New import

# --- Path Adjustment ---
# Ensure the script can find whistledrop_server and other project modules
# when run directly from the 'utils' directory.
current_dir = os.path.dirname(os.path.abspath(__file__)) # antons_utils/utils
project_root = os.path.dirname(current_dir) # antons_utils/
sys.path.insert(0, project_root) # Add project_root to the beginning of sys.path
# --- End Path Adjustment ---


from stem import Signal
from stem.control import Controller
# Now these imports should work:
from whistledrop_server.config import Config 
from whistledrop_server.app import app as flask_app 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("tor_manager")

# ... (Rest of the tor_manager.py script remains the same) ...
def start_whistledrop_with_tor_hidden_service():
    """
    Attempts to create an ephemeral Tor hidden service and then starts the WhistleDrop Flask app.
    Requires Tor to be running and its control port configured and accessible.
    """
    flask_host = Config.SERVER_HOST
    flask_port = Config.SERVER_PORT
    control_port = Config.TOR_CONTROL_PORT
    control_password = Config.TOR_CONTROL_PASSWORD # Can be None if using cookie auth or no auth

    logger.info("Attempting to connect to Tor control port...")
    try:
        with Controller.from_port(port=control_port) as controller:
            if control_password: # Only try to authenticate with password if one is provided
                try:
                    controller.authenticate(password=control_password)
                    logger.info("Authenticated to Tor control port using password.")
                except Exception as auth_exc:
                    logger.error(f"Password authentication to Tor control port failed: {auth_exc}")
                    logger.error("Ensure TOR_CONTROL_PASSWORD is set correctly if your control port is password-protected.")
                    logger.error("If using CookieAuthentication, ensure TOR_CONTROL_PASSWORD is NOT set or is empty.")
                    return
            else: # Try cookie or no authentication
                try:
                    controller.authenticate() 
                    logger.info("Authenticated to Tor control port (likely cookie or no auth).")
                except Exception as auth_exc:
                    logger.warning(f"Cookie/No-auth authentication to Tor control port failed: {auth_exc}")
                    logger.warning("If your control port is password-protected, set TOR_CONTROL_PASSWORD env var.")
                    # Depending on Tor config, failing to auth might still allow some operations, or not.
                    # For create_ephemeral_hidden_service, authentication is usually required.
                    # If it proceeds and fails later, the error will be caught.

            
            logger.info(f"Creating ephemeral hidden service for {flask_host}:{flask_port}...")
            # Ensure we wait for publication for reliability
            response = controller.create_ephemeral_hidden_service(
                {80: f"{flask_host}:{flask_port}"}, 
                await_publication=True,
                # detach=True # Detach=True could be useful if you want the service to persist after script exits, 
                              # but then you'd need a way to remove it. For ephemeral, detach=False (default) is fine.
            ) 
            
            if not response.service_id:
                logger.error("Failed to create hidden service. Tor logs might have more details.")
                logger.error("Ensure Tor is running, ControlPort is accessible and authenticated.")
                return

            onion_address = f"{response.service_id}.onion"
            logger.info("--------------------------------------------------------------------")
            logger.info(f"WhistleDrop Hidden Service ONION ADDRESS: {onion_address}")
            logger.info("This service is EPHEMERAL and will be removed when this script exits.")
            logger.info("--------------------------------------------------------------------")
            print(f"\nWhistleDrop accessible at: {onion_address}\n(Ensure Tor Browser is running and can connect to new .onion addresses)")
            print(f"Also locally at http://{flask_host}:{flask_port} (for direct testing if needed)\n")


            logger.info(f"Starting WhistleDrop server on {flask_host}:{flask_port}...")
            try:
                # Run Flask app. debug=False and use_reloader=False are important when managed by stem.
                flask_app.run(host=flask_host, port=flask_port, debug=False, use_reloader=False)
            except KeyboardInterrupt:
                logger.info("Flask app stopped by user (KeyboardInterrupt).")
            except Exception as flask_e:
                logger.error(f"Flask app crashed: {flask_e}", exc_info=True)
            finally:
                logger.info("Flask app has shut down.")
                # The ephemeral hidden service is automatically removed when the controller connection is closed (i.e., 'with' block exits).
                # Explicit removal is usually not needed for ephemeral services managed this way.
                # if response and response.service_id:
                #    try:
                #        controller.remove_ephemeral_hidden_service(response.service_id)
                #        logger.info(f"Successfully removed ephemeral hidden service: {response.service_id}")
                #    except Exception as remove_e:
                #        logger.error(f"Error removing ephemeral hidden service {response.service_id}: {remove_e}")
                logger.info("Tor manager script finished.")

    except ConnectionRefusedError:
        logger.error(f"Connection to Tor control port {control_port} refused.")
        logger.error("Ensure Tor is running and ControlPort is enabled and listening on the correct address/port.")
    except Exception as e:
        logger.error(f"An error occurred in the Tor manager: {e}", exc_info=True)
        logger.error("Troubleshooting tips:")
        logger.error("  - Is Tor running?")
        logger.error(f"  - Is ControlPort {control_port} enabled in torrc and accessible?")
        logger.error("  - If password protected, is TOR_CONTROL_PASSWORD env var set correctly?")
        logger.error("  - If using CookieAuthentication, can this script access the auth cookie file?")
        print("\nFailed to start with Tor hidden service. Check logs and Tor configuration.")

if __name__ == "__main__":
    print("Starting WhistleDrop with Tor Hidden Service Management...")
    print("IMPORTANT: Ensure Tor is installed and running with its control port enabled.")
    print(f"           Default control port used by this script: {Config.TOR_CONTROL_PORT}")
    print("           This script will attempt to create an EPHEMERAL hidden service.")
    print("           Press Ctrl+C to stop the server and remove the hidden service.\n")
    start_whistledrop_with_tor_hidden_service()