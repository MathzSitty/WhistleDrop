# whistledrop/utils/tor_manager.py
import os
import sys
import logging
import time
import subprocess
import threading

# --- Path Adjustment ---
current_script_path = os.path.abspath(__file__)
utils_dir = os.path.dirname(current_script_path)
project_root_dir = os.path.dirname(utils_dir)
if project_root_dir not in sys.path:
    sys.path.insert(0, project_root_dir)

from stem import Signal
from stem.control import Controller
from whistledrop_server.config import Config
from whistledrop_server.app import app as flask_app
from whistledrop_server import key_manager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("tor_manager")

TOR_EXE_PATH = r"C:\Tor\Tor\tor.exe"
TOR_RC_PATH = r"C:\Tor\data\torrc"

# --- GLOBAL CONFIGURATION ---
# Für HTTPS .onion MUSS das lokale Ziel HTTPS sein.
# Wenn USE_LOCAL_HTTPS_TARGET False ist, wird der HS trotzdem auf Port 443 erstellt,
# aber das Ziel wäre HTTP, was zu Mixed-Content-Problemen oder Fehlern führen kann.
# Für ein echtes HTTPS .onion muss der Flask Server auch HTTPS bereitstellen.
USE_LOCAL_HTTPS_TARGET = True  # Für HTTPS .onion ist dies jetzt der Standard

tor_process = None


def read_tor_output(pipe, log_prefix="Tor"):
    # (Unchanged from previous version)
    try:
        for line_bytes in iter(pipe.readline, b''):
            line = line_bytes.decode('utf-8', errors='replace').strip()
            if line:
                logger.info(f"[{log_prefix}] {line}")
                if "Bootstrapped 100% (done)" in line:
                    logger.info("Tor successfully bootstrapped!")
    except Exception as e:
        logger.error(f"Error reading {log_prefix} output: {e}")
    finally:
        pipe.close()


def start_standalone_tor():
    # (Unchanged from previous version)
    global tor_process
    if not os.path.exists(TOR_EXE_PATH):
        logger.error(f"Tor executable not found at: {TOR_EXE_PATH}");
        return False
    if not os.path.exists(TOR_RC_PATH):
        logger.error(f"Tor configuration file (torrc) not found at: {TOR_RC_PATH}");
        return False
    logger.info(f"Attempting to start Standalone Tor from: {TOR_EXE_PATH} with config: {TOR_RC_PATH}")
    try:
        tor_process = subprocess.Popen([TOR_EXE_PATH, "-f", TOR_RC_PATH], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=False)
        logger.info(f"Standalone Tor process started with PID: {tor_process.pid}")
        threading.Thread(target=read_tor_output, args=(tor_process.stdout, "Tor STDOUT"), daemon=True).start()
        threading.Thread(target=read_tor_output, args=(tor_process.stderr, "Tor STDERR"), daemon=True).start()
        logger.info("Waiting a few seconds for Tor to initialize (increase sleep if needed)...")
        time.sleep(30)  # Increased default sleep time
        if tor_process.poll() is not None:
            logger.error(
                f"Standalone Tor process terminated unexpectedly with code {tor_process.returncode}. Check Tor logs.");
            return False
        logger.info("Standalone Tor seems to be running. Proceeding to connect via ControlPort.")
        return True
    except Exception as e:
        logger.error(f"Failed to start Standalone Tor: {e}", exc_info=True); return False


def stop_standalone_tor():
    # (Unchanged from previous version)
    global tor_process
    if tor_process:
        logger.info(f"Attempting to terminate Standalone Tor process (PID: {tor_process.pid})...")
        try:
            tor_process.terminate();
            tor_process.wait(timeout=10)
            logger.info("Standalone Tor process terminated.")
        except subprocess.TimeoutExpired:
            logger.warning("Standalone Tor process did not terminate in time, killing...");
            tor_process.kill();
            tor_process.wait()
            logger.info("Standalone Tor process killed.")
        except Exception as e:
            logger.error(f"Error terminating Standalone Tor process: {e}")
        tor_process = None


def start_whistledrop_with_tor_hidden_service():
    flask_host = Config.SERVER_HOST
    ssl_context_for_flask = None
    local_target_port = Config.SERVER_PORT
    local_target_protocol = "http"  # Default, wird überschrieben wenn USE_LOCAL_HTTPS_TARGET

    if USE_LOCAL_HTTPS_TARGET:
        if os.path.exists(Config.SSL_CERT_PATH) and os.path.exists(Config.SSL_KEY_PATH):
            local_target_protocol = "https"
            local_target_port = Config.SERVER_HTTPS_PORT  # z.B. 5001
            ssl_context_for_flask = (Config.SSL_CERT_PATH, Config.SSL_KEY_PATH)
            logger.info(f"Flask will run with SSL on port {local_target_port}. This will be the Hidden Service target.")
        else:
            logger.error(
                f"USE_LOCAL_HTTPS_TARGET is True, but SSL certificates not found at {Config.SSL_CERT_PATH} or {Config.SSL_KEY_PATH}.")
            logger.error("Cannot start with HTTPS target for Hidden Service. Please generate SSL certs for Flask.")
            return
    else:
        # Dieser Block ist jetzt weniger relevant, wenn das Ziel immer HTTPS sein soll für ein HTTPS .onion
        # Aber wir lassen ihn für den Fall, dass man doch mal ein HTTP .onion mit HTTP Backend testen will.
        local_target_protocol = "http"
        local_target_port = Config.SERVER_PORT  # z.B. 5000
        ssl_context_for_flask = None
        logger.warning(f"USE_LOCAL_HTTPS_TARGET is False. Flask will run HTTP on port {local_target_port}.")
        logger.warning(
            "If you intend to create an HTTPS .onion, ensure USE_LOCAL_HTTPS_TARGET is True and Flask serves HTTPS.")

    control_port = Config.TOR_CONTROL_PORT
    control_password = Config.TOR_CONTROL_PASSWORD

    logger.info(f"Attempting to connect to Tor control port {control_port}...")
    try:
        with Controller.from_port(port=control_port) as controller:
            if control_password:
                controller.authenticate(password=control_password)
            else:
                controller.authenticate()
            logger.info("Authenticated to Tor control port.")

            # --- WICHTIGE ÄNDERUNG HIER ---
            # Der Hidden Service soll auf Port 443 (HTTPS) lauschen.
            # Das lokale Ziel MUSS dann auch HTTPS sein (local_target_port und local_target_protocol müssen passen).
            # Wir stellen sicher, dass USE_LOCAL_HTTPS_TARGET oben auf True ist und Flask HTTPS bedient.
            if not USE_LOCAL_HTTPS_TARGET:
                logger.error(
                    "Configuration error: To create an HTTPS .onion, USE_LOCAL_HTTPS_TARGET must be True and Flask must serve HTTPS.")
                logger.error("Current local target is HTTP. Aborting HTTPS .onion creation.")
                return

            hidden_service_port_mapping = {443: f"{flask_host}:{local_target_port}"}
            logger.info(
                f"Creating ephemeral hidden service (HTTPS): Port 443 -> {local_target_protocol}://{flask_host}:{local_target_port}...")

            response = controller.create_ephemeral_hidden_service(
                hidden_service_port_mapping,
                await_publication=True,
            )

            if not response or not response.service_id:
                logger.error("Failed to create hidden service.");
                return

            # Die .onion Adresse wird jetzt mit https:// gebildet
            onion_address = f"https://{response.service_id}.onion"

            logger.info("--------------------------------------------------------------------")
            logger.info(f"WhistleDrop Hidden Service ONION ADDRESS: {onion_address}")
            logger.info(
                f"(Service forwards from its port 443 to local: {local_target_protocol}://{flask_host}:{local_target_port})")
            # ... (Rest der Log-Ausgaben) ...
            print(f"\nWhistleDrop accessible at: {onion_address}")
            print(f"(Ensure Tor Browser is running. You WILL see a certificate warning!)")
            print(f"Flask server running locally at: {local_target_protocol}://{flask_host}:{local_target_port}\n")

            logger.info(
                f"Starting WhistleDrop (Flask) server on {flask_host}:{local_target_port} (Protocol: {local_target_protocol.upper()})...")
            try:
                if not os.path.exists(Config.KEY_DB_PATH):
                    key_manager.initialize_key_database()
                flask_app.run(host=flask_host, port=local_target_port, debug=False, use_reloader=False,
                              ssl_context=ssl_context_for_flask)
            except KeyboardInterrupt:
                logger.info("Flask app stopped by user.")
            except Exception as flask_e:
                logger.error(f"Flask app crashed: {flask_e}", exc_info=True)
            # finally Block hier nicht mehr nötig

    except ConnectionRefusedError:
        logger.error(f"Connection to Tor control port {control_port} refused.");  # ...
    except Exception as e:
        logger.error(f"An error occurred while setting up Tor hidden service: {e}", exc_info=True);  # ...


if __name__ == "__main__":
    print("WhistleDrop Tor Manager")
    print("=" * 30)

    if not start_standalone_tor():
        print("Could not start Standalone Tor. Exiting.");
        sys.exit(1)

    print("\nStarting WhistleDrop with Tor Hidden Service Management...")
    print(f"           Using Tor executable: {TOR_EXE_PATH}")
    print(f"           Using Tor configuration: {TOR_RC_PATH}")

    if USE_LOCAL_HTTPS_TARGET:
        if os.path.exists(Config.SSL_CERT_PATH) and os.path.exists(Config.SSL_KEY_PATH):
            print(
                f"           Mode: Hidden Service will be HTTPS, targeting local HTTPS Flask server on port {Config.SERVER_HTTPS_PORT}.")
        else:
            print(
                f"           ERROR: Mode set to HTTPS target, but SSL certs for Flask not found at {Config.SSL_CERT_PATH} or {Config.SSL_KEY_PATH}.")
            stop_standalone_tor();
            sys.exit(1)
    else:
        # Dieser Modus ist für ein HTTPS .onion nicht sinnvoll, da das lokale Ziel auch HTTPS sein sollte.
        print(
            f"           WARNING: Mode: Hidden Service will be HTTPS, but local Flask target is set to HTTP on port {Config.SERVER_PORT}.")
        print(
            f"                    This may lead to issues. For a proper HTTPS .onion, ensure USE_LOCAL_HTTPS_TARGET is True.")

    print("           Press Ctrl+C to stop the Flask server, the hidden service, and the Standalone Tor process.\n")

    # (Journalist Account Check bleibt gleich)
    try:
        conn = key_manager.get_db_connection();
        cursor = conn.cursor();
        cursor.execute("SELECT COUNT(*) FROM journalists")
        count = cursor.fetchone()[0];
        conn.close()
        if count == 0: print("=" * 70 + "\nWARNING: No journalist accounts found...\n" + "=" * 70); time.sleep(2)
    except Exception as e:
        logger.error(f"Could not check for journalist accounts: {e}")

    try:
        start_whistledrop_with_tor_hidden_service()
    except KeyboardInterrupt:
        logger.info("Tor manager script interrupted by user (Ctrl+C).")
    except Exception as main_e:
        logger.error(f"An unexpected error occurred: {main_e}", exc_info=True)
    finally:
        logger.info("Shutting down...");
        stop_standalone_tor()
        logger.info("WhistleDrop Tor Manager finished.")