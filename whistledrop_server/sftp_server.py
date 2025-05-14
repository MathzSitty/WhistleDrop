# whistledrop/whistledrop_server/sftp_server.py
import os
import stat
import threading
import logging
import paramiko
import socket  # For socket operations in main server loop
from .config import Config

# storage_manager is not directly used here as SFTP operates on file system paths
# The structure of SUBMISSIONS_DIR is what SFTP serves.

logger = logging.getLogger(__name__)


# Optional: Increase paramiko logging for debugging SFTP issues
# paramiko_logger = logging.getLogger("paramiko")
# paramiko_logger.setLevel(logging.DEBUG) # Or INFO
# paramiko_logger.addHandler(logging.StreamHandler(sys.stderr))


class WhistleDropSFTPHandle(paramiko.SFTPHandle):
    def __init__(self, file_obj, flags):
        super().__init__(flags)
        self.file_obj = file_obj
        logger.debug(f"SFTPHandle created for {getattr(file_obj, 'name', 'unknown_file')}, flags={flags}")

    def read(self, offset, length):
        logger.debug(f"SFTPHandle read: offset={offset}, length={length} on {self.file_obj.name}")
        try:
            self.file_obj.seek(offset)
            return self.file_obj.read(length)
        except Exception as e:
            logger.error(f"SFTPHandle read error on {self.file_obj.name}: {e}")
            return paramiko.SFTP_FAILURE  # General failure

    def write(self, offset, data):
        logger.warning(f"SFTP Write operation attempted and denied on {self.file_obj.name} (read-only server).")
        return paramiko.SFTP_PERMISSION_DENIED

    def close(self):
        logger.debug(f"SFTPHandle close: {self.file_obj.name}")
        try:
            self.file_obj.close()
            return paramiko.SFTP_OK
        except Exception as e:
            logger.error(f"SFTPHandle close error on {self.file_obj.name}: {e}")
            return paramiko.SFTP_FAILURE

    # fstat, fsetstat, chattr might be called by some clients
    def fstat(self):
        logger.debug(f"SFTPHandle fstat on {self.file_obj.name}")
        try:
            return paramiko.SFTPAttributes.from_stat(os.fstat(self.file_obj.fileno()))
        except OSError as e:
            logger.error(f"SFTPHandle fstat error on {self.file_obj.name}: {e}")
            return paramiko.SFTP_FAILURE

    def chattr(self, attr):
        logger.warning(f"SFTPHandle chattr denied on {self.file_obj.name} (read-only).")
        return paramiko.SFTP_PERMISSION_DENIED


class WhistleDropSFTPServerInterface(paramiko.SFTPServerInterface):
    # The root of the SFTP jail. Must be an absolute path.
    # All paths provided by the client will be relative to this root.
    ROOT = os.path.abspath(Config.SUBMISSIONS_DIR)

    def __init__(self, server, *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        logger.info(f"WhistleDropSFTPInterface initialized. SFTP Root: {self.ROOT}")

    def _resolve_path(self, path):
        """
        Resolves a client-provided path to an absolute path on the server,
        ensuring it's within the defined ROOT.
        """
        if os.path.isabs(path):  # Path should be relative from client
            path = path[1:] if path.startswith('/') else path

        # Normalize the path (e.g., collapses ../, //) and join with ROOT
        full_path = os.path.normpath(os.path.join(self.ROOT, path))

        # Security check: Ensure the resolved path is still within the ROOT directory
        if not full_path.startswith(self.ROOT):
            logger.warning(
                f"SFTP path traversal attempt denied: client path '{path}' resolved to '{full_path}', which is outside ROOT '{self.ROOT}'")
            return None
        return full_path

    def list_folder(self, path):
        logger.debug(f"SFTP list_folder request for client path: '{path}'")
        full_path = self._resolve_path(path)
        if not full_path:
            return paramiko.SFTP_NO_SUCH_FILE  # Or SFTP_PERMISSION_DENIED due to traversal attempt

        if not os.path.isdir(full_path):
            logger.warning(f"SFTP list_folder: '{full_path}' is not a directory.")
            return paramiko.SFTP_NO_SUCH_FILE  # Or SFTP_BAD_MESSAGE if path is not a dir

        dirents = []
        try:
            for fname in os.listdir(full_path):
                fpath_abs = os.path.join(full_path, fname)
                try:
                    attr = paramiko.SFTPAttributes.from_stat(os.stat(fpath_abs))
                    attr.filename = fname  # Crucial: filename must be set
                    dirents.append(attr)
                except OSError as e_stat:
                    logger.warning(f"SFTP list_folder: Could not stat '{fpath_abs}': {e_stat}. Skipping.")
            logger.debug(f"SFTP list_folder success for '{path}', found {len(dirents)} items.")
            return dirents
        except OSError as e:
            logger.error(f"SFTP list_folder OSError for '{path}' (resolved: '{full_path}'): {e}")
            return paramiko.SFTP_FAILURE

    def stat(self, path):
        logger.debug(f"SFTP stat request for client path: '{path}'")
        full_path = self._resolve_path(path)
        if not full_path:
            return paramiko.SFTP_NO_SUCH_FILE
        try:
            return paramiko.SFTPAttributes.from_stat(os.stat(full_path))
        except OSError:
            logger.debug(f"SFTP stat: File not found at resolved path '{full_path}'")
            return paramiko.SFTP_NO_SUCH_FILE

    def lstat(self, path):
        logger.debug(f"SFTP lstat request for client path: '{path}' (delegating to stat)")
        # No symlinks expected or handled in submissions directory for this simple server
        return self.stat(path)

    def open(self, path, flags, attr):
        logger.debug(f"SFTP open request for client path: '{path}', flags={flags}")
        full_path = self._resolve_path(path)
        if not full_path:
            return paramiko.SFTP_NO_SUCH_FILE

        # Enforce read-only access
        if (flags & os.O_WRONLY) or (flags & os.O_RDWR) or (flags & os.O_APPEND):
            logger.warning(f"SFTP Write access denied for path: '{path}' (resolved: '{full_path}')")
            return paramiko.SFTP_PERMISSION_DENIED

        try:
            if os.path.isdir(full_path):
                logger.warning(f"SFTP: Attempt to open directory '{full_path}' as a file.")
                return paramiko.SFTP_BAD_MESSAGE  # Or SFTP_FAILURE, opening a dir like a file is bad.

            # All files are opened in binary read mode ("rb")
            file_obj = open(full_path, "rb")
            handle = WhistleDropSFTPHandle(file_obj, flags)
            logger.debug(f"SFTP file opened successfully: '{path}' (resolved: '{full_path}')")
            return handle
        except FileNotFoundError:
            logger.warning(f"SFTP open: File not found at '{full_path}'")
            return paramiko.SFTP_NO_SUCH_FILE
        except OSError as e:
            logger.error(f"SFTP open OSError for '{path}' (resolved: '{full_path}'): {e}")
            return paramiko.SFTP_FAILURE

    # Deny all write and modification operations explicitly
    def remove(self, path):
        logger.warning(f"SFTP remove denied for '{path}' (read-only).")
        return paramiko.SFTP_PERMISSION_DENIED

    def rename(self, oldpath, newpath):
        logger.warning(f"SFTP rename denied for '{oldpath}' to '{newpath}' (read-only).")
        return paramiko.SFTP_PERMISSION_DENIED

    def mkdir(self, path, attr):
        logger.warning(f"SFTP mkdir denied for '{path}' (read-only).")
        return paramiko.SFTP_PERMISSION_DENIED

    def rmdir(self, path):
        logger.warning(f"SFTP rmdir denied for '{path}' (read-only).")
        return paramiko.SFTP_PERMISSION_DENIED

    def chattr(self, path, attr):  # For changing attributes of a file/dir
        logger.warning(f"SFTP chattr denied for '{path}' (read-only).")
        return paramiko.SFTP_PERMISSION_DENIED

    def symlink(self, target_path, link_path):
        logger.warning(f"SFTP symlink creation denied (read-only).")
        return paramiko.SFTP_OP_UNSUPPORTED  # Or SFTP_PERMISSION_DENIED

    def readlink(self, path):
        logger.debug(f"SFTP readlink for '{path}' - not supported.")
        return paramiko.SFTP_OP_UNSUPPORTED


class WhistleDropSSHServerInterface(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()  # Used to signal completion of auth or other events
        self.authenticated_username = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_publickey(self, username, key):
        if username != Config.SFTP_USER:
            logger.warning(f"SFTP Auth: Username '{username}' not allowed (expected '{Config.SFTP_USER}').")
            return paramiko.AUTH_FAILED

        logger.info(f"SFTP Auth: Attempting public key auth for user '{username}' with key type '{key.get_name()}'")

        if not os.path.exists(Config.SFTP_AUTHORIZED_KEYS_PATH):
            logger.error(f"SFTP Auth: authorized_keys file not found at {Config.SFTP_AUTHORIZED_KEYS_PATH}")
            return paramiko.AUTH_FAILED

        try:
            # Use paramiko's AuthorizedKeysFile for robust parsing
            auth_keys_file = paramiko.AuthorizedKeysFile(Config.SFTP_AUTHORIZED_KEYS_PATH)
            if auth_keys_file.check_key(username, key):  # This method does not exist. We need to iterate.
                # Iterate through keys for the specified user (or all if user is None)
                # For simplicity, we assume Config.SFTP_USER is the only one.
                # A more complex setup might check keys for the specific 'username'.

                # Manual iteration and comparison:
                with open(Config.SFTP_AUTHORIZED_KEYS_PATH, "r") as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        try:
                            # Attempt to load the key from the line in authorized_keys
                            # This supports various key types and formats in the file.
                            auth_file_key = paramiko.PKey.from_type_string(line.split()[1], line.split()[0])
                            if auth_file_key == key:  # Compare the key objects
                                logger.info(f"SFTP Auth: Public key accepted for user '{username}'.")
                                self.authenticated_username = username
                                return paramiko.AUTH_SUCCESSFUL
                        except (IndexError, paramiko.SSHException, UnicodeDecodeError) as e_parse:
                            logger.warning(
                                f"SFTP Auth: Skipping malformed line {line_num} in authorized_keys: {e_parse} - Line: '{line[:50]}...'")
                            continue

                logger.warning(
                    f"SFTP Auth: Public key for user '{username}' not found or did not match in {Config.SFTP_AUTHORIZED_KEYS_PATH}.")
                return paramiko.AUTH_FAILED

        except Exception as e:
            logger.error(f"SFTP Auth: Error processing authorized_keys file: {e}", exc_info=True)
            return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        logger.info("SFTP: Shell access requested and denied.")
        self.event.set()  # Signal that a channel type was checked
        return False  # No shell access

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        logger.info("SFTP: PTY access requested and denied.")
        self.event.set()  # Signal that a channel type was checked
        return False  # No PTY access

    def get_allowed_auths(self, username):
        # This method tells the client what authentication methods are available.
        return "publickey"


def start_sftp_server():
    logger.info(f"Attempting to start SFTP server on {Config.SERVER_HOST}:{Config.SFTP_PORT}")
    logger.info(f"SFTP Submissions (root) directory: {os.path.abspath(Config.SUBMISSIONS_DIR)}")
    logger.info(f"SFTP Authorized keys file: {os.path.abspath(Config.SFTP_AUTHORIZED_KEYS_PATH)}")

    # Ensure host key exists, generate if not
    if not os.path.exists(Config.SFTP_HOST_KEY_PATH):
        try:
            logger.info(f"Generating new SFTP host key at {Config.SFTP_HOST_KEY_PATH} (RSA 2048)")
            # Using RSAKey for broader compatibility, Ed25519Key is also good.
            host_key = paramiko.RSAKey.generate(2048)
            host_key.write_private_key_file(Config.SFTP_HOST_KEY_PATH)
            logger.info("SFTP host key generated successfully.")
        except Exception as e:
            logger.error(f"Failed to generate or save SFTP host key: {e}", exc_info=True)
            print(f"CRITICAL: Could not generate SFTP host key. Server cannot start: {e}")
            return
    else:
        logger.info(f"Using existing SFTP host key from {Config.SFTP_HOST_KEY_PATH}")

    # Load the host key
    try:
        host_key = paramiko.RSAKey(filename=Config.SFTP_HOST_KEY_PATH)  # Or Ed25519Key etc.
    except Exception as e:
        logger.error(f"Failed to load SFTP host key from {Config.SFTP_HOST_KEY_PATH}: {e}", exc_info=True)
        print(f"CRITICAL: Could not load SFTP host key. Please delete it to regenerate or fix permissions: {e}")
        return

    # Socket setup
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((Config.SERVER_HOST, Config.SFTP_PORT))
        sock.listen(5)  # Max backlog of connections
        logger.info(f"SFTP server listening on {Config.SERVER_HOST}:{Config.SFTP_PORT}")
    except Exception as e:
        logger.error(f"SFTP Server critical error during socket setup: {e}", exc_info=True)
        print(f"CRITICAL: SFTP server could not bind to socket: {e}")
        return

    # Main server loop
    try:
        while True:
            logger.debug("SFTP server waiting for a new connection...")
            conn, addr = sock.accept()
            logger.info(f"SFTP connection received from {addr}")

            transport = None  # Initialize transport to None for finally block
            try:
                transport = paramiko.Transport(conn)
                transport.set_gss_host(socket.getfqdn(""))  # For GSSAPI if ever enabled
                transport.load_server_moduli()  # For DH group exchange
                transport.add_server_key(host_key)

                # Instantiate our SSH server interface
                ssh_server_interface = WhistleDropSSHServerInterface()

                # Start the server protocol
                transport.start_server(server=ssh_server_interface)

                # Wait for a channel to be opened (e.g., "session" for SFTP)
                channel = transport.accept(timeout=30)  # Timeout for accepting a channel
                if channel is None:
                    logger.warning(f"SFTP: No channel opened from {addr} within timeout. Closing transport.")
                    transport.close()
                    continue

                logger.info(f"SFTP: Channel opened by {addr}. User: {ssh_server_interface.authenticated_username}")

                # At this point, if auth was successful and channel is 'session',
                # paramiko will look for a subsystem_handler for 'sftp'.
                transport.set_subsystem_handler(
                    "sftp", paramiko.SFTPServer, WhistleDropSFTPServerInterface
                )

                # Keep the connection alive as long as the transport is active
                # The SFTPServer and its interface handle the actual SFTP commands.
                while transport.is_active():
                    # transport.join(timeout=1) # Check transport status, not strictly needed here
                    # A more robust way to keep alive or detect closure might be needed
                    # depending on paramiko's internal handling of SFTPServer.
                    # For now, rely on client disconnecting or errors to break.
                    # If the client sends a disconnect, transport.is_active() will become false.
                    # If an error occurs, it should break out.
                    # Let's add a small sleep to prevent a tight loop if join isn't blocking enough.
                    socket.setdefaulttimeout(1.0)  # Timeout for socket operations within paramiko
                    if not transport.is_active():  # Re-check after potential operations
                        break
                    # This loop is mainly to keep the thread alive for this connection.
                    # The actual SFTP command processing happens in paramiko's threads.
                    # We can simply wait on the event if we need to react to shell/pty requests,
                    # but for SFTP, it's mostly handled by the subsystem.
                    # ssh_server_interface.event.wait(1) # Wait with a timeout
                    # if ssh_server_interface.event.is_set():
                    #    logger.debug("SFTP: Event was set on SSH server interface.")
                    #    ssh_server_interface.event.clear() # Reset for next event
                    #    if not transport.is_active(): break
                    time.sleep(0.1)  # Small sleep to yield CPU

            except paramiko.SSHException as ssh_e:
                logger.warning(f"SFTP session SSH exception for {addr}: {ssh_e}",
                               exc_info=False)  # exc_info=False for less verbose common errors
            except Exception as e_sess:
                logger.error(f"SFTP session unexpected error for {addr}: {e_sess}", exc_info=True)
            finally:
                if transport and transport.is_active():
                    logger.info(f"SFTP: Closing active transport for {addr}.")
                    transport.close()
                elif transport:  # Transport exists but not active (e.g. closed by client)
                    logger.info(f"SFTP: Transport for {addr} already closed or was never fully active.")
                else:  # Connection object `conn` might still be open if transport failed early
                    conn.close()  # Ensure raw socket is closed
                logger.info(f"SFTP connection from {addr} ended.")

    except KeyboardInterrupt:
        logger.info("SFTP server shutting down due to KeyboardInterrupt.")
    except Exception as e_main:
        logger.error(f"SFTP Server critical error in main loop: {e_main}", exc_info=True)
    finally:
        if 'sock' in locals() and sock:
            sock.close()
        logger.info("SFTP server stopped.")


# This allows running the SFTP server directly for testing,
# but it's intended to be started as a thread by tor_manager.py
if __name__ == '__main__':
    import sys

    # Setup basic logging for standalone run
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Ensure necessary directories and files for standalone testing
    Config.ensure_dirs_exist()  # Creates sftp_data, authorized_keys placeholder etc.
    if not os.path.exists(Config.SUBMISSIONS_DIR):
        os.makedirs(Config.SUBMISSIONS_DIR)
        print(f"INFO: Created submissions directory for testing: {Config.SUBMISSIONS_DIR}")
        # Create a dummy submission for testing listing
        dummy_sub_path = os.path.join(Config.SUBMISSIONS_DIR, "test_submission_123")
        os.makedirs(dummy_sub_path, exist_ok=True)
        with open(os.path.join(dummy_sub_path, "encrypted_file.dat"), "w") as f: f.write("dummydata")
        with open(os.path.join(dummy_sub_path, "rsa_public_key_hint.txt"), "w") as f: f.write("test_hint")

    print("Starting SFTP server in standalone mode for testing...")
    start_sftp_server()