## WhistleDrop: Step-by-Step Usage Guide

This guide walks you through the entire process of setting up and using WhistleDrop, from key generation to file decryption.

### Phase 1: Journalist - Initial Setup & Key Generation

The journalist is the intended recipient of the whistleblower's information. They need to generate RSA key pairs.

1.  **Navigate to `journalist_tool` directory:**
    ```bash
    cd whistledrop/journalist_tool
    ```
2.  **Activate Python Virtual Environment:**
    ```bash
    source ../venv/bin/activate  # Linux/macOS
    # ..\venv\Scripts\activate    # Windows
    ```
3.  **Generate RSA Key Pairs (using the GUI):**

    - Run the Journalist GUI tool:
      ```bash
      python journalist_gui.py
      ```
    - Go to the **"Key Management"** tab.
    - **Number of Keys:** Enter how many key pairs you want to generate (e.g., 5).
    - **Key ID Prefix:** Choose a prefix (e.g., `my_secure_keys`). This helps organize them.
    - **Password-protect:** Check this box (highly recommended). You'll be prompted to enter and confirm a strong password for these private keys. **Remember this password!**
    - Click **"Generate Keys"**.
    - The private keys (e.g., `my_secure_keys_1_private.pem`) will be saved in `whistledrop/journalist_tool/private_keys/`.
    - The public keys (e.g., `my_secure_keys_1_public.pem`) will also be saved there, AND their content will be displayed in the GUI text box. Copy all the public key contents from this box. You'll need to provide these to the server administrator.
    - **Security Note:** Store your private keys and their password in a very secure location (e.g., an encrypted vault). **Never share your private keys or their password.**

4.  **Alternative: Generate RSA Key Pairs (using CLI):**

    ```bash
    cd ../utils  # Navigate to the utils directory
    python generate_rsa_keys.py
    ```

    - Follow the prompts to specify the number of keys, a prefix, and whether to password-protect them.
    - Public and private keys will be saved in `whistledrop/journalist_tool/private_keys/`.
    - The public key content will be printed to the console. Copy this.

5.  **Provide Public Keys to Server Administrator:**
    The `.pem` files ending with `_public.pem` (or the text copied from the GUI/CLI) must be securely transmitted to the person administering the WhistleDrop server.

### Phase 2: Server Administrator - Server Setup & Configuration

The server administrator sets up the WhistleDrop server application.

1.  **Server Prerequisites:**

    - Ensure Python 3.9+ and `pip` are installed.
    - Ensure Tor is installed and running. The `utils/tor_manager.py` script requires Tor's control port to be enabled.
      - Edit your `torrc` file (e.g., `/etc/tor/torrc` or via Tor Browser settings).
      - Add/uncomment:
        ```
        ControlPort 9051
        CookieAuthentication 1
        # OR (less recommended for this script unless TOR_CONTROL_PASSWORD env var is set):
        # HashedControlPassword YOUR_HASHED_PASSWORD
        # (generate with 'tor --hash-password "your_password"')
        ```
      - Restart Tor: `sudo systemctl restart tor` (or equivalent).

2.  **Clone/Download WhistleDrop Project:**
    Obtain the WhistleDrop project files on the server.

3.  **Create Virtual Environment & Install Dependencies:**

    ```bash
    cd whistledrop
    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

4.  **Create Necessary Directories (if not existing):**

    ```bash
    mkdir -p whistledrop_server/data/submissions
    mkdir -p whistledrop_server/data/db
    ```

5.  **Configure the Server (`whistledrop_server/config.py`):**

    - Set `JOURNALIST_API_KEY`: Open `whistledrop_server/config.py` and change the `JOURNALIST_API_KEY` to a strong, unique, random string.
      ```python
      JOURNALIST_API_KEY = "your-very-strong-unique-api-key-here"
      ```
      Alternatively, set it as an environment variable: `export WHISTLEDROP_JOURNALIST_API_KEY="your-key"`
    - Review `TOR_CONTROL_PORT` and `TOR_CONTROL_PASSWORD` if you are not using cookie authentication for Tor.

6.  **Add Journalist's Public Keys to Server Database:**

    - Place the public key `.pem` files (received from the journalist) into a temporary directory on the server, or directly into `whistledrop/journalist_tool/private_keys/` if setting up on the same machine for testing.
    - Navigate to the `utils` directory: `cd utils`
    - Run the `add_public_key_to_db.py` script, pointing it to the directory containing the public keys:
      ```bash
      python add_public_key_to_db.py /path/to/journalist_public_keys/
      # Example: python add_public_key_to_db.py ../journalist_tool/private_keys/
      ```
    - The script will report how many keys were successfully added or if any failed (e.g., duplicates).

7.  **Start the WhistleDrop Server with Tor Hidden Service:**
    - Navigate to the `utils` directory: `cd utils`
    - Run the `tor_manager.py` script:
      ```bash
      python tor_manager.py
      ```
    - If successful, the script will connect to Tor, create an ephemeral hidden service, and print the `.onion` address to the console (e.g., `abcdef1234567890.onion`).
    - **Copy this `.onion` address.** This is what whistleblowers will use.
    - The WhistleDrop Flask server will also start. Keep this script running. Press `Ctrl+C` to stop the server and remove the ephemeral hidden service.
    - **Security Note:** The `tor_manager.py` creates an _ephemeral_ service. For a permanent service, configure it directly in your `torrc` file as described in the main `README.md` and run the server using Gunicorn:
      ```bash
      # From whistledrop/whistledrop_server/ directory
      # gunicorn --bind 127.0.0.1:5000 wsgi:app
      ```

### Phase 3: Whistleblower - Submitting Information

The whistleblower needs Tor Browser to submit files anonymously and securely.

1.  **Install and Open Tor Browser.**
2.  **Navigate to the `.onion` Address:**
    Paste the `.onion` address (obtained by the server administrator in Phase 2, Step 7) into Tor Browser's address bar and press Enter.
3.  **Use the Upload Form:**
    - The WhistleDrop upload page will appear.
    - Click "Choose File" (or similar, depending on browser language) and select the file you want to submit.
    - **Security Tip for Whistleblowers:** Before uploading, consider:
      - Removing personal metadata from your files (e.g., author names in documents, GPS data in images).
      - Using generic filenames.
      - Encrypting the file locally with a one-time password communicated separately if an extra layer is desired (though WhistleDrop provides E2E encryption).
    - Click "Upload Securely".
4.  **Confirmation:**
    If successful, the page will display a message like "File uploaded securely! Submission ID: [some-uuid]". The Whistleblower generally does not need this ID, but it confirms the upload.

### Phase 4: Journalist - Retrieving & Decrypting Submissions

The journalist uses their local tools to download and decrypt submissions.

1.  **Open the Journalist GUI Tool:**

    - Navigate to `whistledrop/journalist_tool/`
    - Ensure your virtual environment is active.
    - Run: `python journalist_gui.py`

2.  **Configure the GUI (Setup Tab):**

    - **Server URL:** Enter the full `.onion` address of the WhistleDrop server (e.g., `http://abcdef1234567890.onion`).
      - **Important:** For the GUI to access `.onion` addresses, your system's network requests (or at least Python's `requests` library used by the GUI) must be routed through Tor. This typically means running a local Tor proxy (like the one Tor Browser provides on port 9050 or 9150 by default) and configuring the `requests` library to use it. The current GUI script _does not_ automatically configure SOCKS5 proxy for `requests`. This is a manual setup step for the journalist or a feature to be added to the GUI (e.g., proxy settings).
      - For local testing without Tor routing for the GUI, you can use `http://127.0.0.1:5000` if the server is running directly on your machine.
    - **API Key:** Enter the `JOURNALIST_API_KEY` that was configured on the server.
    - Click **"Save Configuration"**.

3.  **Refresh Submissions List (Submissions Tab):**

    - Go to the "Submissions" tab.
    - Click **"Refresh Submissions List"**. The listbox should populate with available submission IDs.
    - If you get errors, check your Server URL, API Key, Tor proxy settings, and server logs.

4.  **Select a Submission and Private Key:**

    - Click on a submission ID in the list.
    - Click **"Select Private Key..."** and choose the RSA private key file (e.g., `my_secure_keys_1_private.pem`) that you believe corresponds to one of the public keys the server might have used for this submission.
      - **Note on Key Matching:** The current system doesn't explicitly tell the journalist which of _their_ private keys to use. If you've provided multiple public keys to the server, you might need to try different private keys if the first one fails decryption (especially if they have different passwords). Future enhancements could include a server-provided key hint.

5.  **Decrypt the Submission:**

    - Click **"Decrypt Selected Submission"**.
    - If your private key is password-protected, a dialog will appear asking for the **private key password**. Enter it.
    - The tool will download the encrypted components, decrypt the AES key, then decrypt the original filename and the file content.
    - A "Save As" dialog will appear, pre-filled with the decrypted original filename. Choose a location and save the file.
    - Check the log panel in the GUI for progress and any error messages.

6.  **Alternative: Using the CLI Decryption Tool (`decrypt_tool.py`):**
    - Navigate to `whistledrop/journalist_tool/`.
    - Run the command:
      ```bash
      python decrypt_tool.py <submission_id> <your_private_key_filename.pem> --server_url <server_onion_or_local_url> --api_key <your_api_key>
      ```
      Example:
      ```bash
      python decrypt_tool.py a1b2c3d4-e5f6... my_secure_keys_1_private.pem --server_url http://abcdef1234567890.onion --api_key your-very-strong-unique-api-key-here
      ```
    - You will be prompted for the private key password if it's protected.
    - The decrypted file will be saved in `whistledrop/journalist_tool/decrypted_submissions/`.
    - **Tor for CLI:** Similar to the GUI, if using an `.onion` URL, the `requests` library in `decrypt_tool.py` needs to be configured to use a SOCKS proxy. You can do this by setting environment variables `HTTP_PROXY` and `HTTPS_PROXY`:
      ```bash
      export HTTP_PROXY=socks5h://127.0.0.1:9050
      export HTTPS_PROXY=socks5h://127.0.0.1:9050
      # Then run the python script
      ```
      (Adjust port if your Tor proxy runs on a different one, e.g., 9150 for Tor Browser's proxy).

### General Security Reminders

- **Journalist:** Protect your private keys and their passwords vigilantly. Use strong, unique passwords. Keep your system secure.
- **Server Administrator:** Keep the server operating system and WhistleDrop software updated. Secure the `JOURNALIST_API_KEY`. Monitor server logs for suspicious activity. Ensure Tor is configured securely.
- **Whistleblower:** Use an updated Tor Browser from a trusted source. Be mindful of operational security (e.g., not using a work computer or network for submissions if you are an internal whistleblower).

This guide provides a comprehensive workflow. Remember that this is a prototype; real-world deployment would require further hardening and security audits.
