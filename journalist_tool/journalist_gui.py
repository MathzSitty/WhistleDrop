# whistledrop/journalist_tool/journalist_gui.py
import tkinter as tk
from tkinter import ttk, filedialog, simpledialog, messagebox, scrolledtext
import os
import sys
import threading
import json
import secrets
import string
import urllib.parse
import time
import traceback # For detailed error logging

# Adjust path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir) # Add project_root to sys.path

from utils import generate_rsa_keys as rsa_gen_module
from journalist_tool import crypto_utils # Corrected import if crypto_utils is in the same package
import requests

CONFIG_FILE = os.path.join(current_dir, "gui_config.json")
DEFAULT_PRIVATE_KEYS_DIR = rsa_gen_module.PRIVATE_KEYS_OUTPUT_DIR
DEFAULT_PUBLIC_KEYS_FOR_SERVER_DIR = rsa_gen_module.PUBLIC_KEYS_FOR_SERVER_OUTPUT_DIR
DEFAULT_DOWNLOAD_DIR = os.path.join(current_dir, "decrypted_submissions")

os.makedirs(DEFAULT_PRIVATE_KEYS_DIR, exist_ok=True)
os.makedirs(DEFAULT_PUBLIC_KEYS_FOR_SERVER_DIR, exist_ok=True)
os.makedirs(DEFAULT_DOWNLOAD_DIR, exist_ok=True)


class ToolTip: # Moved ToolTip class definition earlier or ensure it's accessible
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        self.id = None
        self.x = self.y = 0

    def showtip(self):
        self.hidetip()
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(1)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                         background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                         font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hidetip(self):
        if self.tipwindow:
            self.tipwindow.destroy()
        self.tipwindow = None


class JournalistApp:
    def __init__(self, root):
        self.root = root
        self.root.title("WhistleDrop Journalist Tool")
        self.root.geometry("850x650")

        self.server_url = tk.StringVar(value="http://127.0.0.1:5000")
        self.api_key = tk.StringVar()
        self.private_key_path = tk.StringVar()
        self.selected_submission_id = tk.StringVar()

        self.load_config()

        self.notebook = ttk.Notebook(root)
        self.setup_tab = ttk.Frame(self.notebook, padding=10)
        self.submissions_tab = ttk.Frame(self.notebook, padding=10)
        self.keys_tab = ttk.Frame(self.notebook, padding=10)

        self.notebook.add(self.setup_tab, text='Server Setup & Admin')
        self.notebook.add(self.submissions_tab, text='Submissions')
        self.notebook.add(self.keys_tab, text='My Key Pairs')
        self.notebook.pack(expand=1, fill='both', padx=5, pady=5)

        self.create_setup_tab()
        self.create_submissions_tab() # This will create self.submissions_tree
        self.create_keys_tab()

        self.log_text_frame = ttk.LabelFrame(root, text="Log", padding=5)
        self.log_text_frame.pack(pady=5, padx=10, fill=tk.X)
        self.log_text = scrolledtext.ScrolledText(self.log_text_frame, height=8, state=tk.DISABLED, wrap=tk.WORD)
        self.log_text.pack(fill=tk.X, expand=True)
        self.log_message("GUI Initialized. Configure server and API key in 'Server Setup & Admin' tab.")
        self.log_message(
            "REMINDER: For .onion addresses, ensure your system/Python can route through Tor (e.g., SOCKS proxy).")

    def log_message(self, message, level="INFO"):
        self.log_text.config(state=tk.NORMAL)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.log_text.insert(tk.END, f"[{timestamp} {level}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config_data = json.load(f)
                    self.server_url.set(config_data.get("server_url", "http://127.0.0.1:5000"))
                    self.api_key.set(config_data.get("api_key", ""))
        except Exception as e:
            self.log_message(f"Error loading config: {e}", "ERROR")

    def save_config(self):
        config_data = {
            "server_url": self.server_url.get(),
            "api_key": self.api_key.get()
        }
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config_data, f, indent=4)
            self.log_message("Configuration saved.")
        except Exception as e:
            self.log_message(f"Error saving config: {e}", "ERROR")

    def create_tooltip(self, widget, text):
        tooltip = ToolTip(widget, text)
        widget.bind("<Enter>", lambda event, t=tooltip: t.showtip()) # Capture tooltip instance
        widget.bind("<Leave>", lambda event, t=tooltip: t.hidetip()) # Capture tooltip instance

    def create_setup_tab(self):
        conn_frame = ttk.LabelFrame(self.setup_tab, text="WhistleDrop Server Connection", padding=10)
        conn_frame.pack(padx=5, pady=5, fill=tk.X)
        ttk.Label(conn_frame, text="Server URL:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Entry(conn_frame, textvariable=self.server_url, width=60).grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        api_key_label = ttk.Label(conn_frame, text="API Key:")
        api_key_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        tooltip_text = ("The API key is a secret token configured on the WhistleDrop server...\n"
                        "The server admin must provide this key... Example: " +
                        ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(20)) + "...")
        self.create_tooltip(api_key_label, tooltip_text)
        ttk.Entry(conn_frame, textvariable=self.api_key, width=60, show="*").grid(row=1, column=1, padx=5, pady=5,sticky=tk.EW)
        ttk.Button(conn_frame, text="Save Connection Settings", command=self.save_config).grid(row=2, column=0, columnspan=2, pady=10)
        conn_frame.columnconfigure(1, weight=1)

        pubkey_upload_frame = ttk.LabelFrame(self.setup_tab, text="Upload Public Keys to Server", padding=10)
        pubkey_upload_frame.pack(padx=5, pady=10, fill=tk.X)
        info_label_pubkey = ttk.Label(pubkey_upload_frame,
            text=f"Upload .pem/.pub from '{os.path.basename(DEFAULT_PUBLIC_KEYS_FOR_SERVER_DIR)}' or selected.")
        info_label_pubkey.pack(pady=5)
        ttk.Button(pubkey_upload_frame, text="Select & Upload Public Keys to Server", command=self.upload_public_keys_to_server_threaded).pack(pady=5)

    def upload_public_keys_to_server_threaded(self):
        # This method is called by the button.
        # It should handle the GUI interaction (file dialog) in the main thread.
        if not self.server_url.get() or not self.api_key.get():
            self.log_message("Server URL or API Key not configured for uploading keys.", "ERROR")
            self.root.after(0, lambda: messagebox.showerror(
                "Configuration Error",
                "Please set Server URL and API Key first.",
                parent=self.root
            ))
            return

        # --- File dialog MUST be in the main GUI thread ---
        selected_key_files = filedialog.askopenfilenames(
            parent=self.root,  # Good practice to set parent
            title="Select Public Key Files to Upload",
            initialdir=DEFAULT_PUBLIC_KEYS_FOR_SERVER_DIR,
            filetypes=(("Public Key files", "*.pem *.pub"), ("All files", "*.*"))
        )

        if not selected_key_files:  # User cancelled or selected no files
            self.log_message("No public key files selected for upload.")
            return

        # Now pass the selected_key_files to the worker thread
        threading.Thread(target=self.upload_public_keys_to_server_worker,
                         args=(selected_key_files,),  # Pass as a tuple
                         daemon=True).start()

    def upload_public_keys_to_server_worker(self, key_files_to_upload):  # Renamed method for clarity
        # This method runs in the worker thread.
        # 'key_files_to_upload' is the list of paths passed from the main thread.

        public_keys_payload = []
        for f_path in key_files_to_upload:  # Use the passed argument
            try:
                with open(f_path, 'r') as kf:
                    content = kf.read()
                if content.strip().startswith("-----BEGIN PUBLIC KEY-----"):
                    filename_base = os.path.basename(f_path)
                    hint = filename_base
                    possible_suffixes = ["_public.pem", ".pem", "_public.pub", ".pub"]
                    for suffix in possible_suffixes:
                        if hint.lower().endswith(suffix.lower()):
                            hint = hint[:-len(suffix)]
                            break

                    self.log_message(
                        f"GUI UPLOAD (Worker): Preparing key from '{filename_base}' with extracted HINT: '{hint}' for upload.",
                        "DEBUG")
                    public_keys_payload.append({"pem": content, "hint": hint})
                else:
                    self.log_message(f"Skipping {os.path.basename(f_path)}: Not a valid public key PEM format.",
                                     "WARNING")
            except Exception as e:
                self.log_message(f"Error reading {os.path.basename(f_path)}: {e}", "ERROR")

        if not public_keys_payload:
            self.log_message("No valid public keys found in selected files to form payload.", "WARNING")
            return  # Exit if no valid keys to send

        self.log_message(f"Attempting to upload {len(public_keys_payload)} public keys to server...")

        payload_to_send = {"public_keys": public_keys_payload}
        # Ensure self.api_key.get() is thread-safe (StringVar.get() is generally okay)
        # Ensure self.server_url.get() is thread-safe (StringVar.get() is generally okay)
        headers_req = {"Authorization": f"Bearer {self.api_key.get()}", "Content-Type": "application/json"}

        try:
            target_url = f"{self.server_url.get().rstrip('/')}/journalist/admin/add-public-keys"
            self.log_message(f"GUI UPLOAD (Worker): Sending POST to {target_url}", "DEBUG")

            response = requests.post(
                target_url,
                json=payload_to_send,
                headers=headers_req,
                timeout=30
            )
            response.raise_for_status()  # Will raise HTTPError for 4xx/5xx
            result_data = response.json()

            self.log_message(f"Server response: {result_data.get('message', 'No message.')}", "INFO")
            self.log_message(
                f"Successfully added: {result_data.get('success_count', 0)}, Failed: {result_data.get('failure_count', 0)}",
                "INFO")

            details_log = []
            if result_data.get('details'):
                for detail in result_data['details']:
                    log_entry = f"  - Key: {detail.get('key_preview', 'N/A')} - Status: {detail.get('status', 'N/A')} ({detail.get('reason', '')})"
                    self.log_message(log_entry, "DETAIL")
                    details_log.append(log_entry)

            # Schedule messagebox in main thread
            self.root.after(0, lambda r_data=result_data: messagebox.showinfo(
                "Upload Complete",
                f"Public key upload attempt finished.\n"
                f"Successful: {r_data.get('success_count', 0)}\n"
                f"Failed: {r_data.get('failure_count', 0)}\n"
                "Check log for details.",
                parent=self.root
            ))

        except requests.exceptions.HTTPError as http_e:
            err_msg = f"HTTP error uploading keys: {http_e.response.status_code} for {http_e.request.url if http_e.request else 'N/A'}."
            try:
                server_err = http_e.response.json().get("error", "No specific error message from server.")
                err_msg += f" Server said: {server_err}"
            except ValueError:  # JSONDecodeError
                err_msg += f" Server raw response (not JSON): {http_e.response.text[:100]}"
            except Exception:
                err_msg += " Could not parse server error response."
            self.log_message(err_msg, "ERROR")
            self.root.after(0, lambda em=err_msg: messagebox.showerror("Upload Error", em, parent=self.root))
        except requests.exceptions.RequestException as req_e:
            failed_url = req_e.request.url if req_e.request else 'N/A'
            self.log_message(f"Network error uploading keys: {req_e} (URL: {failed_url})", "ERROR")
            self.root.after(0, lambda er=req_e: messagebox.showerror("Network Error", f"Could not upload keys: {er}",
                                                                     parent=self.root))
        except Exception as e_gen:
            self.log_message(f"Unexpected error during key upload worker: {e_gen}", "ERROR")
            self.log_message(traceback.format_exc(), "ERROR_TRACE")
            self.root.after(0, lambda eg=e_gen: messagebox.showerror("Error",
                                                                     f"An unexpected error occurred during upload: {eg}",
                                                                     parent=self.root))

    def create_submissions_tab(self):
        top_frame = ttk.Frame(self.submissions_tab)
        top_frame.pack(fill=tk.X, pady=5)
        ttk.Button(top_frame, text="Refresh Submissions List", command=self.refresh_submissions_list_threaded).pack(side=tk.LEFT, padx=5)
        columns = ("submission_id", "key_hint")
        self.submissions_tree = ttk.Treeview(self.submissions_tab, columns=columns, show="headings", height=10)
        self.submissions_tree.heading("submission_id", text="Submission ID")
        self.submissions_tree.heading("key_hint", text="Key Hint Used by Server")
        self.submissions_tree.column("submission_id", width=300, anchor="w")
        self.submissions_tree.column("key_hint", width=200, anchor="w")
        self.submissions_tree.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        self.submissions_tree.bind('<<TreeviewSelect>>', self.on_submission_select_treeview)
        decrypt_frame = ttk.Frame(self.submissions_tab)
        decrypt_frame.pack(fill=tk.X, pady=5)
        key_select_button = ttk.Button(decrypt_frame, text="Select Private Key for Decryption...", command=self.select_private_key_file)
        key_select_button.pack(side=tk.LEFT, padx=5)
        self.private_key_display_label = ttk.Label(decrypt_frame, text="No private key selected", width=30, anchor="w", relief=tk.SUNKEN, padding=2)
        self.private_key_display_label.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.decrypt_button = ttk.Button(decrypt_frame, text="Decrypt Selected Submission", command=self.decrypt_selected_submission_threaded, state=tk.DISABLED)
        self.decrypt_button.pack(side=tk.LEFT, padx=5)

    def on_submission_select_treeview(self, event): # Method definition
        selected_item_id_internal = self.submissions_tree.focus()
        if selected_item_id_internal:
            item_values = self.submissions_tree.item(selected_item_id_internal)['values']
            if item_values and len(item_values) >= 1:
                self.selected_submission_id.set(str(item_values[0]))
                key_hint_used = str(item_values[1]) if len(item_values) > 1 else "N/A"
                self.log_message(f"Submission selected: {self.selected_submission_id.get()} (Server used key hint: '{key_hint_used}')")
                if self.private_key_path.get(): self.decrypt_button.config(state=tk.NORMAL)
            else:
                self.selected_submission_id.set(""); self.decrypt_button.config(state=tk.DISABLED)
                self.log_message("Selected treeview item has no values.", "WARNING")
        else:
            self.selected_submission_id.set(""); self.decrypt_button.config(state=tk.DISABLED)

    def select_private_key_file(self): # CORRECTED THIS METHOD
        filepath = filedialog.askopenfilename(
            parent=self.root, # Good to set parent for dialogs
            initialdir=DEFAULT_PRIVATE_KEYS_DIR,
            title="Select RSA Private Key",
            filetypes=(("PEM files", "*.pem"), ("All files", "*.*"))
        )
        if filepath:
            self.private_key_path.set(filepath)
            self.private_key_display_label.config(text=os.path.basename(filepath))
            self.log_message(f"Private key selected for decryption: {os.path.basename(filepath)}")
            # Check selection in Treeview (self.submissions_tree) not self.submissions_listbox
            if self.submissions_tree.focus(): # If an item in the tree is selected/focused
                self.decrypt_button.config(state=tk.NORMAL)
        else:
            # self.private_key_path.set("") # Not strictly necessary to clear if user cancels
            # self.private_key_display_label.config(text="No private key selected") # Keep current if cancelled
            self.decrypt_button.config(state=tk.DISABLED) # Always disable if key selection is cancelled

    def refresh_submissions_list_threaded(self):
        threading.Thread(target=self.refresh_submissions_list, daemon=True).start()

    def refresh_submissions_list(self):
        self.log_message("Refreshing submissions list...")
        current_api_key = self.api_key.get()
        if not current_api_key:
            self.log_message("API Key is missing in GUI config. Cannot refresh.", "ERROR")
            self.root.after(0, lambda: messagebox.showerror("Config Error", "API Key is not set in Setup tab.", parent=self.root))
            return
        headers_for_request = {"Authorization": f"Bearer {current_api_key}"}
        try:
            response = requests.get(
                f"{self.server_url.get().rstrip('/')}/journalist/submissions",
                headers=headers_for_request, timeout=15)
            response.raise_for_status()
            data = response.json()
            self.log_message(f"RAW SERVER RESPONSE for /submissions: {data}", "DEBUG_DATA")
            for item in self.submissions_tree.get_children(): self.submissions_tree.delete(item)
            if data and "submissions" in data and isinstance(data["submissions"], list):
                submissions_list = data["submissions"]
                if submissions_list:
                    for sub_info_item in submissions_list:
                        submission_id_val = sub_info_item.get("id", "UnknownID")
                        key_hint_val = sub_info_item.get("key_hint", "N/A")
                        self.submissions_tree.insert("", tk.END, values=(submission_id_val, key_hint_val))
                    self.log_message(f"Found {len(submissions_list)} submissions.")
                else: self.log_message("No submissions found in the response list.")
            else:
                self.log_message("No 'submissions' list in server response or unexpected format.", "WARNING")
                if data: self.log_message(f"Server response received: {str(data)[:200]}", "DEBUG")
        except requests.exceptions.HTTPError as http_e:
            err_msg = f"HTTP error: {http_e.response.status_code} for {http_e.request.url}."
            try: server_err = http_e.response.json().get("error", "No details."); err_msg += f" Server: {server_err}"
            except: err_msg += f" Server raw response: {http_e.response.text[:100]}"
            self.log_message(err_msg, "ERROR")
            self.root.after(0, lambda em=err_msg: messagebox.showerror("Network Error", em, parent=self.root))
        except requests.exceptions.RequestException as req_e:
            failed_url = req_e.request.url if req_e.request else 'N/A'
            self.log_message(f"Network error refreshing submissions: {req_e} (URL: {failed_url})", "ERROR")
            self.root.after(0, lambda er=req_e: messagebox.showerror("Network Error", f"Could not refresh submissions: {er}", parent=self.root))
        except json.JSONDecodeError:
            self.log_message("Invalid JSON response from server (refreshing submissions).", "ERROR")
            self.root.after(0, lambda: messagebox.showerror("Server Error", "Invalid JSON response from server.", parent=self.root))
        except TypeError as te:
            self.log_message(f"TypeError processing submission data: {te}. Check server response format.", "ERROR")
            self.log_message(traceback.format_exc(), "ERROR_TRACE")
            self.root.after(0, lambda t=te: messagebox.showerror("Data Error", f"Error processing data: {t}", parent=self.root))
        except Exception as ex:
            self.log_message(f"Unexpected error refreshing submissions: {ex}", "ERROR")
            self.log_message(traceback.format_exc(), "ERROR_TRACE")
            self.root.after(0, lambda e=ex: messagebox.showerror("Error", f"Unexpected error: {e}", parent=self.root))

    def decrypt_selected_submission_threaded(self):
        if not self.selected_submission_id.get():
            messagebox.showwarning("No Selection", "Please select a submission to decrypt.", parent=self.root); return
        if not self.private_key_path.get():
            messagebox.showwarning("No Key", "Please select an RSA private key for decryption.", parent=self.root); return
        sub_id = self.selected_submission_id.get()
        priv_key_file = self.private_key_path.get()
        self.log_message(f"Preparing for decryption of {sub_id} using {os.path.basename(priv_key_file)}", "DEBUG")
        self.log_message(f"Attempting to read private key file: {priv_key_file}", "DEBUG")
        private_key_pem = None
        try:
            with open(priv_key_file, 'r') as f: private_key_pem = f.read()
            self.log_message("Private key file read successfully.", "DEBUG")
        except Exception as e:
            self.log_message(f"FATAL: Error reading private key file: {e}", "ERROR")
            messagebox.showerror("Key Error", f"Could not read private key: {e}", parent=self.root); return
        self.log_message("Prompting for private key password (GUI Thread)...", "DEBUG")
        priv_key_password_input = simpledialog.askstring(
            "Private Key Password", f"Enter password for {os.path.basename(priv_key_file)}\n(Leave blank if not password-protected):",
            parent=self.root, show='*')
        if priv_key_password_input is None:
            self.log_message("Decryption cancelled by user at password prompt.", "INFO"); return
        actual_priv_key_password = priv_key_password_input if priv_key_password_input else None
        self.log_message("Password dialog returned. Starting worker thread for decryption.", "DEBUG")
        threading.Thread(target=self.decrypt_selected_submission_worker,
            args=(sub_id, private_key_pem, actual_priv_key_password), daemon=True).start()

    def decrypt_selected_submission_worker(self, sub_id, private_key_pem_content, priv_key_password):
        self.log_message(f"Worker thread started for decryption of {sub_id}.", "DEBUG")
        current_api_key = self.api_key.get()
        if not current_api_key:
            self.log_message("API Key is missing in GUI config. Cannot proceed.", "ERROR")
            self.root.after(0, lambda: messagebox.showerror("Config Error", "API Key is not set in Setup tab.", parent=self.root))
            return
        headers_req = {"Authorization": f"Bearer {current_api_key}"}
        base_server_url = self.server_url.get().rstrip('/')
        self.log_message("Entering main decryption network/crypto block (Worker Thread)...", "DEBUG")
        try:
            package_info_url = urllib.parse.urljoin(base_server_url + '/', f"journalist/submission/{sub_id}/package")
            self.log_message(f"Fetching package info from: {package_info_url}", "DEBUG")
            resp_pkg = requests.get(package_info_url, headers=headers_req, timeout=15)
            resp_pkg.raise_for_status(); package_data = resp_pkg.json()
            self.log_message(f"Package info fetched: {str(package_data)[:200]}...", "DEBUG") # Log some of package_data

            enc_aes_key_url = package_data['encrypted_aes_key_url']
            enc_file_url = package_data['encrypted_file_url']
            enc_filename_url = package_data['encrypted_filename_url']

            self.log_message(f"Downloading AES key from {enc_aes_key_url}", "DEBUG")
            resp_key = requests.get(enc_aes_key_url, headers=headers_req, timeout=20); resp_key.raise_for_status()
            encrypted_aes_key_data = resp_key.content; self.log_message("AES key downloaded.", "DEBUG")

            self.log_message(f"Downloading filename from {enc_filename_url}", "DEBUG")
            resp_fname = requests.get(enc_filename_url, headers=headers_req, timeout=20); resp_fname.raise_for_status()
            encrypted_original_filename_data = resp_fname.content; self.log_message("Encrypted filename downloaded.", "DEBUG")

            self.log_message(f"Downloading file from {enc_file_url}", "DEBUG")
            resp_file = requests.get(enc_file_url, headers=headers_req, timeout=180); resp_file.raise_for_status()
            encrypted_file_data = resp_file.content; self.log_message("Encrypted file downloaded.", "DEBUG")

            self.log_message("Decrypting AES key (locally)...", "DEBUG")
            decrypted_aes_key = crypto_utils.decrypt_rsa(encrypted_aes_key_data, private_key_pem_content, priv_key_password)
            if not decrypted_aes_key:
                self.log_message("Failed to decrypt AES key. Wrong password or key mismatch.", "ERROR")
                self.root.after(0, lambda: messagebox.showerror("Decryption Error","Failed to decrypt AES key. Check password or key.", parent=self.root)); return
            self.log_message("AES key decrypted.", "DEBUG")

            self.log_message("Decrypting original filename (locally)...", "DEBUG")
            decrypted_original_filename_bytes = crypto_utils.decrypt_aes_gcm(encrypted_original_filename_data, decrypted_aes_key)
            original_filename = f"{sub_id}_decrypted.dat"
            if decrypted_original_filename_bytes:
                original_filename = decrypted_original_filename_bytes.decode('utf-8', errors='replace')
                self.log_message(f"Original filename: {original_filename}", "DEBUG")
            else: self.log_message("Failed to decrypt original filename. Using generic.", "WARNING")

            self.log_message(f"Decrypting content for '{original_filename}' (locally)...", "DEBUG")
            decrypted_file_data = crypto_utils.decrypt_aes_gcm(encrypted_file_data, decrypted_aes_key)
            if not decrypted_file_data:
                self.log_message("Failed to decrypt file data. AES key incorrect/data corrupted.", "ERROR")
                self.root.after(0, lambda: messagebox.showerror("Decryption Error", "Failed to decrypt file data.", parent=self.root)); return
            self.log_message("File content decrypted.", "SUCCESS")

            def ask_save_file_main_thread():
                save_path = filedialog.asksaveasfilename(parent=self.root, initialdir=DEFAULT_DOWNLOAD_DIR,
                    initialfile=original_filename, title="Save Decrypted File As", defaultextension=".*")
                if save_path:
                    try:
                        with open(save_path, 'wb') as f: f.write(decrypted_file_data)
                        self.log_message(f"File saved: {save_path}", "SUCCESS")
                        messagebox.showinfo("Success", f"File saved:\n{save_path}", parent=self.root)
                    except IOError as ioe:
                        self.log_message(f"IOError saving: {ioe}", "ERROR")
                        messagebox.showerror("Save Error", f"Could not save: {ioe}", parent=self.root)
                else: self.log_message("Save cancelled.")
            self.root.after(0, ask_save_file_main_thread)
        except requests.exceptions.HTTPError as http_e:
            err_msg = f"HTTP error: {http_e.response.status_code} for {http_e.request.url}."
            try: server_err = http_e.response.json().get("error", "No details."); err_msg += f" Server: {server_err}"
            except: err_msg += f" Server raw response: {http_e.response.text[:100]}"
            self.log_message(err_msg, "ERROR")
            self.root.after(0, lambda em=err_msg: messagebox.showerror("Network Error", em, parent=self.root))
        except requests.exceptions.RequestException as req_e:
            failed_url = req_e.request.url if req_e.request else 'N/A'
            self.log_message(f"Network error: {req_e} (URL: {failed_url})", "ERROR")
            self.root.after(0, lambda er=req_e: messagebox.showerror("Network Error", f"Could not download: {er}", parent=self.root))
        except Exception as e_gen:
            self.log_message(f"Unexpected error in decryption worker: {e_gen}", "ERROR")
            self.log_message(traceback.format_exc(), "ERROR_TRACE")
            self.root.after(0, lambda eg=e_gen: messagebox.showerror("Error", f"Unexpected error: {eg}", parent=self.root))

    def create_keys_tab(self):
        frame = ttk.LabelFrame(self.keys_tab, text="Generate My RSA Key Pairs", padding=10)
        frame.pack(padx=5, pady=5, fill=tk.X)
        ttk.Label(frame, text="Number of New Key Pairs:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.num_keys_var = tk.StringVar(value="1")
        ttk.Entry(frame, textvariable=self.num_keys_var, width=5).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Label(frame, text="Key Filename Prefix:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.key_prefix_var = tk.StringVar(value="journalist_gui_key")
        ttk.Entry(frame, textvariable=self.key_prefix_var, width=25).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        self.password_protect_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Password-protect new private keys", variable=self.password_protect_var).grid(row=2, column=0, columnspan=2, pady=5, sticky=tk.W)
        ttk.Button(frame, text="Generate Key Pairs", command=self.generate_keys_threaded).grid(row=3, column=0, columnspan=2, pady=10)
        info_frame = ttk.Frame(self.keys_tab, padding=5)
        info_frame.pack(fill=tk.X)
        ttk.Label(info_frame, text=f"Private keys saved to: '{os.path.basename(DEFAULT_PRIVATE_KEYS_DIR)}'").pack(anchor='w')
        ttk.Label(info_frame, text=f"Public keys (for server) saved to: '{os.path.basename(DEFAULT_PUBLIC_KEYS_FOR_SERVER_DIR)}'").pack(anchor='w')
        ttk.Label(info_frame, text="Use 'Server Setup & Admin' tab to upload public keys to the server.").pack(anchor='w', pady=(0,5))
        pubkey_display_frame = ttk.LabelFrame(self.keys_tab, text="Content of Last Generated Public Keys", padding=5)
        pubkey_display_frame.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        self.generated_pubkeys_text = scrolledtext.ScrolledText(pubkey_display_frame, height=6, state=tk.DISABLED, wrap=tk.WORD)
        self.generated_pubkeys_text.pack(fill=tk.BOTH, expand=True)
        self.generated_pubkeys_text.insert(tk.END,"Public key content will appear here after generation...\n"); self.generated_pubkeys_text.config(state=tk.DISABLED)

    def generate_keys_threaded(self):
        try:
            num_keys = int(self.num_keys_var.get())
            if num_keys <= 0: messagebox.showerror("Invalid Input", "Number of keys must be positive.", parent=self.root); return
        except ValueError: messagebox.showerror("Invalid Input", "Number of keys must be a valid integer.", parent=self.root); return
        key_prefix = self.key_prefix_var.get().strip()
        if not key_prefix: messagebox.showerror("Invalid Input", "Key ID prefix cannot be empty.", parent=self.root); return
        password = None
        if self.password_protect_var.get():
            password = simpledialog.askstring("Set Key Password", "Enter password for new private keys:", parent=self.root, show='*')
            if password is None: self.log_message("Key generation cancelled by user."); return
            if not password:
                if messagebox.askyesno("Password Empty", "Password is empty. Generate keys WITHOUT password protection?", parent=self.root): password = None
                else: self.log_message("Key generation aborted (empty password not accepted)."); return
        threading.Thread(target=self.generate_keys_worker, args=(num_keys, key_prefix, password), daemon=True).start()

    def generate_keys_worker(self, num_keys, key_prefix, password):
        self.log_message(f"Generating {num_keys} key pair(s) with prefix '{key_prefix}'...")
        all_pub_keys_text_content = ""
        for i in range(1, num_keys + 1):
            self.log_message(f"Generating pair {i}...", "DEBUG")
            try:
                pub_path_for_server, priv_path = rsa_gen_module.generate_rsa_key_pair(
                    key_id_prefix=key_prefix, key_index=i, password=password)
                with open(pub_path_for_server, 'r') as f_pub: pub_key_content = f_pub.read()
                all_pub_keys_text_content += f"--- Public Key for {os.path.basename(pub_path_for_server)} ---\n{pub_key_content}\n\n"
                self.log_message(f"Generated: {os.path.basename(priv_path)} and {os.path.basename(pub_path_for_server)}")
            except Exception as e:
                self.log_message(f"Error generating key pair {i}: {e}", "ERROR")
                self.root.after(0, lambda err=e, idx=i: messagebox.showerror("Key Generation Error", f"Failed for pair {idx}: {err}", parent=self.root))
                return
        def update_gui_after_gen():
            self.generated_pubkeys_text.config(state=tk.NORMAL); self.generated_pubkeys_text.delete('1.0', tk.END)
            self.generated_pubkeys_text.insert(tk.END, all_pub_keys_text_content); self.generated_pubkeys_text.config(state=tk.DISABLED)
            self.log_message(f"{num_keys} pairs generated. Private keys in '{os.path.basename(DEFAULT_PRIVATE_KEYS_DIR)}', public keys in '{os.path.basename(DEFAULT_PUBLIC_KEYS_FOR_SERVER_DIR)}'.", "SUCCESS")
            messagebox.showinfo("Key Generation Complete", f"{num_keys} key pair(s) generated.", parent=self.root)
        self.root.after(0, update_gui_after_gen)

# No `generate_keys` method was present in the provided snippet,
# the threaded one calls generate_keys_worker.

if __name__ == '__main__':
    root = tk.Tk()
    app = JournalistApp(root)
    root.mainloop()