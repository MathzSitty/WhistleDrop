# whistledrop/journalist_tool/journalist_gui.py
import tkinter as tk
from tkinter import ttk, filedialog, simpledialog, messagebox, scrolledtext
import os
import sys
import threading
import json
import time
import traceback
import keyring
from pathlib import Path
import requests  # For fetching metadata from Journalist Interface via Tor
import socks  # PySocks for requests via Tor
import socket  # For configuring socks

# Adjust path for imports
current_script_dir = Path(__file__).parent.resolve()
project_root_dir = current_script_dir.parent
if str(project_root_dir) not in sys.path:
    sys.path.insert(0, str(project_root_dir))

from utils import generate_rsa_keys as rsa_encryption_key_gen_module
from journalist_tool import crypto_utils

# --- Configuration and Constants ---
CONFIG_FILE_NAME = "gui_config.json"
CONFIG_FILE_PATH = current_script_dir / CONFIG_FILE_NAME

DEFAULT_LOCAL_ENCRYPTED_SUBMISSIONS_IMPORT_DIR = "local_encrypted_submissions_import"
DEFAULT_LOCAL_DECRYPTED_SUBMISSIONS_OUTPUT_DIR = "decrypted_submissions"
DEFAULT_RSA_PRIVATE_KEYS_DIR = "private_keys"
DEFAULT_RSA_PUBLIC_KEYS_FOR_SERVER_DIR = "public_keys_for_server"

DEFAULT_TOR_SOCKS_HOST = "127.0.0.1"
DEFAULT_TOR_SOCKS_PORT = 9150

# Expected filenames within a local (imported) submission directory
LOCAL_ENCRYPTED_FILE_NAME = "encrypted_file.dat"
LOCAL_ENCRYPTED_AES_KEY_NAME = "encrypted_aes_key.dat"
LOCAL_ENCRYPTED_ORIGINAL_FILENAME_NAME = "encrypted_filename.dat"
LOCAL_RSA_PUBLIC_KEY_HINT_NAME = "rsa_public_key_hint.txt"


# --- ToolTip Class (same as before) ---
class ToolTip:
    def __init__(self, widget, text, font_config=None):
        self.widget = widget;
        self.text = text;
        self.tipwindow = None
        self.font = font_config if font_config else ("Segoe UI", 8, "normal")

    def showtip(self, event=None):
        self.hidetip()
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25;
        y += self.widget.winfo_rooty() + 20
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(1);
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify=tk.LEFT, background="#FFFFE0",
                         relief=tk.SOLID, borderwidth=1, font=self.font, wraplength=350)
        label.pack(ipadx=3, ipady=2)

    def hidetip(self, event=None):
        if self.tipwindow: self.tipwindow.destroy()
        self.tipwindow = None


# --- Main Application Class ---
class JournalistApp:
    def __init__(self, root_window):
        self.root = root_window
        self.root.title("WhistleDrop Journalist Tool (SecureDrop-Workflow Edition)")
        self.root.geometry("1050x900")

        # --- Theme Colors & Styles (same as previous GUI version) ---
        self.bg_color = '#FAF8F1';
        self.border_color = '#FFFFFF'
        self.frame_bg_color = '#F3EADA';
        self.accent_color_primary = '#E87A00'
        self.accent_hover_primary = '#D36F00';
        self.accent_color_secondary = '#8C5A32';
        self.accent_hover_secondary = '#754C24'
        self.text_color = '#5D4037';
        self.header_text_color = self.accent_color_secondary
        '; self.border_color = '  # D1C0A8'
        self.entry_bg_color = '#FFFDF9';
        self.button_text_color_on_orange = '#FFFFFF';
        self.button_text_color_on_brown = '#FAF8F1'
        self.disabled_fg_color = '#9E9E9E';
        self.tooltip_font = ("Segoe UI", 9, "normal")
        self.root.configure(bg=self.bg_color)
        self.style = ttk.Style();
        self.style.theme_use('clam')
        self.default_font = ("Segoe UI", 10);
        self.bold_font = ("Segoe UI", 10, "bold");
        self.log_font = ("Consolas", 9)
        self.root.option_add("*Font", self.default_font)
        # ... (Full ttk style configuration as in previous GUI version, adapted for new elements if any) ...
        self.style.configure(".", font=self.default_font, background=self.bg_color, foreground=self.text_color)
        self.style.configure("TFrame", background=self.frame_bg_color)
        self.style.configure("TLabel", background=self.frame_bg_color, foreground=self.text_color, padding=3)
        self.style.configure("TLabelframe", background=self.frame_bg_color, bordercolor=self.border_color,
                             font=self.bold_font, relief="groove", borderwidth=1, padding=10)
        self.style.configure("TLabelframe.Label", background=self.frame_bg_color, foreground=self.header_text_color,
                             font=self.bold_font, padding=(0, 0, 0, 5))
        self.style.configure("TButton", font=self.default_font, padding=(12, 6), background=self.accent_color_primary,
                             foreground=self.button_text_color_on_orange, relief="raised", borderwidth=1,
                             bordercolor=self.accent_color_primary)
        self.style.map("TButton",
                       background=[('active', self.accent_hover_primary), ('pressed', self.accent_hover_primary),
                                   ('disabled', self.frame_bg_color)],
                       foreground=[('disabled', self.disabled_fg_color)],
                       bordercolor=[('active', self.accent_hover_primary)],
                       relief=[('pressed', 'sunken'), ('!pressed', 'raised')])
        self.style.configure("Secondary.TButton", font=self.default_font, padding=(10, 5),
                             background=self.accent_color_secondary, foreground=self.button_text_color_on_brown,
                             relief="raised", borderwidth=1, bordercolor=self.accent_color_secondary)
        self.style.map("Secondary.TButton",
                       background=[('active', self.accent_hover_secondary), ('pressed', self.accent_hover_secondary),
                                   ('disabled', self.frame_bg_color)],
                       foreground=[('disabled', self.disabled_fg_color)],
                       bordercolor=[('active', self.accent_hover_secondary)], relief=[('pressed', 'sunken')])
        self.style.configure("TEntry", font=self.default_font, padding=6, fieldbackground=self.entry_bg_color,
                             foreground=self.text_color, borderwidth=1, relief="solid", bordercolor=self.border_color)
        self.style.map("TEntry", bordercolor=[('focus', self.accent_color_primary)],
                       fieldbackground=[('disabled', self.frame_bg_color)],
                       foreground=[('disabled', self.disabled_fg_color)],
                       selectbackground=[('focus', self.accent_color_primary)],
                       selectforeground=[('focus', self.button_text_color_on_orange)])
        self.style.configure("TNotebook", background=self.bg_color, borderwidth=0, tabmargins=[2, 5, 2, 0])
        self.style.configure("TNotebook.Tab", font=self.default_font, padding=(15, 7), background=self.frame_bg_color,
                             foreground=self.text_color, borderwidth=1)
        self.style.map("TNotebook.Tab", background=[("selected", self.bg_color)],
                       foreground=[("selected", self.accent_color_primary)],
                       bordercolor=[("selected", self.accent_color_primary), ("!selected", self.border_color)],
                       lightcolor=[("selected", self.bg_color)], font=[("selected", self.bold_font)])
        self.style.configure("Treeview", font=self.default_font, rowheight=28, fieldbackground=self.entry_bg_color,
                             foreground=self.text_color, borderwidth=1, relief="solid", bordercolor=self.border_color)
        self.style.configure("Treeview.Heading", font=self.bold_font, background=self.frame_bg_color,
                             foreground=self.header_text_color, padding=7, relief="raised", borderwidth=1)
        self.style.map("Treeview.Heading", background=[('active', self.accent_color_secondary)],
                       foreground=[('active', self.button_text_color_on_brown)])
        self.style.configure("PrivateKeyDisplay.TLabel", background=self.entry_bg_color, foreground=self.text_color,
                             borderwidth=1, relief="sunken", padding=(6, 5), font=self.default_font, anchor="w")
        self.style.configure("TCheckbutton", background=self.frame_bg_color, foreground=self.text_color,
                             indicatorrelief="flat", indicatormargin=5, font=self.default_font)
        self.style.map("TCheckbutton", indicatorbackground=[('selected', self.accent_color_primary),
                                                            ('!selected', self.entry_bg_color)],
                       indicatorforeground=[('selected', self.button_text_color_on_orange)])
        self.log_text_area_config = {"font": self.log_font, "bg": self.entry_bg_color, "fg": self.text_color,
                                     "relief": "solid", "borderwidth": 1, "highlightthickness": 1,
                                     "highlightbackground": self.border_color,
                                     "highlightcolor": self.accent_color_primary, "insertbackground": self.text_color,
                                     "selectbackground": self.accent_color_secondary,
                                     "selectforeground": self.button_text_color_on_brown}

        # --- Application Variables ---
        self.journalist_interface_url = tk.StringVar()
        self.journalist_api_key = tk.StringVar()  # For Journalist Interface
        self.tor_socks_host = tk.StringVar()
        self.tor_socks_port = tk.IntVar()
        self.local_encrypted_submissions_import_dir = tk.StringVar()
        self.local_decrypted_submissions_output_dir = tk.StringVar()
        self.default_rsa_private_keys_dir_var = tk.StringVar()  # For RSA content decryption keys

        self.rsa_private_key_for_decryption_path = tk.StringVar()  # Path to selected RSA key for content decryption
        self.selected_local_submission_id = tk.StringVar()  # ID of submission selected in local Treeview

        # --- UI Elements ---
        self.log_text_frame = ttk.LabelFrame(root_window, text="Application Log", style="TLabelframe")
        self.log_text = scrolledtext.ScrolledText(self.log_text_frame, height=8, state=tk.DISABLED, wrap=tk.WORD,
                                                  **self.log_text_area_config)
        self.load_config()  # Load settings from JSON

        self.notebook = ttk.Notebook(root_window, style="TNotebook")
        self.setup_tab = ttk.Frame(self.notebook, padding=(15, 10), style="TFrame")
        self.submissions_tab = ttk.Frame(self.notebook, padding=(15, 10), style="TFrame")
        self.rsa_keys_tab = ttk.Frame(self.notebook, padding=(15, 10), style="TFrame")

        self.notebook.add(self.setup_tab, text=' Settings & Server Interface ')
        self.notebook.add(self.submissions_tab, text=' Local Submissions & Decryption ')
        self.notebook.add(self.rsa_keys_tab, text=' RSA Encryption Key Generation ')
        self.notebook.pack(expand=True, fill='both', padx=10, pady=(10, 5))

        self.create_setup_tab_content()
        self.create_submissions_tab_content()
        self.create_rsa_keys_tab_content()

        self.log_text_frame.pack(pady=(5, 10), padx=10, fill=tk.X)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        if not hasattr(self, 'initial_log_done'):
            self.log_message("Journalist Tool GUI Initialized (SecureDrop-Workflow Edition).")
            self.log_message(
                "Configure Journalist Interface URL, API Key, Tor SOCKS, and local directories in 'Settings' tab.")
            self.initial_log_done = True

    # --- Helper Methods (Logging, Config, Tooltips, API Client) ---
    def log_message(self, message: str, level: str = "INFO"):  # (Same as before)
        if hasattr(self, 'log_text') and self.log_text:
            self.log_text.config(state=tk.NORMAL);
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            self.log_text.insert(tk.END, f"[{timestamp} {level}] {message}\n");
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
        else:
            print(f"LOG_EARLY [{level}]: {message}")

    def load_config(self):  # Adapted for new config structure
        defaults = {
            "journalist_interface_url": "https://yourwhistledrop.onion/wd-journalist",
            "journalist_api_key": "",
            "tor_socks_host": DEFAULT_TOR_SOCKS_HOST, "tor_socks_port": DEFAULT_TOR_SOCKS_PORT,
            "local_encrypted_submissions_import_dir": str(
                Path(current_script_dir, DEFAULT_LOCAL_ENCRYPTED_SUBMISSIONS_IMPORT_DIR)),
            "local_decrypted_submissions_output_dir": str(
                Path(current_script_dir, DEFAULT_LOCAL_DECRYPTED_SUBMISSIONS_OUTPUT_DIR)),
            "default_rsa_private_keys_dir": str(Path(current_script_dir, DEFAULT_RSA_PRIVATE_KEYS_DIR))
        }
        try:
            if CONFIG_FILE_PATH.exists():
                with open(CONFIG_FILE_PATH, 'r') as f:
                    config_data = json.load(f)
                current_config = {**defaults, **config_data}
                self.log_message(f"Config loaded from '{CONFIG_FILE_PATH}'.", "INFO")
            else:
                current_config = defaults
                self.log_message(f"Config file '{CONFIG_FILE_PATH}' not found. Using defaults.", "INFO")
                self._save_config_data(current_config)  # Save defaults

            self.journalist_interface_url.set(current_config["journalist_interface_url"])
            # API key: try keyring first, then config file (for backward compatibility or if keyring fails)
            stored_api_key = keyring.get_password("whistledrop_journalist", "journalist_interface_api_key")
            if stored_api_key:
                self.journalist_api_key.set(stored_api_key)
            else:
                self.journalist_api_key.set(current_config.get("journalist_api_key", ""))  # Fallback to config

            self.tor_socks_host.set(current_config["tor_socks_host"])
            self.tor_socks_port.set(int(current_config["tor_socks_port"]))
            self.local_encrypted_submissions_import_dir.set(current_config["local_encrypted_submissions_import_dir"])
            self.local_decrypted_submissions_output_dir.set(current_config["local_decrypted_submissions_output_dir"])
            self.default_rsa_private_keys_dir_var.set(current_config["default_rsa_private_keys_dir"])

            for dir_path_str in [self.local_encrypted_submissions_import_dir.get(),
                                 self.local_decrypted_submissions_output_dir.get(),
                                 self.default_rsa_private_keys_dir_var.get(),
                                 str(Path(current_script_dir, DEFAULT_RSA_PUBLIC_KEYS_FOR_SERVER_DIR))]:
                Path(dir_path_str).mkdir(parents=True, exist_ok=True)

        except (json.JSONDecodeError, ValueError, TypeError) as e:
            self.log_message(f"Error decoding config '{CONFIG_FILE_PATH}': {e}. Using defaults & re-saving.", "ERROR")
            self._apply_and_save_defaults(defaults)
        except Exception as e:
            self.log_message(f"Unexpected error loading config: {e}. Using defaults.", "ERROR")
            self._apply_and_save_defaults(defaults)

    def _apply_and_save_defaults(self, defaults):  # (Same as before)
        self.journalist_interface_url.set(defaults["journalist_interface_url"])
        self.journalist_api_key.set(defaults["journalist_api_key"])  # API key from defaults
        self.tor_socks_host.set(defaults["tor_socks_host"]);
        self.tor_socks_port.set(defaults["tor_socks_port"])
        self.local_encrypted_submissions_import_dir.set(defaults["local_encrypted_submissions_import_dir"])
        self.local_decrypted_submissions_output_dir.set(defaults["local_decrypted_submissions_output_dir"])
        self.default_rsa_private_keys_dir_var.set(defaults["default_rsa_private_keys_dir"])
        self._save_config_data(defaults)

    def _save_config_data(self, config_data_dict):  # (Same as before)
        try:
            with open(CONFIG_FILE_PATH, 'w') as f:
                json.dump(config_data_dict, f, indent=4)
            self.log_message(f"Config saved to '{CONFIG_FILE_PATH}'.", "INFO")
        except IOError as e:
            self.log_message(f"Error saving config to '{CONFIG_FILE_PATH}': {e}", "ERROR")
            messagebox.showerror("Save Error", f"Could not save config: {e}", parent=self.root)

    def save_current_config_action(self):  # Adapted for new config structure
        try:
            tor_port_val = self.tor_socks_port.get()
            if not (0 < tor_port_val < 65536):
                messagebox.showerror("Invalid Port", "Tor SOCKS Port must be between 1 and 65535.", parent=self.root);
                return
        except tk.TclError:
            messagebox.showerror("Invalid Port", "Tor SOCKS Port must be a valid number.", parent=self.root);
            return

        current_api_key_val = self.journalist_api_key.get()
        save_api_key_to_file = False
        if current_api_key_val:
            try:
                keyring.set_password("whistledrop_journalist", "journalist_interface_api_key", current_api_key_val)
                self.log_message("API key for Journalist Interface securely stored in system keyring.", "INFO")
            except Exception as e_keyring:
                self.log_message(f"Warning: Could not store API key in system keyring: {e_keyring}", "WARNING")
                if messagebox.askyesno("Security Warning", "Could not store API key securely in system keyring.\n"
                                                           "Store it in the config file as plain text instead?\n(Not recommended)",
                                       parent=self.root):
                    save_api_key_to_file = True

        current_config_data = {
            "journalist_interface_url": self.journalist_interface_url.get(),
            "journalist_api_key": current_api_key_val if save_api_key_to_file else "",
            # Only save to file if keyring failed AND user agreed
            "tor_socks_host": self.tor_socks_host.get(), "tor_socks_port": self.tor_socks_port.get(),
            "local_encrypted_submissions_import_dir": self.local_encrypted_submissions_import_dir.get(),
            "local_decrypted_submissions_output_dir": self.local_decrypted_submissions_output_dir.get(),
            "default_rsa_private_keys_dir": self.default_rsa_private_keys_dir_var.get()
        }
        self._save_config_data(current_config_data)
        for dir_path_str in [self.local_encrypted_submissions_import_dir.get(),
                             self.local_decrypted_submissions_output_dir.get(),
                             self.default_rsa_private_keys_dir_var.get()]:
            Path(dir_path_str).mkdir(parents=True, exist_ok=True)
        messagebox.showinfo("Configuration Saved", "Settings have been saved.", parent=self.root)

    def create_tooltip_for_widget(self, widget, text):  # (Same as before)
        ToolTip(widget, text, font_config=self.tooltip_font).create()

    def _get_requests_session_with_tor_proxy(self) -> requests.Session | None:
        """Configures a requests session to use the Tor SOCKS proxy."""
        host = self.tor_socks_host.get()
        try:
            port = self.tor_socks_port.get()
        except tk.TclError:
            self.log_message("Invalid Tor SOCKS port in settings.", "ERROR");
            return None
        if not host or not (0 < port < 65536):
            self.log_message("Tor SOCKS proxy host or port invalid.", "ERROR");
            return None

        session = requests.Session()
        session.proxies = {'http': f'socks5h://{host}:{port}', 'https': f'socks5h://{host}:{port}'}
        self.log_message(f"Requests session configured for Tor proxy: socks5h://{host}:{port}", "DEBUG")
        return session

    # --- Tab Creation Methods ---
    def create_setup_tab_content(self):  # Heavily adapted
        # Frame for Journalist Interface Connection
        server_if_frame = ttk.LabelFrame(self.setup_tab, text="WhistleDrop Server - Journalist Interface (Metadaten)",
                                         padding=15, style="TLabelframe")
        server_if_frame.pack(padx=5, pady=10, fill=tk.X)
        ttk.Label(server_if_frame, text="Interface URL (.onion):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        if_url_entry = ttk.Entry(server_if_frame, textvariable=self.journalist_interface_url, width=50)
        if_url_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        self.create_tooltip_for_widget(if_url_entry,
                                       "Full HTTPS URL of the Journalist Interface (e.g., https://your.onion/wd-journalist).")

        ttk.Label(server_if_frame, text="API Key:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        api_key_entry = ttk.Entry(server_if_frame, textvariable=self.journalist_api_key, width=50, show="*")
        api_key_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        self.create_tooltip_for_widget(api_key_entry,
                                       "API Key provided by your server administrator for accessing the Journalist Interface.")
        server_if_frame.columnconfigure(1, weight=1)

        # Frame for Tor SOCKS Proxy (still needed for Journalist Interface access)
        tor_proxy_frame = ttk.LabelFrame(self.setup_tab, text="Tor SOCKS Proxy (for Journalist Interface)", padding=15,
                                         style="TLabelframe")
        tor_proxy_frame.pack(padx=5, pady=10, fill=tk.X)
        # ... (Tor SOCKS Host/Port entries as in previous SFTP GUI version) ...
        ttk.Label(tor_proxy_frame, text="SOCKS Host:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        tor_host_entry = ttk.Entry(tor_proxy_frame, textvariable=self.tor_socks_host, width=20)
        tor_host_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW);
        self.create_tooltip_for_widget(tor_host_entry, "Usually 127.0.0.1")
        ttk.Label(tor_proxy_frame, text="SOCKS Port:").grid(row=0, column=2, padx=(10, 5), pady=5, sticky=tk.W)
        tor_port_entry = ttk.Entry(tor_proxy_frame, textvariable=self.tor_socks_port, width=8)
        tor_port_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W);
        self.create_tooltip_for_widget(tor_port_entry, "e.g., 9150 (Tor Browser) or 9050 (system Tor)")
        tor_proxy_frame.columnconfigure(1, weight=1)

        # Frame for Local Directory Settings
        local_dirs_frame = ttk.LabelFrame(self.setup_tab, text="Local Directory Settings (for SecureDrop Workflow)",
                                          padding=15, style="TLabelframe")
        local_dirs_frame.pack(padx=5, pady=10, fill=tk.X)
        # ... (Entries for local_encrypted_submissions_import_dir, local_decrypted_submissions_output_dir, default_rsa_private_keys_dir_var with Browse buttons) ...
        # Example for one:
        ttk.Label(local_dirs_frame, text="Import Dir (Encrypted):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        import_dir_frame = ttk.Frame(local_dirs_frame, style="TFrame")
        import_dir_frame.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        import_dir_entry = ttk.Entry(import_dir_frame, textvariable=self.local_encrypted_submissions_import_dir,
                                     width=40)
        import_dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True);
        self.create_tooltip_for_widget(import_dir_entry,
                                       "Directory where you place encrypted submissions exported by the admin.")
        ttk.Button(import_dir_frame, text="Browse...",
                   command=lambda: self._select_directory_action(self.local_encrypted_submissions_import_dir,
                                                                 "Select Import Directory for Encrypted Submissions"),
                   style="Secondary.TButton").pack(side=tk.LEFT, padx=(5, 0))
        # Repeat for local_decrypted_submissions_output_dir and default_rsa_private_keys_dir_var
        ttk.Label(local_dirs_frame, text="Output Dir (Decrypted):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        output_dir_frame = ttk.Frame(local_dirs_frame, style="TFrame")
        output_dir_frame.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        output_dir_entry = ttk.Entry(output_dir_frame, textvariable=self.local_decrypted_submissions_output_dir,
                                     width=40)
        output_dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True);
        self.create_tooltip_for_widget(output_dir_entry, "Directory where successfully decrypted files will be saved.")
        ttk.Button(output_dir_frame, text="Browse...",
                   command=lambda: self._select_directory_action(self.local_decrypted_submissions_output_dir,
                                                                 "Select Output Directory for Decrypted Files"),
                   style="Secondary.TButton").pack(side=tk.LEFT, padx=(5, 0))

        ttk.Label(local_dirs_frame, text="RSA Private Keys Dir:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        rsa_keys_dir_frame = ttk.Frame(local_dirs_frame, style="TFrame")
        rsa_keys_dir_frame.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)
        rsa_keys_dir_entry = ttk.Entry(rsa_keys_dir_frame, textvariable=self.default_rsa_private_keys_dir_var, width=40)
        rsa_keys_dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True);
        self.create_tooltip_for_widget(rsa_keys_dir_entry,
                                       "Default directory containing your private RSA keys for decrypting submission content.")
        ttk.Button(rsa_keys_dir_frame, text="Browse...",
                   command=lambda: self._select_directory_action(self.default_rsa_private_keys_dir_var,
                                                                 "Select Default Directory for RSA Private Keys"),
                   style="Secondary.TButton").pack(side=tk.LEFT, padx=(5, 0))
        local_dirs_frame.columnconfigure(1, weight=1)

        save_button = ttk.Button(self.setup_tab, text="Save All Settings", command=self.save_current_config_action,
                                 style="TButton")
        save_button.pack(pady=(20, 5));
        self.create_tooltip_for_widget(save_button, "Save all settings to the configuration file.")

    def create_submissions_tab_content(self):  # Heavily adapted for local workflow
        # Top frame for controls
        top_controls_frame = ttk.Frame(self.submissions_tab, style="TFrame")
        top_controls_frame.pack(fill=tk.X, pady=(0, 10))

        refresh_local_button = ttk.Button(top_controls_frame, text="Refresh Local Submissions List",
                                          command=self._refresh_local_submissions_list_action,
                                          style="Secondary.TButton")
        refresh_local_button.pack(side=tk.LEFT, padx=(0, 10));
        self.create_tooltip_for_widget(refresh_local_button,
                                       "Scan the 'Local Encrypted Submissions Import Dir' for new submission packages.")

        fetch_server_meta_button = ttk.Button(top_controls_frame, text="Fetch New Submission Info from Server",
                                              command=self._fetch_server_metadata_threaded_action,
                                              style="Secondary.TButton")
        fetch_server_meta_button.pack(side=tk.LEFT);
        self.create_tooltip_for_widget(fetch_server_meta_button,
                                       "Connect to the Journalist Interface (via Tor) to get a list of submission metadata from the server.")

        # Treeview for displaying submissions (both local and server-fetched for comparison)
        columns = ("submission_id", "status", "timestamp_utc", "key_hint")
        self.submissions_tree = ttk.Treeview(self.submissions_tab, columns=columns, show="headings", height=15,
                                             style="Treeview")
        self.submissions_tree.heading("submission_id", text="Submission ID");
        self.submissions_tree.column("submission_id", width=280, anchor="w")
        self.submissions_tree.heading("status", text="Status");
        self.submissions_tree.column("status", width=120, anchor="w")  # e.g., "Local", "Server Only"
        self.submissions_tree.heading("timestamp_utc", text="Timestamp (UTC)");
        self.submissions_tree.column("timestamp_utc", width=180, anchor="w")
        self.submissions_tree.heading("key_hint", text="RSA Key Hint");
        self.submissions_tree.column("key_hint", width=200, anchor="w")
        # ... (Scrollbar setup as before) ...
        tree_scrollbar_y = ttk.Scrollbar(self.submissions_tab, orient="vertical", command=self.submissions_tree.yview)
        self.submissions_tree.configure(yscrollcommand=tree_scrollbar_y.set)
        self.submissions_tree.pack(side=tk.LEFT, padx=0, pady=5, fill=tk.BOTH, expand=True)
        tree_scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y, pady=(5, 0))
        self.submissions_tree.bind('<<TreeviewSelect>>', self._on_local_submission_select_action)  # Renamed action

        # Decryption controls (similar to before, but operate on selected local submission)
        decrypt_frame = ttk.Frame(self.submissions_tab, style="TFrame", padding=(0, 10))
        decrypt_frame.pack(fill=tk.X, pady=(15, 0))
        # ... (RSA Private Key selection for DECRYPTION, Decrypt button - logic adapted for local files) ...
        key_select_button = ttk.Button(decrypt_frame, text="Select RSA Private Key (for Decryption)...",
                                       command=self._select_rsa_private_key_for_decryption_action,
                                       style="Secondary.TButton")
        key_select_button.pack(side=tk.LEFT, padx=(0, 10));
        self.create_tooltip_for_widget(key_select_button,
                                       "Select your RSA private key matching the submission's Key Hint.")
        self.rsa_private_key_display_label = ttk.Label(decrypt_frame, text="No decryption key selected", width=40,
                                                       style="PrivateKeyDisplay.TLabel", relief="sunken")
        self.rsa_private_key_display_label.pack(side=tk.LEFT, padx=0, fill=tk.X, expand=True)
        self.decrypt_button = ttk.Button(decrypt_frame, text="Decrypt Selected Local Submission",
                                         command=self._decrypt_selected_local_submission_threaded_action,
                                         state=tk.DISABLED, style="TButton")
        self.decrypt_button.pack(side=tk.LEFT, padx=(10, 0));
        self.create_tooltip_for_widget(self.decrypt_button, "Decrypt the selected local submission package.")

    def create_rsa_keys_tab_content(self):  # (Remains largely the same as previous GUI version)
        # ... (UI for generating RSA encryption key pairs: num_keys, prefix, password, generate button, output display) ...
        # This tab's functionality is independent of the server communication method.
        frame = ttk.LabelFrame(self.rsa_keys_tab, text="Generate My RSA Encryption Key Pairs", padding=15,
                               style="TLabelframe")
        frame.pack(padx=5, pady=10, fill=tk.X, expand=False)
        ttk.Label(frame, text="Number of New Key Pairs:").grid(row=0, column=0, padx=5, pady=10, sticky=tk.W)
        self.num_rsa_keys_var = tk.StringVar(value="1")
        num_keys_entry = ttk.Entry(frame, textvariable=self.num_rsa_keys_var, width=7)
        num_keys_entry.grid(row=0, column=1, padx=5, pady=10, sticky=tk.W);
        self.create_tooltip_for_widget(num_keys_entry, "Number of new RSA key pairs to generate.")
        ttk.Label(frame, text="Key Filename Prefix:").grid(row=1, column=0, padx=5, pady=10, sticky=tk.W)
        self.rsa_key_prefix_var = tk.StringVar(value="journalist_enc_key")
        key_prefix_entry = ttk.Entry(frame, textvariable=self.rsa_key_prefix_var, width=30)
        key_prefix_entry.grid(row=1, column=1, padx=5, pady=10, sticky=tk.W);
        self.create_tooltip_for_widget(key_prefix_entry, "Prefix for generated key filenames.")
        self.rsa_password_protect_var = tk.BooleanVar(value=True)
        password_check = ttk.Checkbutton(frame, text="Password-protect new private keys",
                                         variable=self.rsa_password_protect_var, style="TCheckbutton")
        password_check.grid(row=2, column=0, columnspan=2, pady=10, sticky=tk.W);
        self.create_tooltip_for_widget(password_check,
                                       "Prompt for a password to encrypt the generated private RSA keys.")
        generate_button = ttk.Button(frame, text="Generate Encryption Key Pairs",
                                     command=self._generate_rsa_encryption_keys_threaded_action, style="TButton")
        generate_button.grid(row=3, column=0, columnspan=2, pady=(15, 5));
        self.create_tooltip_for_widget(generate_button, "Generate RSA key pairs for submission content encryption.")
        info_frame = ttk.Frame(self.rsa_keys_tab, padding=(5, 0), style="TFrame")
        info_frame.pack(fill=tk.X, pady=(10, 10))
        abs_private_keys_dir = Path(current_script_dir,
                                    self.default_rsa_private_keys_dir_var.get() or DEFAULT_RSA_PRIVATE_KEYS_DIR).resolve()
        abs_public_keys_dir = Path(current_script_dir, DEFAULT_RSA_PUBLIC_KEYS_FOR_SERVER_DIR).resolve()
        ttk.Label(info_frame, text=f"Private RSA keys saved to: '{abs_private_keys_dir}'", style="TLabel").pack(
            anchor='w', padx=5)
        ttk.Label(info_frame, text=f"Public RSA keys (for server admin) saved to: '{abs_public_keys_dir}'",
                  style="TLabel").pack(anchor='w', padx=5)
        ttk.Label(info_frame, text="Provide generated public key files to your server administrator.",
                  style="TLabel").pack(anchor='w', padx=5, pady=(5, 0))
        pubkey_display_frame = ttk.LabelFrame(self.rsa_keys_tab, text="Content of Last Generated Public Keys",
                                              padding=10, style="TLabelframe")
        pubkey_display_frame.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        self.generated_rsa_pubkeys_text_area = scrolledtext.ScrolledText(pubkey_display_frame, height=7,
                                                                         state=tk.DISABLED, wrap=tk.WORD,
                                                                         **self.log_text_area_config)
        self.generated_rsa_pubkeys_text_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # --- Action Methods (Callbacks for UI elements) ---
    def _select_directory_action(self, tk_string_var: tk.StringVar, title: str):
        # Generic directory selector
        initial_dir = Path(tk_string_var.get() or Path.cwd()).resolve()
        dirpath = filedialog.askdirectory(parent=self.root, title=title, initialdir=str(initial_dir))
        if dirpath:
            tk_string_var.set(dirpath)
            self.log_message(f"Directory for '{title}' set to: {dirpath}", "INFO")
            Path(dirpath).mkdir(parents=True, exist_ok=True)

    def _refresh_local_submissions_list_action(self):  # Scans local import directory
        self.log_message("Refreshing local submissions list...", "INFO")
        import_dir_str = self.local_encrypted_submissions_import_dir.get()
        if not import_dir_str:
            messagebox.showerror("Configuration Error",
                                 "Local Encrypted Submissions Import Directory is not set in Settings.",
                                 parent=self.root)
            return

        import_dir = Path(import_dir_str)
        if not import_dir.is_dir():
            messagebox.showerror("Directory Error",
                                 f"Local import directory not found or is not a directory:\n{import_dir}",
                                 parent=self.root)
            return

        # Clear existing local items (or merge logic could be more complex)
        # For now, simple clear and reload of local items.
        # We might want to preserve server-fetched items if we implement merging.
        for i in self.submissions_tree.get_children(): self.submissions_tree.delete(i)

        found_local_submissions = 0
        for item in import_dir.iterdir():
            if item.is_dir():  # Each submission is expected to be a directory
                submission_id = item.name
                key_hint = "N/A"
                timestamp_str = "N/A (Local)"  # Timestamp from server metadata is preferred

                # Try to read hint file from local submission package
                hint_file_path = item / LOCAL_RSA_PUBLIC_KEY_HINT_NAME
                if hint_file_path.is_file():
                    try:
                        hint_content = hint_file_path.read_text(encoding='utf-8').strip()
                        if hint_content: key_hint = hint_content
                    except Exception as e_read_hint:
                        self.log_message(f"Error reading local hint file '{hint_file_path}': {e_read_hint}", "WARNING")

                # Check for essential files to consider it a valid package
                if not (item / LOCAL_ENCRYPTED_FILE_NAME).is_file() or \
                        not (item / LOCAL_ENCRYPTED_AES_KEY_NAME).is_file():
                    self.log_message(f"Skipping local directory '{submission_id}': missing essential encrypted files.",
                                     "WARNING")
                    continue

                self.submissions_tree.insert("", tk.END,
                                             values=(submission_id, "Local Package", timestamp_str, key_hint),
                                             tags=('local',))
                found_local_submissions += 1

        if found_local_submissions > 0:
            self.log_message(f"Found {found_local_submissions} local submission packages in '{import_dir}'.", "INFO")
        else:
            self.log_message(
                f"No valid local submission packages found in '{import_dir}'. Ensure each submission is in its own subdirectory containing the encrypted files.",
                "INFO")

    def _fetch_server_metadata_threaded_action(self):  # Fetches metadata from Journalist Interface
        # Disable button
        for child_f in self.submissions_tab.winfo_children():
            if isinstance(child_f, ttk.Frame):  # top_controls_frame
                for btn in child_f.winfo_children():
                    if isinstance(btn, ttk.Button) and "Fetch New Submission Info" in btn.cget("text"):
                        btn.config(state=tk.DISABLED);
                        break
                break
        threading.Thread(target=self._fetch_server_metadata_worker, daemon=True).start()

    def _fetch_server_metadata_worker(self):
        self.log_message("Fetching submission metadata from Journalist Interface server...", "INFO")
        url = self.journalist_interface_url.get()
        api_key = self.journalist_api_key.get()

        if not url or not api_key:
            self.log_message("Journalist Interface URL or API Key not set in Settings.", "ERROR")
            self.root.after(0, lambda: messagebox.showerror("Config Error",
                                                            "Journalist Interface URL and API Key must be set.",
                                                            parent=self.root))
            self._reenable_fetch_button_safely();
            return

        session = self._get_requests_session_with_tor_proxy()
        if not session:
            self._reenable_fetch_button_safely();
            return  # Error already logged by helper

        metadata_endpoint = url.rstrip('/') + "/submissions"  # Assuming this is the endpoint
        headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}

        server_submissions_metadata = []
        try:
            response = session.get(metadata_endpoint, headers=headers, timeout=45)  # Increased timeout for Tor
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            data = response.json()

            if data and "submissions" in data and isinstance(data["submissions"], list):
                server_submissions_metadata = data["submissions"]
                self.log_message(
                    f"Successfully fetched metadata for {len(server_submissions_metadata)} submissions from server.",
                    "INFO")
            else:
                self.log_message("No 'submissions' list in server response or format is unexpected.", "WARNING")
                if data: self.log_message(f"Server raw response sample: {str(data)[:200]}", "DEBUG")

        except requests.exceptions.HTTPError as http_e:
            err_msg = f"HTTP error fetching metadata: {http_e.response.status_code} for {metadata_endpoint}."
            try:
                server_err = http_e.response.json().get("error", "No details."); err_msg += f" Server: {server_err}"
            except:
                err_msg += f" Server raw response: {http_e.response.text[:100]}"
            self.log_message(err_msg, "ERROR")
            self.root.after(0, lambda em=err_msg: messagebox.showerror("Server Error", em, parent=self.root))
        except requests.exceptions.RequestException as req_e:  # Covers DNS, Connection, Timeout etc.
            self.log_message(f"Network error fetching metadata from {metadata_endpoint}: {req_e}", "ERROR")
            self.root.after(0, lambda er=req_e: messagebox.showerror("Network Error", f"Could not fetch metadata: {er}",
                                                                     parent=self.root))
        except json.JSONDecodeError:
            self.log_message("Invalid JSON response from server when fetching metadata.", "ERROR")
            self.root.after(0, lambda: messagebox.showerror("Server Error", "Invalid JSON response from server.",
                                                            parent=self.root))
        except Exception as ex:  # Catch-all
            self.log_message(f"Unexpected error fetching metadata: {ex}", "ERROR");
            self.log_message(traceback.format_exc(), "ERROR_TRACE")
            self.root.after(0, lambda e=ex: messagebox.showerror("Error", f"Unexpected error: {e}", parent=self.root))
        finally:
            if session: session.close()
            self._reenable_fetch_button_safely()

        # Update Treeview with fetched server metadata (and merge/compare with local)
        if server_submissions_metadata:
            self.root.after(0, lambda: self._update_submissions_tree_with_server_data(server_submissions_metadata))

    def _reenable_fetch_button_safely(self):
        def reenable():
            for child_f in self.submissions_tab.winfo_children():
                if isinstance(child_f, ttk.Frame):
                    for btn in child_f.winfo_children():
                        if isinstance(btn, ttk.Button) and "Fetch New Submission Info" in btn.cget("text"):
                            btn.config(state=tk.NORMAL);
                            return

        self.root.after(0, reenable)

    def _update_submissions_tree_with_server_data(self, server_metadata_list):
        # This function needs to intelligently merge server data with existing local data in the tree.
        # For simplicity now, it will clear and repopulate, prioritizing server info if IDs match.
        # A more advanced version would update existing rows or highlight differences.

        # Get current local items from tree to compare
        local_items_in_tree = {}
        for item_id_internal in self.submissions_tree.get_children():
            values = self.submissions_tree.item(item_id_internal)['values']
            if values and values[1] == "Local Package":  # Identify local items
                local_items_in_tree[values[0]] = {"status": values[1], "timestamp_utc": values[2],
                                                  "key_hint": values[3]}

        self.submissions_tree.delete(*self.submissions_tree.get_children())  # Clear tree

        processed_ids = set()
        for server_item in server_metadata_list:
            sub_id = server_item.get("id")
            status = "Server Only"
            if sub_id in local_items_in_tree:
                status = "Local & Server"  # Or "Synced", "Local Available"
                # Could compare timestamps or other metadata here if needed
            self.submissions_tree.insert("", tk.END, values=(
                sub_id, status, server_item.get("timestamp_utc", "N/A"), server_item.get("rsa_key_hint", "N/A")
            ), tags=('server',))
            processed_ids.add(sub_id)

        # Add back any local items that were not in the server list (e.g., older, already exported & deleted from server view)
        for sub_id, local_data in local_items_in_tree.items():
            if sub_id not in processed_ids:
                self.submissions_tree.insert("", tk.END, values=(
                    sub_id, local_data["status"], local_data["timestamp_utc"], local_data["key_hint"]
                ), tags=('local',))
        self.log_message("Submissions tree updated with server metadata.", "INFO")

    def _on_local_submission_select_action(self, event=None):  # Renamed, logic adapted
        selected_items = self.submissions_tree.selection()
        if not selected_items:
            self.selected_local_submission_id.set("");
            self.decrypt_button.config(state=tk.DISABLED);
            return

        item_values = self.submissions_tree.item(selected_items[0])['values']
        if item_values and len(item_values) >= 1:
            submission_id_val = str(item_values[0])
            status_val = str(item_values[1])

            # Only enable decryption for items that are "Local Package" or "Local & Server"
            if "Local" in status_val:
                self.selected_local_submission_id.set(submission_id_val)
                self.log_message(f"Local submission package selected: '{submission_id_val}'", "INFO")
                if self.rsa_private_key_for_decryption_path.get():
                    self.decrypt_button.config(state=tk.NORMAL)
                else:
                    self.decrypt_button.config(state=tk.DISABLED)
                    self.log_message("RSA decryption key not yet selected.", "INFO")
            else:  # "Server Only" or other status
                self.selected_local_submission_id.set("")  # Clear selection if not local
                self.decrypt_button.config(state=tk.DISABLED)
                self.log_message(
                    f"Submission '{submission_id_val}' selected (Status: {status_val}). Not a local package available for decryption.",
                    "INFO")
        else:
            self.selected_local_submission_id.set("");
            self.decrypt_button.config(state=tk.DISABLED)

    def _select_rsa_private_key_for_decryption_action(self):  # (Same as previous GUI version)
        initial_dir = Path(self.default_rsa_private_keys_dir_var.get() or Path.cwd()).resolve()
        filepath = filedialog.askopenfilename(parent=self.root, initialdir=str(initial_dir),
                                              title="Select RSA Private Key (for Submission Content Decryption)",
                                              filetypes=(("PEM files", "*.pem"), ("All Private Keys", "*"),
                                                         ("All files", "*.*")))
        if filepath:
            self.rsa_private_key_for_decryption_path.set(filepath)
            self.rsa_private_key_display_label.config(text=Path(filepath).name)
            self.log_message(f"RSA private key for content decryption selected: {Path(filepath).name}", "INFO")
            if self.selected_local_submission_id.get(): self.decrypt_button.config(state=tk.NORMAL)

    def _decrypt_selected_local_submission_threaded_action(self):  # Adapted for local workflow
        if not self.selected_local_submission_id.get():
            messagebox.showwarning("No Local Submission", "Select a 'Local Package' submission to decrypt.",
                                   parent=self.root);
            return
        if not self.rsa_private_key_for_decryption_path.get():
            messagebox.showwarning("No Decryption Key", "Select your RSA private key for content decryption.",
                                   parent=self.root);
            return

        self.decrypt_button.config(state=tk.DISABLED)
        submission_id_to_decrypt = self.selected_local_submission_id.get()
        rsa_priv_key_path = self.rsa_private_key_for_decryption_path.get()

        try:
            with open(rsa_priv_key_path, 'r') as f:
                rsa_pem_content = f.read()
        except Exception as e:
            self.log_message(f"Error reading RSA private key '{rsa_priv_key_path}': {e}", "ERROR")
            messagebox.showerror("Key Error", f"Could not read RSA private key: {e}", parent=self.root)
            self._reenable_decrypt_button_safely();
            return

        rsa_key_pass = simpledialog.askstring("RSA Key Password",
                                              f"Enter password for RSA key:\n'{Path(rsa_priv_key_path).name}'\n(Leave blank if none):",
                                              parent=self.root, show='*')
        if rsa_key_pass is None:
            self.log_message("Decryption cancelled at RSA key password prompt.", "INFO")
            self._reenable_decrypt_button_safely();
            return

        actual_rsa_key_pass = rsa_key_pass if rsa_key_pass else None

        # Local import directory
        local_import_dir = Path(self.local_encrypted_submissions_import_dir.get())
        submission_package_path = local_import_dir / submission_id_to_decrypt

        if not submission_package_path.is_dir():
            self.log_message(f"Local submission package directory not found: {submission_package_path}", "ERROR")
            messagebox.showerror("File Error", f"Local submission package not found at:\n{submission_package_path}",
                                 parent=self.root)
            self._reenable_decrypt_button_safely();
            return

        threading.Thread(target=self._decrypt_local_submission_worker,
                         args=(submission_package_path, rsa_pem_content, actual_rsa_key_pass),
                         daemon=True).start()

    def _reenable_decrypt_button_safely(self):
        # Only re-enable if a local submission and a key are still selected
        def reenable():
            if self.selected_local_submission_id.get() and self.rsa_private_key_for_decryption_path.get():
                self.decrypt_button.config(state=tk.NORMAL)
            else:
                self.decrypt_button.config(state=tk.DISABLED)

        self.root.after(0, reenable)

    def _decrypt_local_submission_worker(self, submission_pkg_path: Path, rsa_pem: str, rsa_pass: str | None):
        self.log_message(f"Worker: Decrypting local submission package at '{submission_pkg_path}'.", "INFO")
        try:
            # Load encrypted components from the local submission package directory
            def load_local_component(filename: str) -> bytes | None:
                file_p = submission_pkg_path / filename
                if not file_p.is_file():
                    self.log_message(f"Component '{filename}' not found in '{submission_pkg_path}'.", "ERROR");
                    return None
                try:
                    return file_p.read_bytes()
                except IOError as e:
                    self.log_message(f"IOError reading '{file_p}': {e}", "ERROR"); return None

            enc_aes_key = load_local_component(LOCAL_ENCRYPTED_AES_KEY_NAME)
            enc_orig_fname = load_local_component(LOCAL_ENCRYPTED_ORIGINAL_FILENAME_NAME)
            enc_file_data = load_local_component(LOCAL_ENCRYPTED_FILE_NAME)

            if not all([enc_aes_key, enc_orig_fname, enc_file_data]):
                self.root.after(0, lambda: messagebox.showerror("Decryption Error",
                                                                "One or more encrypted component files are missing from the local submission package.",
                                                                parent=self.root))
                return

            # Decryption logic (same as before, using crypto_utils)
            dec_aes_key = crypto_utils.decrypt_rsa(enc_aes_key, rsa_pem, rsa_pass)
            if not dec_aes_key:
                self.log_message("Failed to decrypt AES key.", "ERROR")
                self.root.after(0, lambda: messagebox.showerror("Decryption Error",
                                                                "AES Key decryption failed. Check RSA key password or key.",
                                                                parent=self.root))
                return

            dec_orig_fname_bytes = crypto_utils.decrypt_aes_gcm(enc_orig_fname, dec_aes_key)
            orig_fname_str = f"{submission_pkg_path.name}_decrypted.dat"
            if dec_orig_fname_bytes:
                try:
                    orig_fname_str = dec_orig_fname_bytes.decode('utf-8', errors='replace')
                except:
                    self.log_message("Error decoding original filename.", "WARNING")
            else:
                self.log_message("Failed to decrypt original filename.", "WARNING")

            dec_file_data = crypto_utils.decrypt_aes_gcm(enc_file_data, dec_aes_key)
            if not dec_file_data:
                self.log_message("Failed to decrypt file data.", "ERROR")
                self.root.after(0, lambda: messagebox.showerror("Decryption Error", "File data decryption failed.",
                                                                parent=self.root))
                return
            self.log_message(f"Submission '{submission_pkg_path.name}' decrypted successfully.", "SUCCESS")

            # Ask user where to save (in main thread)
            def ask_save_main():
                save_dir = Path(
                    self.local_decrypted_submissions_output_dir.get() or DEFAULT_LOCAL_DECRYPTED_SUBMISSIONS_OUTPUT_DIR).resolve()
                save_dir.mkdir(parents=True, exist_ok=True)
                safe_fname = "".join(c for c in orig_fname_str if
                                     c.isalnum() or c in ['.', '_', '-']).strip() or f"{submission_pkg_path.name}.dat"
                path_to_save = filedialog.asksaveasfilename(parent=self.root, initialdir=str(save_dir),
                                                            initialfile=safe_fname, title="Save Decrypted File")
                if path_to_save:
                    try:
                        Path(path_to_save).write_bytes(dec_file_data)
                        self.log_message(f"File saved: {path_to_save}", "SUCCESS")
                        messagebox.showinfo("Success", f"Saved to:\n{path_to_save}", parent=self.root)
                    except IOError as e:
                        self.log_message(f"IOError save: {e}", "ERROR"); messagebox.showerror("Save Error",
                                                                                              f"Could not save: {e}",
                                                                                              parent=self.root)
                else:
                    self.log_message("Save cancelled.")

            self.root.after(0, ask_save_main)

        except Exception as e:
            self.log_message(f"Unexpected error in decryption worker: {e}", "ERROR");
            self.log_message(traceback.format_exc(), "ERROR_TRACE")
            self.root.after(0,
                            lambda err=e: messagebox.showerror("Error", f"Unexpected error: {err}", parent=self.root))
        finally:
            self.root.after(0, self._reenable_decrypt_button_safely)

    def _generate_rsa_encryption_keys_threaded_action(self):  # (Same as previous GUI version)
        # ... (Logic for getting num_keys, prefix, password from UI) ...
        try:
            num_keys = int(self.num_rsa_keys_var.get()); prefix = self.rsa_key_prefix_var.get().strip()
        except:
            messagebox.showerror("Input Error", "Invalid number of keys or prefix.", parent=self.root); return
        if num_keys <= 0 or not prefix: messagebox.showerror("Input Error",
                                                             "Number of keys must be >0 and prefix non-empty.",
                                                             parent=self.root); return
        password = None
        if self.rsa_password_protect_var.get():
            password = simpledialog.askstring("Set RSA Key Password", "Enter password for new private RSA keys:",
                                              parent=self.root, show='*')
            if password is None: self.log_message("Key generation cancelled."); return
            if not password:
                if not messagebox.askyesno("Confirm No Password", "Generate keys WITHOUT password?", parent=self.root,
                                           icon='warning'):
                    self.log_message("Key generation aborted.");
                    return
                password = None
        # Disable button
        for child_lf in self.rsa_keys_tab.winfo_children():
            if isinstance(child_lf, ttk.LabelFrame):
                for btn_widget in child_lf.winfo_children():
                    if isinstance(btn_widget, ttk.Button) and "Generate Encryption Key Pairs" in btn_widget.cget(
                            "text"):
                        btn_widget.config(state=tk.DISABLED);
                        break;
                        break
        threading.Thread(target=self._generate_rsa_encryption_keys_worker, args=(num_keys, prefix, password),
                         daemon=True).start()

    def _generate_rsa_encryption_keys_worker(self, num_keys, key_prefix, password):  # (Same as previous GUI version)
        # ... (Calls rsa_encryption_key_gen_module.generate_rsa_key_pair, updates GUI text area) ...
        self.log_message(f"Worker: Generating {num_keys} RSA encryption key(s) with prefix '{key_prefix}'...", "INFO")
        priv_dir = Path(self.default_rsa_private_keys_dir_var.get() or Path(current_script_dir,
                                                                            DEFAULT_RSA_PRIVATE_KEYS_DIR)).resolve()
        pub_dir_for_admin = Path(current_script_dir, DEFAULT_RSA_PUBLIC_KEYS_FOR_SERVER_DIR).resolve()
        priv_dir.mkdir(parents=True, exist_ok=True);
        pub_dir_for_admin.mkdir(parents=True, exist_ok=True)

        # Temporarily override module-level constants if your generate_rsa_keys.py uses them directly
        # This is not ideal; the function should accept output directories as parameters.
        # Assuming rsa_encryption_key_gen_module.generate_rsa_key_pair can take output dirs or uses these constants.
        # For this example, let's assume it uses the constants if not passed as args.
        # If generate_rsa_key_pair is updated to take dirs, pass priv_dir and pub_dir_for_admin.

        # For this example, I'll assume the generate_rsa_key_pair function in rsa_encryption_key_gen_module
        # has been updated to accept output directories. If not, the module's constants would need to be
        # temporarily patched here, which is more complex and error-prone.

        all_pub_keys_text = ""
        success_count = 0
        for i in range(1, num_keys + 1):
            try:
                # Assuming generate_rsa_key_pair is updated to take output dirs:
                # pub_path, _ = rsa_encryption_key_gen_module.generate_rsa_key_pair(
                #     key_id_prefix=key_prefix, key_index=i, password=password,
                #     private_key_dir=priv_dir, public_key_dir=pub_dir_for_admin)

                # If generate_rsa_key_pair still uses its internal constants, you'd need to patch them before calling
                # and restore them after. For simplicity, I'm omitting that patching here.
                # This call will use the constants defined within rsa_encryption_key_gen_module
                # if they are not passed as arguments and the function is not modified.
                # To make this work correctly with the GUI's configured directories,
                # rsa_encryption_key_gen_module.generate_rsa_key_pair *must* accept output directories.
                # I'll proceed as if it does for this GUI logic.

                # Corrected approach: The generate_rsa_keys.py provided earlier *does* use its own constants.
                # So, we need to ensure those constants point to the GUI-configured/default dirs for this call.
                # This is a workaround. Ideally, the utility function is more flexible.

                # Store original module paths
                original_priv_dir_module = rsa_encryption_key_gen_module.PRIVATE_RSA_KEYS_OUTPUT_DIR
                original_pub_dir_module = rsa_encryption_key_gen_module.PUBLIC_RSA_KEYS_FOR_SERVER_OUTPUT_DIR

                # Temporarily set module paths to what GUI wants
                rsa_encryption_key_gen_module.PRIVATE_RSA_KEYS_OUTPUT_DIR = priv_dir
                rsa_encryption_key_gen_module.PUBLIC_RSA_KEYS_FOR_SERVER_OUTPUT_DIR = pub_dir_for_admin

                pub_path, _ = rsa_encryption_key_gen_module.generate_rsa_key_pair(key_prefix, i, password)

                # Restore original module paths
                rsa_encryption_key_gen_module.PRIVATE_RSA_KEYS_OUTPUT_DIR = original_priv_dir_module
                rsa_encryption_key_gen_module.PUBLIC_RSA_KEYS_FOR_SERVER_OUTPUT_DIR = original_pub_dir_module

                if pub_path:
                    with open(pub_path, 'r') as f: pub_key_content = f.read()
                    all_pub_keys_text += f"--- Public Key for {Path(pub_path).name} ---\n{pub_key_content}\n\n"
                    success_count += 1
            except Exception as e:
                self.log_message(f"Error generating key pair {i}: {e}", "ERROR"); break

        def update_ui():
            for child_lf in self.rsa_keys_tab.winfo_children():
                if isinstance(child_lf, ttk.LabelFrame):
                    for btn_widget in child_lf.winfo_children():
                        if isinstance(btn_widget, ttk.Button) and "Generate Encryption Key Pairs" in btn_widget.cget(
                                "text"):
                            btn_widget.config(state=tk.NORMAL);
                            break;
                            break
            if success_count > 0:
                self.generated_rsa_pubkeys_text_area.config(state=tk.NORMAL)
                self.generated_rsa_pubkeys_text_area.delete('1.0', tk.END)
                self.generated_rsa_pubkeys_text_area.insert(tk.END, all_pub_keys_text)
                self.generated_rsa_pubkeys_text_area.config(state=tk.DISABLED)
                msg = f"{success_count} RSA key pair(s) generated.\nPrivate keys in: '{priv_dir}'\nPublic keys for admin in: '{pub_dir_for_admin}'"
                self.log_message(msg.replace('\n', ' - '), "SUCCESS")
                messagebox.showinfo("RSA Keys Generated", msg, parent=self.root)

        self.root.after(0, update_ui)


# --- Main Execution ---
if __name__ == '__main__':
    for p_str in [DEFAULT_LOCAL_ENCRYPTED_SUBMISSIONS_IMPORT_DIR, DEFAULT_LOCAL_DECRYPTED_SUBMISSIONS_OUTPUT_DIR,
                  DEFAULT_RSA_PRIVATE_KEYS_DIR, DEFAULT_RSA_PUBLIC_KEYS_FOR_SERVER_DIR]:
        Path(current_script_dir, p_str).mkdir(parents=True, exist_ok=True)
    root = tk.Tk()
    app = JournalistApp(root)
    # ... (Icon loading logic - same as previous GUI version) ...
    icon_found = False;
    icon_png = 'autumn_leaf.png';
    icon_ico = 'autumn_leaf.ico'
    for icon_p_str in [str(Path(current_script_dir, icon_png)), str(Path(current_script_dir, icon_ico))]:
        icon_p = Path(icon_p_str)
        if icon_p.exists():
            try:
                if icon_p.suffix == '.png':
                    root.iconphoto(False, tk.PhotoImage(file=str(icon_p))); icon_found = True; break
                elif icon_p.suffix == '.ico' and os.name == 'nt':
                    root.iconbitmap(default=str(icon_p)); icon_found = True; break
            except Exception as e:
                app.log_message(f"Error loading icon {icon_p}: {e}", "WARNING")
    if not icon_found: app.log_message("Custom icon not found/loaded.", "WARNING")
    root.mainloop()