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
import traceback

# Adjust path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from utils import generate_rsa_keys as rsa_gen_module
from journalist_tool import crypto_utils
import requests

CONFIG_FILE = os.path.join(current_dir, "gui_config.json")
DEFAULT_PRIVATE_KEYS_DIR = rsa_gen_module.PRIVATE_KEYS_OUTPUT_DIR
DEFAULT_PUBLIC_KEYS_FOR_SERVER_DIR = rsa_gen_module.PUBLIC_KEYS_FOR_SERVER_OUTPUT_DIR
DEFAULT_DOWNLOAD_DIR = os.path.join(current_dir, "decrypted_submissions")

os.makedirs(DEFAULT_PRIVATE_KEYS_DIR, exist_ok=True)
os.makedirs(DEFAULT_PUBLIC_KEYS_FOR_SERVER_DIR, exist_ok=True)
os.makedirs(DEFAULT_DOWNLOAD_DIR, exist_ok=True)


class ToolTip:
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
        label_font = ("Segoe UI", 8, "normal")
        try:
            if hasattr(self.widget, 'winfo_toplevel') and hasattr(self.widget.winfo_toplevel(), 'default_font_tooltip'):
                label_font = self.widget.winfo_toplevel().default_font_tooltip
        except:
            pass
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                         background="#FFFFE0", relief=tk.SOLID, borderwidth=1,
                         font=label_font)
        label.pack(ipadx=2, ipady=1)

    def hidetip(self):
        if self.tipwindow:
            self.tipwindow.destroy()
        self.tipwindow = None


class JournalistApp:
    def __init__(self, root_window):
        self.root = root_window
        self.root.title("WhistleDrop Journalist Tool")
        self.root.geometry("950x750")

        # --- AUTUMN THEME COLORS ---
        self.bg_color = '#FAF8F1'
        self.frame_bg_color = '#F3EADA'
        self.accent_color_primary = '#E87A00'
        self.accent_hover_primary = '#D36F00'
        self.accent_color_secondary = '#8C5A32'
        self.accent_hover_secondary = '#754C24'
        self.text_color = '#5D4037'
        self.header_text_color = self.accent_color_secondary
        self.border_color = '#D1C0A8'
        self.entry_bg_color = '#FFFDF9'
        self.button_text_color_on_orange = '#FFFFFF'
        self.button_text_color_on_brown = '#FAF8F1'
        # --- END AUTUMN THEME COLORS ---

        self.root.configure(bg=self.bg_color)

        self.style = ttk.Style()
        try:
            self.style.theme_use('clam')
        except tk.TclError:
            # log_message is not available yet, so print or pass
            print("WARNING: Clam theme not available, using default.")

        self.default_font = ("Segoe UI", 10)
        self.bold_font = ("Segoe UI", 10, "bold")
        self.log_font = ("Consolas", 9)
        self.root.option_add("*Font", self.default_font)
        self.root.default_font_tooltip = ("Segoe UI", 8, "normal")

        # --- TTK Style Configuration ---
        self.style.configure(".", font=self.default_font, background=self.bg_color, foreground=self.text_color)
        self.style.configure("TFrame", background=self.frame_bg_color)
        self.style.configure("TLabel", background=self.frame_bg_color, foreground=self.text_color, padding=3)
        self.style.configure("TLabelframe", background=self.frame_bg_color, bordercolor=self.border_color,
                             font=self.bold_font, relief="groove", borderwidth=1)
        self.style.configure("TLabelframe.Label", background=self.frame_bg_color, foreground=self.header_text_color,
                             font=self.bold_font, padding=(0, 0, 0, 5))
        self.style.configure("TButton", font=self.default_font, padding=(12, 6),
                             background=self.accent_color_primary, foreground=self.button_text_color_on_orange,
                             relief="raised", borderwidth=1, bordercolor=self.accent_color_primary)
        self.style.map("TButton",
                       background=[('active', self.accent_hover_primary), ('pressed', self.accent_hover_primary)],
                       bordercolor=[('active', self.accent_hover_primary)],
                       relief=[('pressed', 'sunken'), ('!pressed', 'raised')])
        self.style.configure("Secondary.TButton", font=self.default_font, padding=(10, 5),
                             background=self.accent_color_secondary, foreground=self.button_text_color_on_brown,
                             relief="raised", borderwidth=1, bordercolor=self.accent_color_secondary)
        self.style.map("Secondary.TButton",
                       background=[('active', self.accent_hover_secondary), ('pressed', self.accent_hover_secondary)],
                       bordercolor=[('active', self.accent_hover_secondary)],
                       relief=[('pressed', 'sunken')])
        self.style.configure("TEntry", font=self.default_font, padding=6,
                             fieldbackground=self.entry_bg_color, foreground=self.text_color,
                             borderwidth=1, relief="solid", bordercolor=self.border_color)
        self.style.map("TEntry",
                       bordercolor=[('focus', self.accent_color_primary)],
                       selectbackground=[('focus', self.accent_color_primary)],
                       selectforeground=[('focus', self.button_text_color_on_orange)])
        self.style.configure("TNotebook", background=self.bg_color, borderwidth=0, tabmargins=[2, 5, 2, 0])
        self.style.configure("TNotebook.Tab", font=self.default_font, padding=(15, 7),
                             background=self.frame_bg_color, foreground=self.text_color, borderwidth=1)
        self.style.map("TNotebook.Tab",
                       background=[("selected", self.bg_color)],
                       foreground=[("selected", self.accent_color_primary)],
                       bordercolor=[("selected", self.accent_color_primary), ("!selected", self.border_color)],
                       lightcolor=[("selected", self.bg_color)],
                       font=[("selected", self.bold_font)])
        self.style.configure("Treeview", font=self.default_font, rowheight=28,
                             fieldbackground=self.entry_bg_color, foreground=self.text_color,
                             borderwidth=1, relief="solid", bordercolor=self.border_color)
        self.style.configure("Treeview.Heading", font=self.bold_font, background=self.frame_bg_color,
                             foreground=self.header_text_color, padding=7, relief="raised", borderwidth=1)
        self.style.map("Treeview.Heading",
                       background=[('active', self.accent_color_secondary)],
                       foreground=[('active', self.button_text_color_on_brown)])
        self.style.configure("PrivateKeyDisplay.TLabel",
                             background=self.entry_bg_color, foreground=self.text_color,
                             borderwidth=1, relief="sunken", padding=(6, 5),
                             font=self.default_font, anchor="w")
        self.style.configure("TCheckbutton", background=self.frame_bg_color, foreground=self.text_color,
                             indicatorrelief="flat", indicatormargin=5)  # Basic checkbutton style
        self.style.map("TCheckbutton",
                       indicatorbackground=[('selected', self.accent_color_primary),
                                            ('!selected', self.entry_bg_color)],
                       indicatorforeground=[('selected', self.button_text_color_on_orange)])

        self.log_text_area_config = {
            "font": self.log_font,
            "bg": self.entry_bg_color,  # Background of the text area
            "fg": self.text_color,  # Text color
            "relief": "solid",  # Style of the border (e.g., solid, sunken, raised)
            "borderwidth": 1,  # Width of the border in pixels (must be an integer)
            # "bd": self.border_color, # REMOVE THIS LINE or set bd=1

            "highlightthickness": 1,  # Width of the focus highlight ring
            "highlightbackground": self.border_color,  # Color of the border/highlight when NOT focused
            "highlightcolor": self.accent_color_primary,  # Color of the border/highlight when FOCUSED

            "insertbackground": self.text_color,  # Color of the text cursor
            "selectbackground": self.accent_color_secondary,  # Background of selected text
            "selectforeground": self.button_text_color_on_brown  # Foreground of selected text
        }
        # --- End TTK Style Configuration ---

        self.server_url = tk.StringVar(value="http://127.0.0.1:5000")
        self.api_key = tk.StringVar()
        self.private_key_path = tk.StringVar()
        self.selected_submission_id = tk.StringVar()

        # --- Log text area setup (needs to be before load_config if load_config logs) ---
        # Moved log_text_frame and log_text creation here so log_message is available for load_config
        self.log_text_frame = ttk.LabelFrame(root_window, text="Application Log", padding=(10, 5), style="TLabelframe")
        # self.log_text_frame.pack(...) will be done after notebook

        self.log_text = scrolledtext.ScrolledText(
            self.log_text_frame, height=10, state=tk.DISABLED,
            wrap=tk.WORD, **self.log_text_area_config
        )
        # self.log_text.pack(...) will be done after notebook
        # --- End Log text area setup ---

        self.load_config()  # NOW self.log_message can be called by load_config

        self.notebook = ttk.Notebook(root_window, style="TNotebook")

        self.setup_tab = ttk.Frame(self.notebook, padding=(20, 15), style="TFrame")
        self.submissions_tab = ttk.Frame(self.notebook, padding=(20, 15), style="TFrame")
        self.keys_tab = ttk.Frame(self.notebook, padding=(20, 15), style="TFrame")

        self.notebook.add(self.setup_tab, text=' Server & Admin ')
        self.notebook.add(self.submissions_tab, text=' Submissions ')
        self.notebook.add(self.keys_tab, text=' My Key Pairs ')
        self.notebook.pack(expand=1, fill='both', padx=10, pady=(10, 5))

        self.create_setup_tab()
        self.create_submissions_tab()
        self.create_keys_tab()

        # Pack log area after notebook
        self.log_text_frame.pack(pady=(5, 10), padx=10, fill=tk.X)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        if not hasattr(self, 'initial_log_done'):  # Log only once
            self.log_message("GUI Initialized. Configure server and API key.")
            self.log_message(
                "REMINDER: For .onion addresses, set SOCKS proxy environment variables (HTTP_PROXY, HTTPS_PROXY).")
            self.initial_log_done = True

    # ***** ADD THESE METHODS BACK *****
    def log_message(self, message, level="INFO"):
        # Ensure log_text is created before this is called extensively
        if hasattr(self, 'log_text'):
            self.log_text.config(state=tk.NORMAL)
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            self.log_text.insert(tk.END, f"[{timestamp} {level}] {message}\n")
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
        else:  # Fallback if log_text not ready (e.g. very early error in __init__)
            print(f"LOG EARLY [{level}]: {message}")

    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config_data = json.load(f)
                    self.server_url.set(config_data.get("server_url", "http://127.0.0.1:5000"))
                    self.api_key.set(config_data.get("api_key", ""))
                self.log_message("Configuration loaded.", "INFO")
            else:
                self.log_message("Config file not found, using defaults.", "INFO")
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
        # Capture tooltip instance for lambda
        widget.bind("<Enter>", lambda event, t=tooltip: t.showtip())
        widget.bind("<Leave>", lambda event, t=tooltip: t.hidetip())

    # ***** END OF METHODS TO ADD BACK *****

    # --- create_setup_tab, create_submissions_tab, create_keys_tab ---
    # (Using the styled versions from the previous response)
    def create_setup_tab(self):  # Updated with Autumn Styles
        conn_frame = ttk.LabelFrame(self.setup_tab, text="WhistleDrop Server Connection", padding=15,
                                    style="TLabelframe")
        conn_frame.pack(padx=5, pady=10, fill=tk.X, expand=False)

        ttk.Label(conn_frame, text="Server URL:", style="TLabel").grid(row=0, column=0, padx=5, pady=10, sticky=tk.W)
        ttk.Entry(conn_frame, textvariable=self.server_url, width=55, style="TEntry").grid(row=0, column=1, padx=5,
                                                                                           pady=10, sticky=tk.EW)

        api_key_label_frame = ttk.Frame(conn_frame, style="TFrame")
        api_key_label_frame.grid(row=1, column=0, padx=5, pady=10, sticky=tk.W)
        api_key_label = ttk.Label(api_key_label_frame, text="API Key:", style="TLabel")
        api_key_label.pack(side=tk.LEFT, anchor='w')

        tooltip_text = ("The API key is a secret token configured on the WhistleDrop server...\n"
                        "Example: " + ''.join(
            secrets.choice(string.ascii_letters + string.digits) for i in range(20)) + "...")
        self.create_tooltip(api_key_label, tooltip_text)

        ttk.Entry(conn_frame, textvariable=self.api_key, width=55, show="*", style="TEntry").grid(row=1, column=1,
                                                                                                  padx=5, pady=10,
                                                                                                  sticky=tk.EW)

        save_button = ttk.Button(conn_frame, text="Save Connection Settings", command=self.save_config)
        save_button.grid(row=2, column=0, columnspan=2, pady=(15, 5))
        conn_frame.columnconfigure(1, weight=1)

        pubkey_upload_frame = ttk.LabelFrame(self.setup_tab, text="Upload Public Keys to Server", padding=15,
                                             style="TLabelframe")
        pubkey_upload_frame.pack(padx=5, pady=10, fill=tk.X, expand=False)
        info_label_pubkey = ttk.Label(pubkey_upload_frame, justify=tk.LEFT, style="TLabel",
                                      text=f"Select public key files (.pem or .pub) to upload.\nKeys are generated in 'My Key Pairs' tab and stored in:\n'{os.path.basename(DEFAULT_PUBLIC_KEYS_FOR_SERVER_DIR)}'")
        info_label_pubkey.pack(pady=(0, 10), fill=tk.X)
        ttk.Button(pubkey_upload_frame, text="Select & Upload Public Keys",
                   command=self.upload_public_keys_to_server_threaded).pack(pady=5)

    def create_submissions_tab(self):
        top_frame = ttk.Frame(self.submissions_tab, style="TFrame")
        top_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(top_frame, text="Refresh Submissions List", command=self.refresh_submissions_list_threaded,
                   style="Secondary.TButton").pack(side=tk.LEFT, padx=0)

        columns = ("submission_id", "key_hint")
        self.submissions_tree = ttk.Treeview(self.submissions_tab, columns=columns, show="headings", height=10,
                                             style="Treeview")
        self.submissions_tree.heading("submission_id", text="Submission ID")
        self.submissions_tree.heading("key_hint", text="Key Hint Used by Server")
        self.submissions_tree.column("submission_id", width=350, anchor="w", stretch=tk.YES)
        self.submissions_tree.column("key_hint", width=250, anchor="w", stretch=tk.YES)

        tree_scrollbar_y = ttk.Scrollbar(self.submissions_tab, orient="vertical", command=self.submissions_tree.yview)
        self.submissions_tree.configure(yscrollcommand=tree_scrollbar_y.set)
        tree_scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y, pady=(5, 0))
        self.submissions_tree.pack(padx=0, pady=5, fill=tk.BOTH, expand=True)

        self.submissions_tree.bind('<<TreeviewSelect>>', self.on_submission_select_treeview)

        decrypt_frame = ttk.Frame(self.submissions_tab, style="TFrame", padding=(0, 10))
        decrypt_frame.pack(fill=tk.X, pady=(10, 0))

        key_select_button = ttk.Button(decrypt_frame, text="Select Private Key...",
                                       command=self.select_private_key_file, style="Secondary.TButton")
        key_select_button.pack(side=tk.LEFT, padx=(0, 10))

        self.private_key_display_label = ttk.Label(decrypt_frame, text="No private key selected", width=40,
                                                   style="PrivateKeyDisplay.TLabel")
        self.private_key_display_label.pack(side=tk.LEFT, padx=0, fill=tk.X, expand=True)

        self.decrypt_button = ttk.Button(decrypt_frame, text="Decrypt Submission",
                                         command=self.decrypt_selected_submission_threaded, state=tk.DISABLED)
        self.decrypt_button.pack(side=tk.LEFT, padx=(10, 0))

    def create_keys_tab(self):
        frame = ttk.LabelFrame(self.keys_tab, text="Generate My RSA Key Pairs", padding=15, style="TLabelframe")
        frame.pack(padx=5, pady=10, fill=tk.X)

        ttk.Label(frame, text="Number of New Key Pairs:", style="TLabel").grid(row=0, column=0, padx=5, pady=10,
                                                                               sticky=tk.W)
        self.num_keys_var = tk.StringVar(value="1")
        ttk.Entry(frame, textvariable=self.num_keys_var, width=7, style="TEntry").grid(row=0, column=1, padx=5, pady=10,
                                                                                       sticky=tk.W)

        ttk.Label(frame, text="Key Filename Prefix:", style="TLabel").grid(row=1, column=0, padx=5, pady=10,
                                                                           sticky=tk.W)
        self.key_prefix_var = tk.StringVar(value="journalist_key")
        ttk.Entry(frame, textvariable=self.key_prefix_var, width=30, style="TEntry").grid(row=1, column=1, padx=5,
                                                                                          pady=10, sticky=tk.W)

        self.password_protect_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Password-protect new private keys", variable=self.password_protect_var,
                        style="TCheckbutton").grid(row=2, column=0, columnspan=2, pady=10, sticky=tk.W)

        ttk.Button(frame, text="Generate Key Pairs", command=self.generate_keys_threaded).grid(row=3, column=0,
                                                                                               columnspan=2,
                                                                                               pady=(15, 5))

        info_frame = ttk.Frame(self.keys_tab, padding=(5, 0), style="TFrame")
        info_frame.pack(fill=tk.X, pady=(5, 10))
        ttk.Label(info_frame, text=f"Private keys saved to: '{os.path.basename(DEFAULT_PRIVATE_KEYS_DIR)}'",
                  style="TLabel").pack(anchor='w', padx=5)
        ttk.Label(info_frame,
                  text=f"Public keys (for server) saved to: '{os.path.basename(DEFAULT_PUBLIC_KEYS_FOR_SERVER_DIR)}'",
                  style="TLabel").pack(anchor='w', padx=5)
        ttk.Label(info_frame, text="Use 'Server Setup & Admin' tab to upload public keys.", style="TLabel").pack(
            anchor='w', padx=5, pady=(0, 5))

        pubkey_display_frame = ttk.LabelFrame(self.keys_tab, text="Content of Last Generated Public Keys", padding=10,
                                              style="TLabelframe")
        pubkey_display_frame.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        self.generated_pubkeys_text = scrolledtext.ScrolledText(
            pubkey_display_frame, height=6, state=tk.DISABLED,
            wrap=tk.WORD, **self.log_text_area_config
        )
        self.generated_pubkeys_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # --- ALL OTHER JournalistApp METHODS (upload_public_keys_*, on_submission_select_treeview, select_private_key_file, refresh_submissions_*, decrypt_selected_submission_*, generate_keys_*)
    # Ensure you paste your complete, corrected versions of these methods here.
    # I've included the stubs from your file and integrated the select_private_key_file fix.
    # For brevity in this response, I'm not repeating all of them, but they are crucial.

    def upload_public_keys_to_server_threaded(self):  # From your file
        # Corrected: Call the method that takes arguments AFTER getting them
        if not self.server_url.get() or not self.api_key.get():
            self.log_message("Server URL or API Key not configured for uploading keys.", "ERROR")
            self.root.after(0, lambda: messagebox.showerror("Configuration Error",
                                                            "Please set Server URL and API Key first.",
                                                            parent=self.root))
            return
        selected_key_files = filedialog.askopenfilenames(
            parent=self.root, title="Select Public Key Files to Upload",
            initialdir=DEFAULT_PUBLIC_KEYS_FOR_SERVER_DIR,
            filetypes=(("Public Key files", "*.pem *.pub"), ("All files", "*.*")))
        if not selected_key_files:
            self.log_message("No public key files selected for upload.");
            return
        threading.Thread(target=self.upload_public_keys_to_server_worker, args=(selected_key_files,),
                         daemon=True).start()

    def upload_public_keys_to_server_worker(self, key_files_to_upload):  # From your file
        public_keys_payload = []
        for f_path in key_files_to_upload:
            try:
                with open(f_path, 'r') as kf:
                    content = kf.read()
                if content.strip().startswith("-----BEGIN PUBLIC KEY-----"):
                    filename_base = os.path.basename(f_path)
                    hint = filename_base
                    possible_suffixes = ["_public.pem", ".pem", "_public.pub", ".pub"]
                    for suffix in possible_suffixes:
                        if hint.lower().endswith(suffix.lower()): hint = hint[:-len(suffix)]; break
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
            self.log_message("No valid public keys found in selected files to form payload.", "WARNING");
            return
        self.log_message(f"Attempting to upload {len(public_keys_payload)} public keys to server...")
        payload_to_send = {"public_keys": public_keys_payload}
        headers_req = {"Authorization": f"Bearer {self.api_key.get()}", "Content-Type": "application/json"}
        try:
            target_url = f"{self.server_url.get().rstrip('/')}/journalist/admin/add-public-keys"
            self.log_message(f"GUI UPLOAD (Worker): Sending POST to {target_url}", "DEBUG")
            response = requests.post(target_url, json=payload_to_send, headers=headers_req, timeout=30)
            response.raise_for_status();
            result_data = response.json()
            self.log_message(f"Server response: {result_data.get('message', 'No message.')}", "INFO")
            self.log_message(
                f"Successfully added: {result_data.get('success_count', 0)}, Failed: {result_data.get('failure_count', 0)}",
                "INFO")
            if result_data.get('details'):
                for detail in result_data['details']:
                    self.log_message(
                        f"  - Key: {detail.get('key_preview', 'N/A')} - Status: {detail.get('status', 'N/A')} ({detail.get('reason', '')})",
                        "DETAIL")
            self.root.after(0, lambda r_data=result_data: messagebox.showinfo("Upload Complete",
                                                                              f"Upload finished.\nSuccessful: {r_data.get('success_count', 0)}\nFailed: {r_data.get('failure_count', 0)}\nCheck log.",
                                                                              parent=self.root))
        except requests.exceptions.HTTPError as http_e:
            err_msg = f"HTTP error uploading keys: {http_e.response.status_code} for {http_e.request.url if http_e.request else 'N/A'}."
            try:
                server_err = http_e.response.json().get("error", "No details."); err_msg += f" Server: {server_err}"
            except:
                err_msg += f" Server raw response: {http_e.response.text[:100]}"
            self.log_message(err_msg, "ERROR")
            self.root.after(0, lambda em=err_msg: messagebox.showerror("Upload Error", em, parent=self.root))
        except requests.exceptions.RequestException as req_e:
            failed_url = req_e.request.url if req_e.request else 'N/A'
            self.log_message(f"Network error uploading keys: {req_e} (URL: {failed_url})", "ERROR")
            self.root.after(0, lambda er=req_e: messagebox.showerror("Network Error", f"Could not upload keys: {er}",
                                                                     parent=self.root))
        except Exception as e_gen:
            self.log_message(f"Unexpected error during key upload worker: {e_gen}", "ERROR");
            self.log_message(traceback.format_exc(), "ERROR_TRACE")
            self.root.after(0, lambda eg=e_gen: messagebox.showerror("Error", f"Unexpected error during upload: {eg}",
                                                                     parent=self.root))

    def on_submission_select_treeview(self, event):  # From your file
        selected_item_id_internal = self.submissions_tree.focus()
        if selected_item_id_internal:
            item_values = self.submissions_tree.item(selected_item_id_internal)['values']
            if item_values and len(item_values) >= 1:
                self.selected_submission_id.set(str(item_values[0]))
                key_hint_used = str(item_values[1]) if len(item_values) > 1 else "N/A"
                self.log_message(
                    f"Submission selected: {self.selected_submission_id.get()} (Server used key hint: '{key_hint_used}')")
                if self.private_key_path.get(): self.decrypt_button.config(state=tk.NORMAL)
            else:
                self.selected_submission_id.set("");
                self.decrypt_button.config(state=tk.DISABLED)
                self.log_message("Selected treeview item has no values.", "WARNING")
        else:
            self.selected_submission_id.set("");
            self.decrypt_button.config(state=tk.DISABLED)

    def select_private_key_file(self):  # From your file, with self.submissions_tree.focus()
        filepath = filedialog.askopenfilename(
            parent=self.root,
            initialdir=DEFAULT_PRIVATE_KEYS_DIR,
            title="Select RSA Private Key",
            filetypes=(("PEM files", "*.pem"), ("All files", "*.*"))
        )
        if filepath:
            self.private_key_path.set(filepath)
            self.private_key_display_label.config(text=os.path.basename(filepath))
            self.log_message(f"Private key selected for decryption: {os.path.basename(filepath)}")
            if self.submissions_tree.focus():
                self.decrypt_button.config(state=tk.NORMAL)
        else:
            self.decrypt_button.config(state=tk.DISABLED)

    def refresh_submissions_list_threaded(self):  # From your file
        threading.Thread(target=self.refresh_submissions_list, daemon=True).start()

    def refresh_submissions_list(self):  # From your file
        self.log_message("Refreshing submissions list...")
        current_api_key = self.api_key.get()
        if not current_api_key:
            self.log_message("API Key is missing in GUI config. Cannot refresh.", "ERROR")
            self.root.after(0, lambda: messagebox.showerror("Config Error", "API Key is not set in Setup tab.",
                                                            parent=self.root))
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
                else:
                    self.log_message("No submissions found in the response list.")
            else:
                self.log_message("No 'submissions' list in server response or unexpected format.", "WARNING")
                if data: self.log_message(f"Server response received: {str(data)[:200]}", "DEBUG")
        except requests.exceptions.HTTPError as http_e:
            err_msg = f"HTTP error: {http_e.response.status_code} for {http_e.request.url}."
            try:
                server_err = http_e.response.json().get("error", "No details."); err_msg += f" Server: {server_err}"
            except:
                err_msg += f" Server raw response: {http_e.response.text[:100]}"
            self.log_message(err_msg, "ERROR")
            self.root.after(0, lambda em=err_msg: messagebox.showerror("Network Error", em, parent=self.root))
        except requests.exceptions.RequestException as req_e:
            failed_url = req_e.request.url if req_e.request else 'N/A'
            self.log_message(f"Network error refreshing submissions: {req_e} (URL: {failed_url})", "ERROR")
            self.root.after(0, lambda er=req_e: messagebox.showerror("Network Error",
                                                                     f"Could not refresh submissions: {er}",
                                                                     parent=self.root))
        except json.JSONDecodeError:
            self.log_message("Invalid JSON response from server (refreshing submissions).", "ERROR")
            self.root.after(0, lambda: messagebox.showerror("Server Error", "Invalid JSON response from server.",
                                                            parent=self.root))
        except TypeError as te:
            self.log_message(f"TypeError processing submission data: {te}. Check server response format.", "ERROR")
            self.log_message(traceback.format_exc(), "ERROR_TRACE")
            self.root.after(0, lambda t=te: messagebox.showerror("Data Error", f"Error processing data: {t}",
                                                                 parent=self.root))
        except Exception as ex:
            self.log_message(f"Unexpected error refreshing submissions: {ex}", "ERROR")
            self.log_message(traceback.format_exc(), "ERROR_TRACE")
            self.root.after(0, lambda e=ex: messagebox.showerror("Error", f"Unexpected error: {e}", parent=self.root))

    def decrypt_selected_submission_threaded(self):  # From your file
        if not self.selected_submission_id.get():
            messagebox.showwarning("No Selection", "Please select a submission to decrypt.", parent=self.root);
            return
        if not self.private_key_path.get():
            messagebox.showwarning("No Key", "Please select an RSA private key for decryption.", parent=self.root);
            return
        sub_id = self.selected_submission_id.get()
        priv_key_file = self.private_key_path.get()
        self.log_message(f"Preparing for decryption of {sub_id} using {os.path.basename(priv_key_file)}", "DEBUG")
        self.log_message(f"Attempting to read private key file: {priv_key_file}", "DEBUG")
        private_key_pem = None
        try:
            with open(priv_key_file, 'r') as f:
                private_key_pem = f.read()
            self.log_message("Private key file read successfully.", "DEBUG")
        except Exception as e:
            self.log_message(f"FATAL: Error reading private key file: {e}", "ERROR")
            messagebox.showerror("Key Error", f"Could not read private key: {e}", parent=self.root);
            return
        self.log_message("Prompting for private key password (GUI Thread)...", "DEBUG")
        priv_key_password_input = simpledialog.askstring(
            "Private Key Password",
            f"Enter password for {os.path.basename(priv_key_file)}\n(Leave blank if not password-protected):",
            parent=self.root, show='*')
        if priv_key_password_input is None:
            self.log_message("Decryption cancelled by user at password prompt.", "INFO");
            return
        actual_priv_key_password = priv_key_password_input if priv_key_password_input else None
        self.log_message("Password dialog returned. Starting worker thread for decryption.", "DEBUG")
        threading.Thread(target=self.decrypt_selected_submission_worker,
                         args=(sub_id, private_key_pem, actual_priv_key_password), daemon=True).start()

    def decrypt_selected_submission_worker(self, sub_id, private_key_pem_content, priv_key_password):  # From your file
        self.log_message(f"Worker thread started for decryption of {sub_id}.", "DEBUG")
        current_api_key = self.api_key.get()
        if not current_api_key:
            self.log_message("API Key is missing in GUI config. Cannot proceed.", "ERROR")
            self.root.after(0, lambda: messagebox.showerror("Config Error", "API Key is not set in Setup tab.",
                                                            parent=self.root))
            return
        headers_req = {"Authorization": f"Bearer {current_api_key}"}
        base_server_url = self.server_url.get().rstrip('/')
        self.log_message("Entering main decryption network/crypto block (Worker Thread)...", "DEBUG")
        try:
            package_info_url = urllib.parse.urljoin(base_server_url + '/', f"journalist/submission/{sub_id}/package")
            self.log_message(f"Fetching package info from: {package_info_url}", "DEBUG")
            resp_pkg = requests.get(package_info_url, headers=headers_req, timeout=15)
            resp_pkg.raise_for_status();
            package_data = resp_pkg.json()
            self.log_message(f"Package info fetched: {str(package_data)[:200]}...", "DEBUG")

            enc_aes_key_url = package_data['encrypted_aes_key_url']
            enc_file_url = package_data['encrypted_file_url']
            enc_filename_url = package_data['encrypted_filename_url']

            self.log_message(f"Downloading AES key from {enc_aes_key_url}", "DEBUG")
            resp_key = requests.get(enc_aes_key_url, headers=headers_req, timeout=20);
            resp_key.raise_for_status()
            encrypted_aes_key_data = resp_key.content;
            self.log_message("AES key downloaded.", "DEBUG")

            self.log_message(f"Downloading filename from {enc_filename_url}", "DEBUG")
            resp_fname = requests.get(enc_filename_url, headers=headers_req, timeout=20);
            resp_fname.raise_for_status()
            encrypted_original_filename_data = resp_fname.content;
            self.log_message("Encrypted filename downloaded.", "DEBUG")

            self.log_message(f"Downloading file from {enc_file_url}", "DEBUG")
            resp_file = requests.get(enc_file_url, headers=headers_req, timeout=180);
            resp_file.raise_for_status()
            encrypted_file_data = resp_file.content;
            self.log_message("Encrypted file downloaded.", "DEBUG")

            self.log_message("Decrypting AES key (locally)...", "DEBUG")
            decrypted_aes_key = crypto_utils.decrypt_rsa(encrypted_aes_key_data, private_key_pem_content,
                                                         priv_key_password)
            if not decrypted_aes_key:
                self.log_message("Failed to decrypt AES key. Wrong password or key mismatch.", "ERROR")
                self.root.after(0, lambda: messagebox.showerror("Decryption Error",
                                                                "Failed to decrypt AES key. Check password or key.",
                                                                parent=self.root));
                return
            self.log_message("AES key decrypted.", "DEBUG")

            self.log_message("Decrypting original filename (locally)...", "DEBUG")
            decrypted_original_filename_bytes = crypto_utils.decrypt_aes_gcm(encrypted_original_filename_data,
                                                                             decrypted_aes_key)
            original_filename = f"{sub_id}_decrypted.dat"
            if decrypted_original_filename_bytes:
                original_filename = decrypted_original_filename_bytes.decode('utf-8', errors='replace')
                self.log_message(f"Original filename: {original_filename}", "DEBUG")
            else:
                self.log_message("Failed to decrypt original filename. Using generic.", "WARNING")

            self.log_message(f"Decrypting content for '{original_filename}' (locally)...", "DEBUG")
            decrypted_file_data = crypto_utils.decrypt_aes_gcm(encrypted_file_data, decrypted_aes_key)
            if not decrypted_file_data:
                self.log_message("Failed to decrypt file data. AES key incorrect/data corrupted.", "ERROR")
                self.root.after(0, lambda: messagebox.showerror("Decryption Error", "Failed to decrypt file data.",
                                                                parent=self.root));
                return
            self.log_message("File content decrypted.", "SUCCESS")

            def ask_save_file_main_thread():
                save_path = filedialog.asksaveasfilename(parent=self.root, initialdir=DEFAULT_DOWNLOAD_DIR,
                                                         initialfile=original_filename, title="Save Decrypted File As",
                                                         defaultextension=".*")
                if save_path:
                    try:
                        with open(save_path, 'wb') as f:
                            f.write(decrypted_file_data)
                        self.log_message(f"File saved: {save_path}", "SUCCESS")
                        messagebox.showinfo("Success", f"File saved:\n{save_path}", parent=self.root)
                    except IOError as ioe:
                        self.log_message(f"IOError saving: {ioe}", "ERROR")
                        messagebox.showerror("Save Error", f"Could not save: {ioe}", parent=self.root)
                else:
                    self.log_message("Save cancelled.")

            self.root.after(0, ask_save_file_main_thread)
        except requests.exceptions.HTTPError as http_e:
            err_msg = f"HTTP error: {http_e.response.status_code} for URL: {http_e.request.url}."
            try:
                server_err = http_e.response.json().get("error", "No details."); err_msg += f" Server: {server_err}"
            except:
                err_msg += f" Server raw response: {http_e.response.text[:100]}"
            self.log_message(err_msg, "ERROR")
            self.root.after(0, lambda emsg=err_msg: messagebox.showerror("Network Error", emsg, parent=self.root))
        except requests.exceptions.RequestException as req_e:
            failed_url = req_e.request.url if req_e.request else 'N/A'
            self.log_message(f"Network error: {req_e} (URL: {failed_url})", "ERROR")
            self.root.after(0, lambda er=req_e: messagebox.showerror("Network Error", f"Could not download: {er}",
                                                                     parent=self.root))
        except Exception as e_gen:
            error_msg = str(e_gen)
            self.log_message(f"Unexpected error in decryption worker: {error_msg}", "ERROR")
            self.log_message(traceback.format_exc(), "ERROR_TRACE")
            self.root.after(0, lambda bound_err=error_msg: messagebox.showerror("Error",
                                                                                f"An unexpected error occurred: {bound_err}",
                                                                                parent=self.root))

    def generate_keys_threaded(self):  # Copied
        try:
            num_keys = int(self.num_keys_var.get())
            if num_keys <= 0: messagebox.showerror("Invalid Input", "Number of keys must be positive.",
                                                   parent=self.root); return
        except ValueError:
            messagebox.showerror("Invalid Input", "Number of keys must be a valid integer.", parent=self.root); return
        key_prefix = self.key_prefix_var.get().strip()
        if not key_prefix: messagebox.showerror("Invalid Input", "Key ID prefix cannot be empty.",
                                                parent=self.root); return
        password = None
        if self.password_protect_var.get():
            password = simpledialog.askstring("Set Key Password", "Enter password for new private keys:",
                                              parent=self.root, show='*')
            if password is None: self.log_message("Key generation cancelled by user."); return
            if not password:
                if messagebox.askyesno("Password Empty",
                                       "Password is empty. Generate keys WITHOUT password protection?",
                                       parent=self.root):
                    password = None
                else:
                    self.log_message("Key generation aborted (empty password not accepted)."); return
        threading.Thread(target=self.generate_keys_worker, args=(num_keys, key_prefix, password), daemon=True).start()

    def generate_keys_worker(self, num_keys, key_prefix, password):  # Copied
        self.log_message(f"Generating {num_keys} key pair(s) with prefix '{key_prefix}'...")
        all_pub_keys_text_content = ""
        for i in range(1, num_keys + 1):
            self.log_message(f"Generating pair {i}...", "DEBUG")
            try:
                pub_path_for_server, priv_path = rsa_gen_module.generate_rsa_key_pair(
                    key_id_prefix=key_prefix, key_index=i, password=password)
                with open(pub_path_for_server, 'r') as f_pub:
                    pub_key_content = f_pub.read()
                all_pub_keys_text_content += f"--- Public Key for {os.path.basename(pub_path_for_server)} ---\n{pub_key_content}\n\n"
                self.log_message(
                    f"Generated: {os.path.basename(priv_path)} and {os.path.basename(pub_path_for_server)}")
            except Exception as e:
                self.log_message(f"Error generating key pair {i}: {e}", "ERROR")
                self.root.after(0, lambda err_val=e, idx_val=i: messagebox.showerror("Key Generation Error",
                                                                                     f"Failed for pair {idx_val}: {err_val}",
                                                                                     parent=self.root))
                return

        def update_gui_after_gen():
            self.generated_pubkeys_text.config(state=tk.NORMAL);
            self.generated_pubkeys_text.delete('1.0', tk.END)
            self.generated_pubkeys_text.insert(tk.END, all_pub_keys_text_content);
            self.generated_pubkeys_text.config(state=tk.DISABLED)
            self.log_message(
                f"{num_keys} pairs generated. Private keys in '{os.path.basename(DEFAULT_PRIVATE_KEYS_DIR)}', public keys in '{os.path.basename(DEFAULT_PUBLIC_KEYS_FOR_SERVER_DIR)}'.",
                "SUCCESS")
            messagebox.showinfo("Key Generation Complete", f"{num_keys} key pair(s) generated.", parent=self.root)

        self.root.after(0, update_gui_after_gen)


if __name__ == '__main__':
    root = tk.Tk()
    app = JournalistApp(root)
    icon_found = False
    icon_paths_to_try = [
        os.path.join(current_dir, 'autumn_leaf.png'),
        os.path.join(current_dir, 'autumn_leaf.ico')
    ]
    # Ensure app.log_message is available if icon loading fails early
    # However, app is defined after this block would run if placed before app = JournalistApp(root)
    # So, icon setting is best done after app instantiation, or use print for pre-app logs.

    for icon_path in icon_paths_to_try:
        if os.path.exists(icon_path):
            try:
                if icon_path.endswith('.png'):
                    img = tk.PhotoImage(file=icon_path)
                    root.tk.call('wm', 'iconphoto', root._w, img)
                    # app.log_message might not be ready if this is before app = ...
                    print(f"INFO: Set window icon from PNG: {icon_path}")
                    icon_found = True;
                    break
                elif icon_path.endswith('.ico') and os.name == 'nt':
                    root.iconbitmap(default=icon_path)
                    print(f"INFO: Set window icon from ICO: {icon_path}")
                    icon_found = True;
                    break
            except tk.TclError as e:
                print(f"WARNING: Could not set icon from {icon_path}: {e}")
            except Exception as e_icon:
                print(f"WARNING: Error loading icon {icon_path}: {e_icon}")

    if not icon_found and app:  # Check if app exists before calling log_message
        app.log_message("Custom window icon not found/loaded.", "WARNING")
    elif not icon_found:
        print("WARNING: Custom window icon not found/loaded.")

    root.mainloop()