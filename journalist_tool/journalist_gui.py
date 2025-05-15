# whistledrop/journalist_tool/journalist_gui.py
import tkinter as tk
from tkinter import ttk, filedialog, simpledialog, messagebox, scrolledtext
import os
import sys
import threading
import json
import secrets
import string  # For tooltip example
import urllib.parse
import time
import traceback
import keyring  # For password storage (optional)
import requests  # For HTTP requests

# Adjust path to allow imports from parent directory (whistledrop/)
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root_dir = os.path.dirname(current_dir)
if project_root_dir not in sys.path:
    sys.path.insert(0, project_root_dir)

from utils import generate_rsa_keys as rsa_gen_module
from journalist_tool import crypto_utils

CONFIG_FILE = os.path.join(current_dir, "gui_config.json")
DEFAULT_PRIVATE_KEYS_DIR = rsa_gen_module.PRIVATE_KEYS_OUTPUT_DIR
DEFAULT_PUBLIC_KEYS_FOR_SERVER_DIR = rsa_gen_module.PUBLIC_KEYS_FOR_SERVER_OUTPUT_DIR
DEFAULT_DOWNLOAD_DIR = os.path.join(current_dir, "decrypted_submissions")

DEFAULT_TOR_SOCKS_HOST = "127.0.0.1"
DEFAULT_TOR_SOCKS_PORT = 9150  # Common for Tor Browser

os.makedirs(DEFAULT_PRIVATE_KEYS_DIR, exist_ok=True)
os.makedirs(DEFAULT_PUBLIC_KEYS_FOR_SERVER_DIR, exist_ok=True)
os.makedirs(DEFAULT_DOWNLOAD_DIR, exist_ok=True)


# --- ToolTip Class (unchanged from your provided file) ---
class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        self.id = None
        self.x = self.y = 0
        self.label_font = ("Segoe UI", 8, "normal")
        try:
            if hasattr(self.widget, 'winfo_toplevel') and hasattr(self.widget.winfo_toplevel(), 'default_font_tooltip'):
                self.label_font = self.widget.winfo_toplevel().default_font_tooltip
        except:
            pass

    def showtip(self):
        self.hidetip()
        x, y, _, _ = self.widget.bbox("insert")
        x_root = self.widget.winfo_rootx()
        y_root = self.widget.winfo_rooty()
        x = x_root + self.widget.winfo_width() // 2
        y = y_root + self.widget.winfo_height() + 5
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(1)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                         background="#FFFFE0", relief=tk.SOLID, borderwidth=1,
                         font=self.label_font, wraplength=300)
        label.pack(ipadx=3, ipady=2)

    def hidetip(self):
        if self.tipwindow:
            self.tipwindow.destroy()
        self.tipwindow = None


class LoginDialog(simpledialog.Dialog):
    def __init__(self, parent, title, initial_username=""):
        self.username_val = tk.StringVar(value=initial_username)
        self.password_val = tk.StringVar()
        self.result = None
        super().__init__(parent, title)

    def body(self, master):
        ttk.Label(master, text="Username:").grid(row=0, sticky=tk.W, padx=5, pady=2)
        self.username_entry = ttk.Entry(master, textvariable=self.username_val, width=30)
        self.username_entry.grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(master, text="Password:").grid(row=1, sticky=tk.W, padx=5, pady=2)
        self.password_entry = ttk.Entry(master, textvariable=self.password_val, show="*", width=30)
        self.password_entry.grid(row=1, column=1, padx=5, pady=2)

        self.username_entry.focus_set()
        return self.username_entry  # initial focus

    def buttonbox(self):
        box = ttk.Frame(self)
        ttk.Button(box, text="Login", width=10, command=self.ok, default=tk.ACTIVE).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(box, text="Cancel", width=10, command=self.cancel).pack(side=tk.LEFT, padx=5, pady=5)
        self.bind("<Return>", self.ok)
        self.bind("<Escape>", self.cancel)
        box.pack()

    def apply(self):
        self.result = (self.username_val.get(), self.password_val.get())


class JournalistApp:
    def __init__(self, root_window):
        self.root = root_window
        self.root.title("WhistleDrop Journalist Tool")
        self.root.geometry("950x750")

        # --- Session for requests ---
        self.session = requests.Session()  # Manages cookies for login

        # --- AUTUMN THEME COLORS (unchanged) ---
        self.bg_color = '#FAF8F1';
        self.frame_bg_color = '#F3EADA'
        self.accent_color_primary = '#E87A00';
        self.accent_hover_primary = '#D36F00'
        self.accent_color_secondary = '#8C5A32';
        self.accent_hover_secondary = '#754C24'
        self.text_color = '#5D4037';
        self.header_text_color = self.accent_color_secondary
        self.border_color = '#D1C0A8';
        self.entry_bg_color = '#FFFDF9'
        self.button_text_color_on_orange = '#FFFFFF';
        self.button_text_color_on_brown = '#FAF8F1'
        self.root.configure(bg=self.bg_color)

        # --- TTK Style Configuration (largely unchanged) ---
        self.style = ttk.Style();
        self.style.theme_use('clam')
        self.default_font = ("Segoe UI", 10);
        self.bold_font = ("Segoe UI", 10, "bold")
        self.log_font = ("Consolas", 9);
        self.root.option_add("*Font", self.default_font)
        self.root.default_font_tooltip = ("Segoe UI", 8, "normal")
        # (All self.style.configure and self.style.map calls remain the same as your provided file)
        self.style.configure(".", font=self.default_font, background=self.bg_color, foreground=self.text_color)
        self.style.configure("TFrame", background=self.frame_bg_color)
        self.style.configure("TLabel", background=self.frame_bg_color, foreground=self.text_color, padding=3)
        self.style.configure("TLabelframe", background=self.frame_bg_color, bordercolor=self.border_color,
                             font=self.bold_font, relief="groove", borderwidth=1, padding=10)
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
                             indicatorrelief="flat", indicatormargin=5, font=self.default_font)
        self.style.map("TCheckbutton",
                       indicatorbackground=[('selected', self.accent_color_primary),
                                            ('!selected', self.entry_bg_color)],
                       indicatorforeground=[('selected', self.button_text_color_on_orange)])

        self.log_text_area_config = {
            "font": self.log_font, "bg": self.entry_bg_color, "fg": self.text_color,
            "relief": "solid", "borderwidth": 1, "highlightthickness": 1,
            "highlightbackground": self.border_color, "highlightcolor": self.accent_color_primary,
            "insertbackground": self.text_color, "selectbackground": self.accent_color_secondary,
            "selectforeground": self.button_text_color_on_brown
        }
        # --- End TTK Style Configuration ---

        self.server_url = tk.StringVar(value="https://127.0.0.1:5001")  # Default to HTTPS
        self.last_username = tk.StringVar()  # For pre-filling login dialog
        self.private_key_path = tk.StringVar()
        self.selected_submission_id = tk.StringVar()
        self.tor_socks_host = tk.StringVar(value=DEFAULT_TOR_SOCKS_HOST)
        self.tor_socks_port = tk.IntVar(value=DEFAULT_TOR_SOCKS_PORT)
        self.verify_ssl_var = tk.BooleanVar(value=False)  # Default to False for self-signed certs

        self.is_logged_in = False
        self.current_journalist_username = tk.StringVar(value="Not logged in")

        self.log_text_frame = ttk.LabelFrame(root_window, text="Application Log", padding=(10, 5), style="TLabelframe")
        self.log_text = scrolledtext.ScrolledText(
            self.log_text_frame, height=10, state=tk.DISABLED,
            wrap=tk.WORD, **self.log_text_area_config
        )

        self.load_config()  # Load config before creating UI elements that depend on it

        self.notebook = ttk.Notebook(root_window, style="TNotebook")
        self.setup_tab = ttk.Frame(self.notebook, padding=(20, 15), style="TFrame")
        self.submissions_tab = ttk.Frame(self.notebook, padding=(20, 15), style="TFrame")
        self.keys_tab = ttk.Frame(self.notebook, padding=(20, 15), style="TFrame")
        self.notebook.add(self.setup_tab, text=' Connection & Admin ')
        self.notebook.add(self.submissions_tab, text=' Submissions ')
        self.notebook.add(self.keys_tab, text=' Key Generation ')
        self.notebook.pack(expand=1, fill='both', padx=10, pady=(10, 5))

        self.create_setup_tab()
        self.create_submissions_tab()
        self.create_keys_tab()

        self.log_text_frame.pack(pady=(5, 10), padx=10, fill=tk.X)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        if not hasattr(self, 'initial_log_done'):
            self.log_message("GUI Initialized. Configure server and login.")
            self.log_message(
                f"Using Tor SOCKS proxy: {self.tor_socks_host.get()}:{self.tor_socks_port.get()} for .onion URLs.")
            self.log_message(
                f"SSL Certificate Verification: {'Enabled' if self.verify_ssl_var.get() else 'Disabled (for self-signed certs)'}")
            self.initial_log_done = True

        self.update_login_status_display()
        self.root.after(100, self.prompt_login_if_not_logged_in)  # Prompt for login shortly after start

    def prompt_login_if_not_logged_in(self):
        if not self.is_logged_in:
            self.handle_login()

    def log_message(self, message, level="INFO"):
        # (Unchanged from your provided file)
        if hasattr(self, 'log_text'):
            self.log_text.config(state=tk.NORMAL)
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            self.log_text.insert(tk.END, f"[{timestamp} {level}] {message}\n")
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
        else:
            print(f"LOG EARLY [{level}]: {message}")

    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config_data = json.load(f)
                    self.server_url.set(config_data.get("server_url", "https://127.0.0.1:5001"))
                    self.last_username.set(config_data.get("last_username", ""))
                    self.tor_socks_host.set(config_data.get("tor_socks_host", DEFAULT_TOR_SOCKS_HOST))
                    self.tor_socks_port.set(int(config_data.get("tor_socks_port", DEFAULT_TOR_SOCKS_PORT)))
                    self.verify_ssl_var.set(config_data.get("verify_ssl", False))  # Load SSL verify preference
                self.log_message("Configuration loaded.", "INFO")
            else:
                self.log_message(f"Config file '{CONFIG_FILE}' not found, using defaults.", "INFO")
        except Exception as e:
            self.log_message(f"Error loading config: {e}. Using defaults.", "ERROR")

    def save_config(self):
        try:
            port_val = self.tor_socks_port.get()
        except tk.TclError:
            messagebox.showerror("Invalid Port", "Tor SOCKS Port must be a valid number.", parent=self.root); return

        config_data = {
            "server_url": self.server_url.get(),
            "last_username": self.last_username.get(),
            "tor_socks_host": self.tor_socks_host.get(),
            "tor_socks_port": port_val,
            "verify_ssl": self.verify_ssl_var.get()
        }
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config_data, f, indent=4)
            self.log_message("Configuration saved.")
            self.log_message(
                f"SSL Certificate Verification set to: {'Enabled' if self.verify_ssl_var.get() else 'Disabled'}")
        except Exception as e:
            self.log_message(f"Error saving config: {e}", "ERROR")

    def create_tooltip(self, widget, text):  # (Unchanged)
        tooltip = ToolTip(widget, text)
        widget.bind("<Enter>", lambda event, t=tooltip: t.showtip())
        widget.bind("<Leave>", lambda event, t=tooltip: t.hidetip())

    def get_proxies(self):  # (Unchanged)
        if ".onion" in self.server_url.get().lower():
            host = self.tor_socks_host.get()
            try:
                port = self.tor_socks_port.get()
                if host and port > 0:
                    proxy_url = f"socks5h://{host}:{port}"
                    return {"http": proxy_url, "https": proxy_url}
            except tk.TclError:
                self.log_message(f"Invalid Tor SOCKS port: '{self.tor_socks_port.get()}'", "ERROR")
        return None  # No proxy for non-.onion or if Tor proxy is invalid

    def update_login_status_display(self):
        if hasattr(self, 'login_status_label'):
            status_text = f"Logged in as: {self.current_journalist_username.get()}" if self.is_logged_in else "Status: Not logged in"
            self.login_status_label.config(text=status_text)
            if hasattr(self, 'login_button'):
                self.login_button.config(text="Logout" if self.is_logged_in else "Login")

    def handle_login_logout(self):
        if self.is_logged_in:
            self.handle_logout()
        else:
            self.handle_login()

    def handle_login(self):
        dialog = LoginDialog(self.root, "Journalist Login", initial_username=self.last_username.get())
        if dialog.result:
            username, password = dialog.result
            if not username or not password:
                messagebox.showerror("Login Failed", "Username and password cannot be empty.", parent=self.root)
                return

            self.last_username.set(username)  # Save for next time
            self.save_config()  # Save updated last_username

            # Perform login in a separate thread
            threading.Thread(target=self.perform_login_worker, args=(username, password), daemon=True).start()

    def perform_login_worker(self, username, password):
        self.log_message(f"Attempting login for user: {username}...")
        login_url = urllib.parse.urljoin(self.server_url.get().rstrip('/') + '/', "login")
        payload = {"username": username, "password": password}
        current_proxies = self.get_proxies()
        ssl_verify = self.verify_ssl_var.get()

        try:
            # Use self.session for requests to maintain login cookies
            response = self.session.post(login_url, data=payload, proxies=current_proxies, verify=ssl_verify,
                                         timeout=90)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

            # Successful login if no HTTPError (server usually redirects or sends success)
            # We assume success if we get here without error.
            # The server should set a session cookie.
            self.is_logged_in = True
            self.current_journalist_username.set(username)
            self.log_message(f"Login successful for {username}.", "SUCCESS")
            self.root.after(0,
                            lambda: messagebox.showinfo("Login Successful", f"Welcome, {username}!", parent=self.root))
            self.root.after(0, self.update_login_status_display)
            self.root.after(0, self.refresh_submissions_list_threaded)  # Refresh list after login

        except requests.exceptions.HTTPError as http_e:
            self.is_logged_in = False
            self.current_journalist_username.set("Not logged in")
            err_msg = f"Login failed for {username}. Server responded with {http_e.response.status_code}."
            try:
                server_err_json = http_e.response.json()
                flash_msg = server_err_json.get("flash_message")  # Check if server sends flash message in JSON
                if flash_msg: err_msg += f" Server message: {flash_msg}"
            except json.JSONDecodeError:  # If response is not JSON
                if "Invalid username or password" in http_e.response.text:  # Crude check
                    err_msg = f"Login failed for {username}: Invalid username or password."
                else:
                    err_msg += f" Raw response: {http_e.response.text[:100]}"

            self.log_message(err_msg, "ERROR")
            self.root.after(0, lambda em=err_msg: messagebox.showerror("Login Failed", em, parent=self.root))
            self.root.after(0, self.update_login_status_display)

        except requests.exceptions.RequestException as req_e:
            self.is_logged_in = False
            self.current_journalist_username.set("Not logged in")
            self.log_message(f"Login network error for {username}: {req_e}", "ERROR")
            self.root.after(0,
                            lambda er=req_e: messagebox.showerror("Login Error", f"Could not connect to server: {er}",
                                                                  parent=self.root))
            self.root.after(0, self.update_login_status_display)
        except Exception as e:
            self.is_logged_in = False
            self.current_journalist_username.set("Not logged in")
            self.log_message(f"Unexpected error during login for {username}: {e}", "ERROR")
            self.root.after(0, lambda ex=e: messagebox.showerror("Login Error", f"An unexpected error occurred: {ex}",
                                                                 parent=self.root))
            self.root.after(0, self.update_login_status_display)

    def handle_logout(self):
        threading.Thread(target=self.perform_logout_worker, daemon=True).start()

    def perform_logout_worker(self):
        if not self.is_logged_in:
            self.log_message("Not logged in, logout unnecessary.", "INFO")
            return

        self.log_message(f"Attempting logout for user: {self.current_journalist_username.get()}...")
        logout_url = urllib.parse.urljoin(self.server_url.get().rstrip('/') + '/', "logout")
        current_proxies = self.get_proxies()
        ssl_verify = self.verify_ssl_var.get()

        try:
            # Use self.session for requests to send session cookies
            response = self.session.get(logout_url, proxies=current_proxies, verify=ssl_verify, timeout=15)
            response.raise_for_status()

            self.is_logged_in = False
            self.log_message(f"Logout successful for {self.current_journalist_username.get()}.", "SUCCESS")
            self.current_journalist_username.set("Not logged in")
            self.root.after(0, lambda: messagebox.showinfo("Logout", "You have been successfully logged out.",
                                                           parent=self.root))
            # Clear submissions tree
            self.root.after(0, lambda: [self.submissions_tree.delete(item) for item in
                                        self.submissions_tree.get_children()])

        except requests.exceptions.RequestException as req_e:
            # Log error, but still mark as logged out on client side for safety/simplicity
            self.log_message(f"Logout network error: {req_e}. Forcing logout on client.", "ERROR")
            self.is_logged_in = False  # Force logout on client
            self.current_journalist_username.set("Not logged in")
            self.root.after(0, lambda er=req_e: messagebox.showwarning("Logout Error",
                                                                       f"Could not confirm logout with server: {er}\nClient state reset.",
                                                                       parent=self.root))
        finally:
            self.root.after(0, self.update_login_status_display)

    def create_setup_tab(self):
        conn_frame = ttk.LabelFrame(self.setup_tab, text="WhistleDrop Server Connection", padding=15,
                                    style="TLabelframe")
        conn_frame.pack(padx=5, pady=(5, 10), fill=tk.X, expand=False)

        ttk.Label(conn_frame, text="Server URL (.onion or local):", style="TLabel").grid(row=0, column=0, padx=5,
                                                                                         pady=5, sticky=tk.W)
        ttk.Entry(conn_frame, textvariable=self.server_url, width=55, style="TEntry").grid(row=0, column=1, padx=5,
                                                                                           pady=5, sticky=tk.EW)

        # Login Status and Button
        login_status_frame = ttk.Frame(conn_frame, style="TFrame")
        login_status_frame.grid(row=1, column=0, columnspan=2, pady=(10, 5), sticky=tk.EW)
        self.login_status_label = ttk.Label(login_status_frame, text="Status: Not logged in", style="TLabel")
        self.login_status_label.pack(side=tk.LEFT, padx=5, pady=5)
        self.login_button = ttk.Button(login_status_frame, text="Login", command=self.handle_login_logout,
                                       style="Secondary.TButton")
        self.login_button.pack(side=tk.RIGHT, padx=5, pady=5)

        proxy_frame = ttk.LabelFrame(conn_frame, text="Tor SOCKS Proxy (for .onion access)", padding=(10, 5),
                                     style="TLabelframe")
        proxy_frame.grid(row=2, column=0, columnspan=2, sticky=tk.EW, pady=(10, 5), padx=0)
        ttk.Label(proxy_frame, text="Host:", style="TLabel").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Entry(proxy_frame, textvariable=self.tor_socks_host, width=20, style="TEntry").grid(row=0, column=1, padx=5,
                                                                                                pady=5, sticky=tk.EW)
        ttk.Label(proxy_frame, text="Port:", style="TLabel").grid(row=0, column=2, padx=(10, 5), pady=5, sticky=tk.W)
        ttk.Entry(proxy_frame, textvariable=self.tor_socks_port, width=8, style="TEntry").grid(row=0, column=3, padx=5,
                                                                                               pady=5, sticky=tk.W)
        proxy_frame.columnconfigure(1, weight=1)

        ssl_check = ttk.Checkbutton(conn_frame, text="Verify SSL Certificate (disable for self-signed certs)",
                                    variable=self.verify_ssl_var, style="TCheckbutton")
        ssl_check.grid(row=3, column=0, columnspan=2, pady=(10, 0), sticky=tk.W)

        save_button = ttk.Button(conn_frame, text="Save Connection & Proxy Settings", command=self.save_config)
        save_button.grid(row=4, column=0, columnspan=2, pady=(15, 5))
        conn_frame.columnconfigure(1, weight=1)

        pubkey_upload_frame = ttk.LabelFrame(self.setup_tab, text="Upload Public Keys to Server", padding=15,
                                             style="TLabelframe")
        pubkey_upload_frame.pack(padx=5, pady=10, fill=tk.X, expand=False)
        info_label_pubkey = ttk.Label(pubkey_upload_frame, justify=tk.LEFT, style="TLabel",
                                      text=f"Select .pem/.pub files to upload. Keys are typically generated in 'Key Generation' tab \nand saved to '{os.path.basename(DEFAULT_PUBLIC_KEYS_FOR_SERVER_DIR)}'. Requires login.")
        info_label_pubkey.pack(pady=(0, 10), fill=tk.X)
        ttk.Button(pubkey_upload_frame, text="Select & Upload Public Keys",
                   command=self.upload_public_keys_to_server_threaded).pack(pady=5)

    def create_submissions_tab(self):  # (Largely unchanged, but button states might depend on login)
        top_frame = ttk.Frame(self.submissions_tab, style="TFrame")
        top_frame.pack(fill=tk.X, pady=(0, 10))
        self.refresh_button = ttk.Button(top_frame, text="Refresh Submissions List",
                                         command=self.refresh_submissions_list_threaded, style="Secondary.TButton")
        self.refresh_button.pack(side=tk.LEFT, padx=0)

        columns = ("submission_id", "key_hint")
        self.submissions_tree = ttk.Treeview(self.submissions_tab, columns=columns, show="headings", height=10,
                                             style="Treeview")
        self.submissions_tree.heading("submission_id", text="Submission ID");
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

    def create_keys_tab(self):  # (Unchanged)
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
        ttk.Label(info_frame, text="Use 'Connection & Admin' tab to upload public keys.", style="TLabel").pack(
            anchor='w', padx=5, pady=(0, 5))
        pubkey_display_frame = ttk.LabelFrame(self.keys_tab, text="Content of Last Generated Public Keys", padding=10,
                                              style="TLabelframe")
        pubkey_display_frame.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        self.generated_pubkeys_text = scrolledtext.ScrolledText(pubkey_display_frame, height=6, state=tk.DISABLED,
                                                                wrap=tk.WORD, **self.log_text_area_config)
        self.generated_pubkeys_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def upload_public_keys_to_server_threaded(self):
        if not self.is_logged_in:
            self.log_message("Login required to upload public keys.", "ERROR")
            messagebox.showerror("Login Required", "Please login first via the 'Connection & Admin' tab.",
                                 parent=self.root)
            return
        # (Rest of the method is the same as your provided file, but uses self.session)
        selected_key_files = filedialog.askopenfilenames(
            parent=self.root, title="Select Public Key Files to Upload",
            initialdir=DEFAULT_PUBLIC_KEYS_FOR_SERVER_DIR,
            filetypes=(("Public Key files", "*.pem *.pub"), ("All files", "*.*")))
        if not selected_key_files:
            self.log_message("No public key files selected for upload.");
            return
        threading.Thread(target=self.upload_public_keys_to_server_worker, args=(selected_key_files,),
                         daemon=True).start()

    def upload_public_keys_to_server_worker(self, key_files_to_upload):
        # (Same logic as your file, but uses self.session and self.verify_ssl_var)
        public_keys_payload = []
        for f_path in key_files_to_upload:
            try:
                with open(f_path, 'r') as kf:
                    content = kf.read()
                if content.strip().startswith("-----BEGIN PUBLIC KEY-----"):
                    filename_base = os.path.basename(f_path)
                    hint = filename_base
                    for suffix in ["_public.pem", ".pem", "_public.pub", ".pub"]:
                        if hint.lower().endswith(suffix.lower()): hint = hint[:-len(suffix)]; break
                    self.log_message(f"Preparing key '{filename_base}' (Hint: '{hint}') for upload.", "DEBUG")
                    public_keys_payload.append({"pem": content, "hint": hint})
                else:
                    self.log_message(f"Skipping {os.path.basename(f_path)}: Not valid PEM.", "WARNING")
            except Exception as e:
                self.log_message(f"Error reading {os.path.basename(f_path)}: {e}", "ERROR")

        if not public_keys_payload: self.log_message("No valid public keys to upload.", "WARNING"); return
        self.log_message(f"Attempting to upload {len(public_keys_payload)} public keys...")
        payload_to_send = {"public_keys": public_keys_payload}
        # Headers for JSON, session cookies handled by self.session
        headers_req = {"Content-Type": "application/json"}
        current_proxies = self.get_proxies()
        ssl_verify = self.verify_ssl_var.get()
        try:
            target_url = urllib.parse.urljoin(self.server_url.get().rstrip('/') + '/',
                                              "journalist/admin/add-public-keys")
            self.log_message(f"Uploading keys to {target_url} (SSL Verify: {ssl_verify})", "DEBUG")
            response = self.session.post(target_url, json=payload_to_send, headers=headers_req, proxies=current_proxies,
                                         verify=ssl_verify, timeout=30)
            response.raise_for_status()
            result_data = response.json()
            self.log_message(f"Server key upload response: {result_data.get('message', 'No message.')}", "INFO")
            # (Rest of result processing is the same)
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
                err_msg += f" Server raw: {http_e.response.text[:100]}"
            self.log_message(err_msg, "ERROR")
            self.root.after(0, lambda em=err_msg: messagebox.showerror("Upload Error", em, parent=self.root))
        except requests.exceptions.RequestException as req_e:
            self.log_message(f"Network error uploading keys: {req_e}", "ERROR")
            self.root.after(0, lambda er=req_e: messagebox.showerror("Network Error", f"Could not upload keys: {er}",
                                                                     parent=self.root))
        except Exception as e_gen:
            self.log_message(f"Unexpected error during key upload: {e_gen}", "ERROR");
            traceback.print_exc()
            self.root.after(0,
                            lambda eg=e_gen: messagebox.showerror("Error", f"Unexpected error: {eg}", parent=self.root))

    def on_submission_select_treeview(self, event):  # (Unchanged)
        selected_item_id_internal = self.submissions_tree.focus()
        if selected_item_id_internal:
            item_values = self.submissions_tree.item(selected_item_id_internal)['values']
            if item_values and len(item_values) >= 1:
                self.selected_submission_id.set(str(item_values[0]))
                key_hint_used = str(item_values[1]) if len(item_values) > 1 else "N/A"
                self.log_message(f"Submission selected: {self.selected_submission_id.get()} (Hint: '{key_hint_used}')")
                if self.private_key_path.get() and self.is_logged_in: self.decrypt_button.config(state=tk.NORMAL)
            else:
                self.selected_submission_id.set(""); self.decrypt_button.config(state=tk.DISABLED)
        else:
            self.selected_submission_id.set(""); self.decrypt_button.config(state=tk.DISABLED)

    def select_private_key_file(self):  # (Unchanged, but decrypt button state also depends on login)
        filepath = filedialog.askopenfilename(parent=self.root, initialdir=DEFAULT_PRIVATE_KEYS_DIR,
                                              title="Select RSA Private Key",
                                              filetypes=(("PEM files", "*.pem"), ("All files", "*.*")))
        if filepath:
            self.private_key_path.set(filepath)
            self.private_key_display_label.config(text=os.path.basename(filepath))
            self.log_message(f"Private key selected: {os.path.basename(filepath)}")
            if self.submissions_tree.focus() and self.is_logged_in: self.decrypt_button.config(state=tk.NORMAL)
        else:
            self.decrypt_button.config(state=tk.DISABLED)

    def refresh_submissions_list_threaded(self):
        if not self.is_logged_in:
            self.log_message("Login required to refresh submissions.", "INFO")
            # Optionally show a message box or just do nothing if login is prompted elsewhere
            # messagebox.showwarning("Login Required", "Please login to refresh submissions.", parent=self.root)
            return
        threading.Thread(target=self.refresh_submissions_list_worker, daemon=True).start()

    def refresh_submissions_list_worker(self):
        self.log_message("Refreshing submissions list...")
        # No API key needed, session cookies are used by self.session
        current_proxies = self.get_proxies()
        ssl_verify = self.verify_ssl_var.get()
        try:
            target_url = urllib.parse.urljoin(self.server_url.get().rstrip('/') + '/', "journalist/submissions")
            self.log_message(f"Refreshing from {target_url} (SSL Verify: {ssl_verify})", "DEBUG")
            response = self.session.get(target_url, proxies=current_proxies, verify=ssl_verify, timeout=90)
            response.raise_for_status()
            data = response.json()
            self.log_message(f"Submissions raw data: {str(data)[:200]}", "DEBUG_DATA")  # Log part of raw data

            self.root.after(0, lambda d=data: self._update_submissions_tree(d))

        except requests.exceptions.HTTPError as http_e:
            err_msg = f"HTTP error refreshing submissions: {http_e.response.status_code}."
            if http_e.response.status_code == 401 or http_e.response.status_code == 403:  # Unauthorized or Forbidden
                err_msg += " Session may have expired or login is required."
                self.is_logged_in = False  # Assume logged out
                self.root.after(0, self.update_login_status_display)
                self.root.after(0, self.prompt_login_if_not_logged_in)
            try:
                server_err = http_e.response.json().get("error", "No details."); err_msg += f" Server: {server_err}"
            except:
                err_msg += f" Server raw: {http_e.response.text[:100]}"
            self.log_message(err_msg, "ERROR")
            self.root.after(0, lambda em=err_msg: messagebox.showerror("Network Error", em, parent=self.root))
        except requests.exceptions.RequestException as req_e:
            self.log_message(f"Network error refreshing: {req_e}", "ERROR")
            self.root.after(0, lambda er=req_e: messagebox.showerror("Network Error", f"Could not refresh: {er}",
                                                                     parent=self.root))
        except json.JSONDecodeError:
            self.log_message("Invalid JSON response (refreshing submissions).", "ERROR")
            self.root.after(0, lambda: messagebox.showerror("Server Error", "Invalid JSON response from server.",
                                                            parent=self.root))
        except Exception as ex:
            self.log_message(f"Unexpected error refreshing: {ex}", "ERROR");
            traceback.print_exc()
            self.root.after(0, lambda e=ex: messagebox.showerror("Error", f"Unexpected error: {e}", parent=self.root))

    def _update_submissions_tree(self, data):
        """Helper to update treeview from main thread."""
        for item in self.submissions_tree.get_children(): self.submissions_tree.delete(item)
        if data and "submissions" in data and isinstance(data["submissions"], list):
            s_list = data["submissions"]
            if s_list:
                for item_info in s_list:
                    s_id = item_info.get("id", "UnknownID");
                    k_hint = item_info.get("key_hint", "N/A")
                    self.submissions_tree.insert("", tk.END, values=(s_id, k_hint))
                self.log_message(f"Found {len(s_list)} submissions.")
            else:
                self.log_message("No submissions found in list.")
        else:
            self.log_message("No 'submissions' list or unexpected format from server.", "WARNING")

    def decrypt_selected_submission_threaded(self):
        if not self.is_logged_in:
            messagebox.showwarning("Login Required", "Please login to decrypt submissions.", parent=self.root);
            return
        if not self.selected_submission_id.get():
            messagebox.showwarning("No Selection", "Please select a submission.", parent=self.root);
            return
        if not self.private_key_path.get():
            messagebox.showwarning("No Key", "Please select an RSA private key.", parent=self.root);
            return
        # (Rest of the method is the same as your provided file)
        sub_id = self.selected_submission_id.get();
        priv_key_file = self.private_key_path.get()
        self.log_message(f"Preparing decryption of {sub_id} using {os.path.basename(priv_key_file)}", "DEBUG")
        private_key_pem = None
        try:
            with open(priv_key_file, 'r') as f:
                private_key_pem = f.read()
        except Exception as e:
            self.log_message(f"Error reading private key file: {e}", "ERROR")
            messagebox.showerror("Key Error", f"Could not read private key: {e}", parent=self.root);
            return

        priv_key_password_input = simpledialog.askstring("Private Key Password",
                                                         f"Enter password for {os.path.basename(priv_key_file)}\n(Leave blank if none):",
                                                         parent=self.root, show='*')
        if priv_key_password_input is None: self.log_message("Decryption cancelled.", "INFO"); return
        actual_priv_key_password = priv_key_password_input if priv_key_password_input else None
        threading.Thread(target=self.decrypt_selected_submission_worker,
                         args=(sub_id, private_key_pem, actual_priv_key_password), daemon=True).start()

    def decrypt_selected_submission_worker(self, sub_id, private_key_pem_content, priv_key_password):
        # (Same logic as your file, but uses self.session and self.verify_ssl_var)
        self.log_message(f"Worker decrypting {sub_id}.", "DEBUG")
        base_server_url = self.server_url.get().rstrip('/')
        current_proxies = self.get_proxies()
        ssl_verify = self.verify_ssl_var.get()
        try:
            package_info_url = urllib.parse.urljoin(base_server_url + '/', f"journalist/submission/{sub_id}/package")
            self.log_message(f"Fetching package info from: {package_info_url} (SSL Verify: {ssl_verify})", "DEBUG")
            resp_pkg = self.session.get(package_info_url, proxies=current_proxies, verify=ssl_verify, timeout=60)
            resp_pkg.raise_for_status()
            package_data = resp_pkg.json()
            self.log_message(f"Package info: {str(package_data)[:200]}...", "DEBUG")

            urls_to_fetch = {"AES key": package_data['encrypted_aes_key_url'],
                             "filename": package_data['encrypted_filename_url'],
                             "file": package_data['encrypted_file_url']}
            downloaded_data = {}
            for name, url_val in urls_to_fetch.items():
                self.log_message(f"Downloading encrypted {name} from {url_val}", "DEBUG")
                resp_comp = self.session.get(url_val, proxies=current_proxies, verify=ssl_verify,
                                             timeout=180 if name == "file" else 30)
                resp_comp.raise_for_status()
                downloaded_data[name] = resp_comp.content
                self.log_message(f"Encrypted {name} downloaded ({len(downloaded_data[name])} bytes).", "DEBUG")

            # (Decryption logic remains the same using crypto_utils)
            encrypted_aes_key_data = downloaded_data["AES key"]
            encrypted_original_filename_data = downloaded_data["filename"]
            encrypted_file_data = downloaded_data["file"]

            self.log_message("Decrypting AES key (locally)...", "DEBUG")
            decrypted_aes_key = crypto_utils.decrypt_rsa(encrypted_aes_key_data, private_key_pem_content,
                                                         priv_key_password)
            if not decrypted_aes_key:
                self.log_message("Failed to decrypt AES key. Wrong password/key.", "ERROR");
                self.root.after(0, lambda: messagebox.showerror("Decryption Error", "AES Key decryption failed.",
                                                                parent=self.root));
                return
            self.log_message("AES key decrypted.", "DEBUG")

            self.log_message("Decrypting original filename (locally)...", "DEBUG")
            dec_orig_fname_bytes = crypto_utils.decrypt_aes_gcm(encrypted_original_filename_data, decrypted_aes_key)
            original_filename = f"{sub_id}_decrypted.dat"
            if dec_orig_fname_bytes:
                original_filename = dec_orig_fname_bytes.decode('utf-8', errors='replace'); self.log_message(
                    f"Filename: {original_filename}", "DEBUG")
            else:
                self.log_message("Failed to decrypt filename. Using generic.", "WARNING")

            self.log_message(f"Decrypting content for '{original_filename}' (locally)...", "DEBUG")
            decrypted_file_data = crypto_utils.decrypt_aes_gcm(encrypted_file_data, decrypted_aes_key)
            if not decrypted_file_data:
                self.log_message("Failed to decrypt file data.", "ERROR");
                self.root.after(0, lambda: messagebox.showerror("Decryption Error", "File data decryption failed.",
                                                                parent=self.root));
                return
            self.log_message("File content decrypted.", "SUCCESS")

            def ask_save_main():  # (Save dialog logic unchanged)
                path = filedialog.asksaveasfilename(parent=self.root, initialdir=DEFAULT_DOWNLOAD_DIR,
                                                    initialfile=original_filename, title="Save Decrypted File",
                                                    defaultextension=".*")
                if path:
                    try:
                        with open(path, 'wb') as f:
                            f.write(decrypted_file_data)
                        self.log_message(f"File saved: {path}", "SUCCESS");
                        messagebox.showinfo("Success", f"Saved:\n{path}", parent=self.root)
                    except IOError as ioe:
                        self.log_message(f"IOError save: {ioe}", "ERROR"); messagebox.showerror("Save Error",
                                                                                                f"Could not save: {ioe}",
                                                                                                parent=self.root)
                else:
                    self.log_message("Save cancelled.")

            self.root.after(0, ask_save_main)

        except requests.exceptions.HTTPError as http_e:
            err_msg = f"HTTP error during decryption download: {http_e.response.status_code} for {http_e.request.url if http_e.request else 'N/A'}."
            if http_e.response.status_code == 401 or http_e.response.status_code == 403:
                err_msg += " Session may have expired. Please re-login."
                self.is_logged_in = False
                self.root.after(0, self.update_login_status_display)
                self.root.after(0, self.prompt_login_if_not_logged_in)
            try:
                server_err = http_e.response.json().get("error", "No details."); err_msg += f" Server: {server_err}"
            except:
                err_msg += f" Server raw: {http_e.response.text[:100]}"
            self.log_message(err_msg, "ERROR");
            self.root.after(0, lambda em=err_msg: messagebox.showerror("Network Error", em, parent=self.root))
        except requests.exceptions.RequestException as req_e:
            self.log_message(f"Network error during decryption: {req_e}", "ERROR");
            self.root.after(0, lambda er=req_e: messagebox.showerror("Network Error", f"Could not download: {er}",
                                                                     parent=self.root))
        except Exception as e_gen:
            self.log_message(f"Unexpected error in decryption: {e_gen}", "ERROR");
            traceback.print_exc()
            self.root.after(0,
                            lambda be=e_gen: messagebox.showerror("Error", f"Unexpected error: {be}", parent=self.root))

    def generate_keys_threaded(self):  # (Unchanged)
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
            if password is None: self.log_message("Key generation cancelled."); return
            if not password:
                if messagebox.askyesno("Password Empty",
                                       "Password is empty. Generate keys WITHOUT password protection?",
                                       parent=self.root):
                    password = None
                else:
                    self.log_message("Key generation aborted (empty password)."); return
        threading.Thread(target=self.generate_keys_worker, args=(num_keys, key_prefix, password), daemon=True).start()

    def generate_keys_worker(self, num_keys, key_prefix, password):  # (Unchanged)
        self.log_message(f"Generating {num_keys} key pair(s) with prefix '{key_prefix}'...")
        all_pub_keys_text_content = ""
        for i in range(1, num_keys + 1):
            self.log_message(f"Generating pair {i}...", "DEBUG")
            try:
                pub_path_for_server, priv_path = rsa_gen_module.generate_rsa_key_pair(key_id_prefix=key_prefix,
                                                                                      key_index=i, password=password)
                with open(pub_path_for_server, 'r') as f_pub:
                    pub_key_content = f_pub.read()
                all_pub_keys_text_content += f"--- Public Key for {os.path.basename(pub_path_for_server)} ---\n{pub_key_content}\n\n"
                self.log_message(
                    f"Generated: {os.path.basename(priv_path)} and {os.path.basename(pub_path_for_server)}")
            except Exception as e:
                self.log_message(f"Error generating key pair {i}: {e}", "ERROR")
                self.root.after(0, lambda err_val=e, idx_val=i: messagebox.showerror("Key Generation Error",
                                                                                     f"Failed for pair {idx_val}: {err_val}",
                                                                                     parent=self.root));
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
    # (Icon loading logic unchanged from your provided file)
    icon_found = False;
    icon_filename_png = 'autumn_leaf.png';
    icon_filename_ico = 'autumn_leaf.ico'
    icon_paths_to_try = [os.path.join(current_dir, icon_filename_png), os.path.join(current_dir, icon_filename_ico)]
    for icon_path in icon_paths_to_try:
        if os.path.exists(icon_path):
            try:
                if icon_path.endswith('.png'):
                    img = tk.PhotoImage(file=icon_path); root.tk.call('wm', 'iconphoto', root._w,
                                                                      img); icon_found = True; break
                elif icon_path.endswith('.ico') and os.name == 'nt':
                    root.iconbitmap(default=icon_path); app.log_message(f"Set icon from ICO: {icon_path}",
                                                                        "INFO"); icon_found = True; break
            except Exception as e_icon:
                app.log_message(f"Error loading icon {icon_path}: {e_icon}", "WARNING")
    if not icon_found: app.log_message(
        f"Custom icon ('{icon_filename_png}' or '{icon_filename_ico}') not found or failed to load.", "WARNING")
    root.mainloop()