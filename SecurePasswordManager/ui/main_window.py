import tkinter as tk
import requests
import ctypes
import logging

logger = logging.getLogger(__name__)

from tkinter import ttk, messagebox, filedialog
from credentials.credential import Credential
from vault.vault import Vault
from vault.database import load_vault
from password_tools.generator_ui import PasswordGeneratorUI
from password_tools.strength import evaluate_password_strength
from password_tools.hibp import check_password_breach


class MainWindow:
    def __init__(self):
        self.root = tk.Tk()

        self.root.title("Secure Password Manager")
        self.root.geometry("1200x800")
        self.root.minsize(900, 600)
        self.root.state("zoomed")
        self.root.protocol("WM_DELETE_WINDOW", self.shutdown)

        self.setup_styles()

        self.is_unlocked = False
        self.vault = Vault()
        self.displayed_credentials = []
        self.credential_detail_dialogs = {}

        
        self.clipboard_clear_job = None
        self.clipboard_password = None
        self.auto_lock_job = None
        self.is_closing = False

        # Track automatic locking and the pending unlock prompt.
        self.unlock_prompt_pending = False
        self.unlock_dialog = None

        # Track mouse and keyboard activity inside SPM.
        self.root.bind_all(
            "<ButtonPress>",
            self.track_user_activity,
            add="+",
        )

        self.root.bind_all(
            "<KeyPress>",
            self.track_user_activity,
            add="+",
        )

        self.root.bind_all(
            "<FocusIn>",
            self.handle_app_focus,
            add="+",
        )

        self.create_main_layout()

        self.update_ui_state()
        self.check_auto_lock()

        if load_vault() is None:
            # First-time user: show Create Vault window.
            self.root.withdraw()
            self.root.after(100, self.show_create_vault_dialog)

        else:
            # Existing user: show Enter Master Password window.
            self.root.withdraw()
            self.root.after(100, self.show_unlock_dialog)

    
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        # Main application colors
        self.bg_color = "#0D1117"
        self.card_color = "#171B22"
        self.input_color = "#0D1117"
        self.accent_color = "#625CF6"
        self.accent_hover = "#5148E5"
        self.text_color = "#E6EDF3"
        self.secondary_text = "#8B949E"
        self.border_color = "#303640"

        self.root.configure(bg=self.bg_color)

        # Frames
        style.configure(
            "TFrame",
            background=self.bg_color,
        )

        style.configure(
            "Card.TFrame",
            background=self.card_color,
        )

        # Labels
        style.configure(
            "TLabel",
            background=self.bg_color,
            foreground=self.text_color,
            font=("Segoe UI", 10),
        )

        style.configure(
            "Title.TLabel",
            background=self.bg_color,
            foreground=self.text_color,
            font=("Segoe UI", 20, "bold"),
        )

        style.configure(
            "Status.TLabel",
            background=self.bg_color,
            foreground=self.secondary_text,
            font=("Segoe UI", 10, "bold"),
        )

        # Entry fields: padding is configured here
        style.configure(
            "TEntry",
            fieldbackground=self.input_color,
            foreground=self.text_color,
            padding=8,
        )

        # Buttons
        style.configure(
            "TButton",
            background=self.accent_color,
            foreground="#FFFFFF",
            font=("Segoe UI", 10, "bold"),
            padding=(14, 8),
            borderwidth=0,
        )

        style.map(
            "TButton",
            background=[
                ("active", self.accent_hover),
                ("pressed", self.accent_hover),
            ],
            foreground=[
                ("disabled", "#64748B"),
            ],
        )

        # Sidebar button styling
        style.configure(
            "Sidebar.TButton",
            background=self.card_color,
            foreground=self.text_color,
            font=("Segoe UI", 9),
            padding=(10, 8),
            relief="solid",
            borderwidth=1,
        )

        style.map(
            "Sidebar.TButton",
            background=[
                ("active", "#292F3A"),
                ("pressed", "#292F3A"),
            ],
            foreground=[
                ("active", "#FFFFFF"),
            ],
        )

        # Lock button styling
        style.configure(
            "Danger.TButton",
            background="#EF4444",
            foreground="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
            padding=(10, 8),
            relief="flat",
            borderwidth=0,
        )

        style.map(
            "Danger.TButton",
            background=[
                ("active", "#DC2626"),
                ("pressed", "#B91C1C"),
            ],
        )

        # Credential table styling
        style.configure(
            "Treeview",
            background="#171B22",
            fieldbackground="#171B22",
            foreground="#E6EDF3",
            rowheight=36,
            borderwidth=1,
            relief="flat",
            font=("Segoe UI", 10),
        )

        style.map(
            "Treeview",
            background=[
                ("selected", "#625CF6"),
            ],
            foreground=[
                ("selected", "#FFFFFF"),
            ],
        )

        # Credential table headings
        style.configure(
            "Treeview.Heading",
            background="#20252E",
            foreground="#A1AAB8",
            font=("Segoe UI", 10, "bold"),
            padding=(8, 10),
            relief="flat",
            borderwidth=0,
        )

        style.map(
            "Treeview.Heading",
            background=[
                ("active", "#292F3A"),
            ],
            foreground=[
                ("active", "#FFFFFF"),
            ],
        )

        # Label frames
        style.configure(
            "TLabelframe",
            background=self.bg_color,
            foreground=self.text_color,
            bordercolor=self.border_color,
        )

        style.configure(
            "TLabelframe.Label",
            background=self.bg_color,
            foreground=self.text_color,
            font=("Segoe UI", 11, "bold"),
        )

        # Password generator checkbox styling
        style.configure(
            "TCheckbutton",
            background=self.bg_color,
            foreground=self.text_color,
            font=("Segoe UI", 10),
            focuscolor=self.bg_color,
        )

        style.map(
            "TCheckbutton",
            background=[
                ("active", self.bg_color),
            ],
            foreground=[
                ("disabled", self.secondary_text),
            ],
        )



    def check_auto_lock(self):
        if self.is_closing:
            return

        if self.is_unlocked and self.vault.is_auto_lock_expired():
            self.lock_vault_ui(show_prompt=False)

        self.auto_lock_job = self.root.after(
            1000,
            self.check_auto_lock,
        )


    def create_main_layout(self):
        # Main application container
        main_frame = tk.Frame(
            self.root,
            bg=self.bg_color,
        )
        main_frame.pack(fill="both", expand=True)

        # LEFT SIDEBAR
        sidebar = tk.Frame(
            main_frame,
            bg=self.card_color,
            width=220,
            highlightbackground=self.border_color,
            highlightthickness=1,
        )

        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # Application branding
        tk.Label(
            sidebar,
            text="Secure Password Manager",
            bg=self.card_color,
            fg=self.text_color,
            font=("Segoe UI", 13, "bold"),
            wraplength=185,
            justify="left",
        ).pack(anchor="w", padx=15, pady=(25, 30))


        # Sidebar section heading
        tk.Label(
            sidebar,
            text="TOOLS",
            bg=self.card_color,
            fg=self.secondary_text,
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", padx=15, pady=(0, 12))

        # Export Vault
        self.export_button = ttk.Button(
            sidebar,
            text="Export Vault",
            style="Sidebar.TButton",
            command=self.export_vault_ui,
        )
        self.export_button.pack(fill="x", padx=12, pady=4)

        # Import Vault
        self.import_button = ttk.Button(
            sidebar,
            text="Import Vault",
            style="Sidebar.TButton",
            command=self.import_vault_ui,
        )
        self.import_button.pack(fill="x", padx=12, pady=4)

        # Import CSV
        self.import_csv_button = ttk.Button(
            sidebar,
            text="Import CSV",
            style="Sidebar.TButton",
            command=self.import_csv_ui,
        )
        self.import_csv_button.pack(fill="x", padx=12, pady=4)

        # Import KeePass XML
        self.import_keepass_button = ttk.Button(
            sidebar,
            text="Import KeePass XML",
            style="Sidebar.TButton",
            command=self.import_keepass_ui,
        )
        self.import_keepass_button.pack(fill="x", padx=12, pady=4)

        # Bottom Lock Vault button
        self.lock_button = ttk.Button(
            sidebar,
            text="🔒  Lock Vault",
            style="Danger.TButton",
            command=self.lock_vault_ui,
        )
        self.lock_button.pack(
            side="bottom",
            fill="x",
            padx=12,
            pady=12,
        )

        # MAIN CONTENT AREA
        content = tk.Frame(
            main_frame,
            bg=self.bg_color,
        )
        content.pack(side="left", fill="both", expand=True)

        # TOP BAR
        top_bar = tk.Frame(
            content,
            bg=self.bg_color,
            highlightthickness=0,
        )
        top_bar.pack(fill="x", padx=16, pady=12)

        # Search field container
        search_frame = tk.Frame(
            top_bar,
            bg=self.input_color,
            highlightbackground=self.border_color,
            highlightthickness=1,
        )
        search_frame.pack(
            side="left",
            fill="both",
            expand=True,
            padx=0,
            pady=0,
        )

        # Search field with placeholder
        self.search_var = tk.StringVar()

        self.search_entry = ttk.Entry(
            search_frame,
            textvariable=self.search_var,
        )
        self.search_entry.pack(
            side="left",
            fill="both",
            expand=True,
            ipady=5,
            padx=0,
        )

        placeholder = "Search credentials..."

        self.search_entry.insert(0, placeholder)
        self.search_entry.config(foreground="#8B949E")

        def clear_placeholder(event):
            if self.search_entry.get() == placeholder:
                self.search_entry.delete(0, tk.END)
                self.search_entry.config(foreground=self.text_color)

        def restore_placeholder(event):
            if not self.search_entry.get().strip():
                self.search_entry.insert(0, placeholder)
                self.search_entry.config(foreground="#8B949E")
                self.search_credentials()

        self.search_entry.bind("<FocusIn>", clear_placeholder)
        self.search_entry.bind("<FocusOut>", restore_placeholder)

        self.search_entry.bind(
            "<KeyRelease>",
            self.search_credentials,
        )

        # Add Credential button
        self.add_button = ttk.Button(
            top_bar,
            text="✚  New Credential",
            command=self.show_add_credential_dialog,
        )
        self.add_button.pack(
            side="right",
            padx=10,
            pady=0,
        )

        # THREE-PANEL CONTENT
        panels = tk.Frame(
            content,
            bg=self.bg_color,
        )
        panels.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=(0, 20),
        )

        # CREDENTIAL LIST PANEL
        list_panel = tk.Frame(
            panels,
            bg=self.card_color,
        )
        list_panel.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(0, 8),
        )

        tk.Label(
            list_panel,
            text="Your Credentials",
            bg=self.card_color,
            fg=self.text_color,
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", padx=15, pady=15)

        self.credential_list = ttk.Treeview(
            list_panel,
            columns=("title", "username"),
            show="headings",
            selectmode="browse",
        )

        self.credential_list.heading("title", text="Title")
        self.credential_list.heading("username", text="Username")

        self.credential_list.column("title", width=150)
        self.credential_list.column("username", width=180)

        self.credential_list.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10,
        )

        self.credential_list.bind(
            "<<TreeviewSelect>>",
            self.show_selected_credential,
        )

        self.empty_message = ttk.Label(
            list_panel,
            text="No credentials to display.",
        )

        # DETAILS PANEL
        self.details_panel = tk.Frame(
            panels,
            bg=self.card_color,
            width=360,
            highlightbackground=self.border_color,
            highlightthickness=1,
        )

        self.details_panel.pack(
            side="right",
            fill="y",
            padx=(8, 0),
        )

        self.details_panel.pack_propagate(False)

        self.details_content = tk.Frame(
            self.details_panel,
            bg=self.card_color,
        )

        self.details_content.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=20,
        )

        self.details_placeholder = tk.Label(
            self.details_content,
            text="Select a credential\nfrom the list to view details.",
            bg=self.card_color,
            fg=self.secondary_text,
            font=("Segoe UI", 10),
            justify="left",
        )

        self.details_placeholder.pack(
            anchor="w",
            pady=15,
        )

    
    def create_header(self):
        header = ttk.Frame(self.root, padding=(22, 20))
        header.pack(fill="x")

        title = ttk.Label(
            header,
            text="Secure Password Manager",
            style="Title.TLabel",
        )
        title.pack(side="left")

        self.status_label = ttk.Label(
            header,
            text="🔒 Locked",
            style="Status.TLabel",
        )
        self.status_label.pack(side="right")


    
    def create_search_area(self):
        frame = ttk.Frame(self.root, padding=(22, 12))
        frame.pack(fill="x")

        label = ttk.Label(
            frame,
            text="Search credentials",
            foreground=self.secondary_text,
        )
        label.pack(anchor="w", pady=(0, 8))

        self.search_entry = ttk.Entry(frame)
        self.search_entry.pack(fill="x", ipady=4)

        self.search_entry.bind(
            "<KeyRelease>",
            self.search_credentials
        )


    
    def create_actions(self):
        frame = ttk.Frame(self.root, padding=(22, 10))
        frame.pack(fill="x")

        self.add_button = ttk.Button(
            frame,
            text="＋  Add Credential",
            command=self.show_add_credential_dialog,
        )
        self.add_button.pack(side="left", padx=(0, 10))

        self.lock_button = ttk.Button(
            frame,
            text="🔒  Lock Vault",
            command=self.lock_vault_ui,
        )
        self.lock_button.pack(side="left", padx=(0, 10))

        self.unlock_button = ttk.Button(
            frame,
            text="🔓  Unlock Vault",
            command=self.show_unlock_dialog,
        )
        self.unlock_button.pack(side="left", padx=(0, 10))

        
        self.export_button = ttk.Button(
            frame,
            text="Export Vault",
            command=self.export_vault_ui,
        )
        self.export_button.pack(side="left", padx=(0, 10))


        self.import_button = ttk.Button(
            frame,
            text="Import Vault",
            command=self.import_vault_ui,
        )
        self.import_button.pack(side="left", padx=(0, 10))

        self.import_csv_button = ttk.Button(
            frame,
            text="Import CSV",
            command=self.import_csv_ui,
        )
        self.import_csv_button.pack(side="left")

        # KeePass XML Import button
        keepass_frame = ttk.Frame(self.root, padding=(22, 0))
        keepass_frame.pack(fill="x")

        self.import_keepass_button = ttk.Button(
            keepass_frame,
            text="Import KeePass XML",
            command=self.import_keepass_ui,
        )
        self.import_keepass_button.pack(side="left")


    def create_credential_area(self):
        frame = ttk.LabelFrame(
            self.root,
            text="  Your Credentials  ",
            padding=15,
        )
        frame.pack(
            fill="both",
            expand=True,
            padx=22,
            pady=(8, 20),
        )

        self.credential_list = tk.Listbox(
            frame,
            bg=self.card_color,
            fg=self.text_color,
            selectbackground=self.accent_color,
            selectforeground="#FFFFFF",
            font=("Segoe UI", 11),
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=self.border_color,
            activestyle="none",
        )

        self.credential_list.bind(
            "<<ListboxSelect>>",
            self.show_selected_credential,
        )
        self.credential_list.pack(fill="both", expand=True)

        self.delete_button = tk.Button(
            frame,
            text="Delete Credential",
            command=self.delete_selected_credential,
            bg="#7F1D1D",
            fg="#FFFFFF",
            activebackground="#991B1B",
            activeforeground="#FFFFFF",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            borderwidth=0,
            padx=14,
            pady=8,
            cursor="hand2",
        )
        self.delete_button.pack(anchor="e", pady=(12, 0))

        self.empty_message = ttk.Label(
            frame,
            text="No credentials to display.",
            foreground=self.secondary_text,
        )


    def update_ui_state(self):
        if self.is_unlocked:

            self.add_button.config(state="normal")
            self.lock_button.config(state="normal")
            self.search_entry.config(state="normal")
            self.export_button.config(state="normal")
            self.import_button.config(state="normal")
            self.import_csv_button.config(state="normal")
            self.import_keepass_button.config(state="normal")

        else:

            self.add_button.config(state="disabled")
            self.lock_button.config(state="disabled")
            self.search_entry.config(state="disabled")
            self.export_button.config(state="disabled")
            self.import_button.config(state="disabled")
            self.import_csv_button.config(state="disabled")
            self.import_keepass_button.config(state="disabled")


    def show_create_vault_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Initialize Vault")
        dialog.geometry("1200x800")
        dialog.minsize(900, 600)
        dialog.resizable(True, True)
        dialog.state("zoomed")
        dialog.configure(bg="#0F1218")
        dialog.lift()
        dialog.focus_force()
        # Exit the application if the user closes
        # the initial Create Vault window.
        dialog.protocol(
            "WM_DELETE_WINDOW",
            self.root.destroy
        )

        # Main card
        card = tk.Frame(
            dialog,
            bg="#181B23",
            highlightbackground="#454A55",
            highlightthickness=1,
        )
        card.place(
            relx=0.5,
            rely=0.5,
            anchor="center",
            width=480,
            height=740,
        )

        # Main heading
        tk.Label(
            card,
            text="Secure Password Manager",
            bg="#181B23",
            fg="#F8FAFC",
            font=("Segoe UI", 19, "bold"),
        ).pack(pady=(55, 8))

        # Subheading
        tk.Label(
            card,
            text="Create Vault",
            bg="#181B23",
            fg="#A5B4FC",
            font=("Segoe UI", 12, "bold"),
        ).pack(pady=(0, 35))

        # Password visibility eye icon
        def create_eye_toggle(parent, entry):

            visible = False

            eye_canvas = tk.Canvas(
                parent,
                width=34,
                height=30,
                bg="#0F1218",
                highlightthickness=0,
                cursor="hand2",
            )

            def draw_eye():
                eye_canvas.delete("all")

                # Draw eye outline
                eye_canvas.create_line(
                    4, 15,
                    8, 10,
                    12, 7,
                    16, 6,
                    20, 7,
                    24, 10,
                    28, 15,
                    24, 20,
                    20, 23,
                    16, 24,
                    12, 23,
                    8, 20,
                    4, 15,
                    smooth=True,
                    splinesteps=20,
                    fill="#A5B4FC",
                    width=2,
                )

                if visible:
                    # Open eye with pupil
                    eye_canvas.create_oval(
                        12, 11, 20, 19,
                        fill="#A5B4FC",
                        outline="#A5B4FC",
                    )
                else:
                    # Closed visibility: eye with diagonal slash
                    eye_canvas.create_line(
                        5, 26, 27, 4,
                        fill="#A5B4FC",
                        width=2,
                    )

            def toggle_visibility(event=None):
                nonlocal visible

                visible = not visible

                entry.config(
                    show="" if visible else "*"
                )

                draw_eye()

            eye_canvas.bind(
                "<Button-1>",
                toggle_visibility,
            )

            draw_eye()

            return eye_canvas

        # Master password label
        tk.Label(
            card,
            text="Master Password",
            bg="#181B23",
            fg="#F8FAFC",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w", padx=36, pady=(0, 7))

        # Password input container
        password_frame = tk.Frame(
            card,
            bg="#0F1218",
            highlightbackground="#454A55",
            highlightthickness=1,
        )
        password_frame.pack(fill="x", padx=36)

        password_entry = tk.Entry(
            password_frame,
            show="*",
            bg="#0F1218",
            fg="#F8FAFC",
            insertbackground="white",
            relief="flat",
            font=("Segoe UI", 12),
        )
        password_entry.pack(
            side="left",
            fill="x",
            expand=True,
            padx=10,
            pady=10,
        )

        # Password visibility control
        create_eye_toggle(
            password_frame,
            password_entry,
        ).pack(side="right", padx=10)

        # Password strength bar
        strength_canvas = tk.Canvas(
            card,
            height=7,
            bg="#252A35",
            highlightthickness=0,
        )
        strength_canvas.pack(fill="x", padx=36, pady=(10, 0))

        strength_text = tk.Label(
            card,
            text="Strength: Enter password",
            bg="#181B23",
            fg="#94A3B8",
            font=("Segoe UI", 9),
        )
        strength_text.pack(anchor="w", padx=36, pady=(8, 25))

        # Password requirements checklist
        requirements_frame = tk.Frame(
            card,
            bg="#181B23",
        )
        requirements_frame.pack(
            anchor="w",
            padx=36,
            pady=(0, 15),
        )

        requirement_labels = {}

        requirements = [
            ("length", "At least 12 characters"),
            ("uppercase", "Uppercase letter (A-Z)"),
            ("lowercase", "Lowercase letter (a-z)"),
            ("number", "Numbers (0-9)"),
            ("symbol", "Symbols (!@#$...)"),
        ]

        for key, label_text in requirements:
            row = tk.Frame(
                requirements_frame,
                bg="#181B23",
            )
            row.pack(anchor="w", pady=2)

            label = tk.Label(
                row,
                text=f"☐   {label_text}",
                bg="#181B23",
                fg="#94A3B8",
                font=("Segoe UI", 9),
            )
            label.pack(anchor="w")

            requirement_labels[key] = label

        def update_strength(event=None):
            password = password_entry.get()

            # Check password requirements
            checks = {
                "length": len(password) >= 12,
                "uppercase": any(c.isupper() for c in password),
                "lowercase": any(c.islower() for c in password),
                "number": any(c.isdigit() for c in password),
                "symbol": any(not c.isalnum() for c in password),
            }

            for key, label_text in requirements:
                passed = checks[key]

                requirement_labels[key].config(
                    text=f"{'☑' if passed else '☐'}   {label_text}",
                    fg="#22C55E" if passed else "#94A3B8",
                )

            strength_canvas.delete("all")

            if not password:
                strength_text.config(
                    text="Strength: Enter password",
                    fg="#94A3B8",
                )
                return

            # Advisory strength estimate
            score = 0
            score += len(password) >= 8
            score += len(password) >= 12
            score += any(c.islower() for c in password)
            score += any(c.isupper() for c in password)
            score += any(c.isdigit() for c in password)
            score += any(not c.isalnum() for c in password)

            if score <= 2:
                level = "Weak"
                color = "#EF4444"
                progress = 1 / 3
            elif score <= 4:
                level = "Medium"
                color = "#F59E0B"
                progress = 2 / 3
            else:
                level = "Strong"
                color = "#22C55E"
                progress = 1

            strength_canvas.update_idletasks()

            width = strength_canvas.winfo_width()

            strength_canvas.create_rectangle(
                0, 0,
                width * progress, 7,
                fill=color,
                outline=color,
            )

            strength_text.config(
                text=f"Strength: {level}",
                fg=color,
            )

        password_entry.bind(
            "<KeyRelease>",
            update_strength,
        )

        # Confirm password
        tk.Label(
            card,
            text="Confirm Master Password",
            bg="#181B23",
            fg="#F8FAFC",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w", padx=36, pady=(0, 7))

        # Confirm password input container
        confirm_frame = tk.Frame(
            card,
            bg="#0F1218",
            highlightbackground="#454A55",
            highlightthickness=1,
        )
        confirm_frame.pack(
            fill="x",
            padx=36,
        )

        confirm_entry = tk.Entry(
            confirm_frame,
            show="*",
            bg="#0F1218",
            fg="#F8FAFC",
            insertbackground="white",
            relief="flat",
            font=("Segoe UI", 12),
        )
        confirm_entry.pack(
            side="left",
            fill="x",
            expand=True,
            padx=10,
            pady=10,
        )

        # Confirm password visibility control
        create_eye_toggle(
            confirm_frame,
            confirm_entry,
        ).pack(side="right", padx=10)

        # Master password reminder
        warning = tk.Frame(
            card,
            bg="#24202A",
            highlightbackground="#7F3038",
            highlightthickness=1,
        )
        warning.pack(fill="x", padx=36, pady=(20, 22))

        tk.Label(
            warning,
            text="⚠ Remember Your Master Password",
            bg="#24202A",
            fg="#F87171",
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", padx=12, pady=(10, 4))

        tk.Label(
            warning,
            text="Don't forget your master password. It cannot\n"
                "be recovered if lost.",
            bg="#24202A",
            fg="#FCA5A5",
            font=("Segoe UI", 9),
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 10))

        # Create Vault button
        def create_vault():
            self.create_vault_ui(
                dialog,
                password_entry.get(),
                confirm_entry.get(),
            )

        create_button = tk.Button(
            card,
            text="Create Vault",
            command=create_vault,
            bg="#6366F1",
            fg="#FFFFFF",
            activebackground="#4F46E5",
            activeforeground="#FFFFFF",
            relief="flat",
            bd=0,
            font=("Segoe UI", 11, "bold"),
            cursor="hand2",
        )
        create_button.pack(
            fill="x",
            padx=36,
            ipady=10,
        )

        password_entry.focus_set()



    def create_vault_ui(self, dialog, master_password, confirm_password):
        if not master_password:
            messagebox.showwarning(
                "Password Required",
                "Please enter a master password.",
                parent=dialog,
            )
            return

        if not confirm_password:
            messagebox.showwarning(
                "Confirmation Required",
                "Please confirm the master password.",
                parent=dialog,
            )
            return

        if master_password != confirm_password:
            messagebox.showerror(
                "Password Mismatch",
                "The master passwords do not match.",
                parent=dialog,
            )
            return

        # Enforce minimum master-password length.
        if len(master_password) < 12:
            messagebox.showwarning(
                "Weak Master Password",
                "Your master password must contain at least 12 characters.",
                parent=dialog,
            )
            return

        # Evaluate master-password strength.
        strength_result = evaluate_password_strength(master_password)

        if strength_result["score"] < 3:
            messagebox.showwarning(
                "Weak Master Password",
                "Please choose a stronger master password.\n"
                "Use a long, unique passphrase with unpredictable words.",
                parent=dialog,
            )
            return

        try:
            self.vault.create(master_password)

        except Exception:
            messagebox.showerror(
                "Vault Creation Failed",
                "Unable to create the vault.",
                parent=dialog,
            )
            return

        # Activate the newly created vault.
        self.is_unlocked = True
        self.vault.update_activity()
        self.displayed_credentials = []

        self.refresh_credentials()

        self.empty_message.config(
            text="No credentials to display."
        )

        self.update_ui_state()

        # Open the main application behind the Create Vault window.
        self.root.deiconify()
        self.root.state("zoomed")
        self.root.update_idletasks()

        # Keep the Create Vault window visible during restoration.
        dialog.attributes("-topmost", True)
        dialog.lift()

        def start_transition():
            if not dialog.winfo_exists():
                return

            # Allow the main application to finish rendering.
            self.root.update_idletasks()

            # Smoothly fade out the Create Vault window.
            def fade_out(step=0):
                if not dialog.winfo_exists():
                    return

                if step >= 10:
                    dialog.destroy()
                    self.root.lift()
                    self.root.focus_force()
                    return

                alpha = 1.0 - ((step + 1) / 10)

                dialog.attributes("-alpha", alpha)

                dialog.after(
                    30,
                    lambda: fade_out(step + 1),
                )

            fade_out()

        # Allow the fullscreen main window to appear first.
        dialog.after(200, start_transition)


        

    def show_unlock_dialog(self, on_shown=None):
        if self.unlock_dialog is not None:
            try:
                if self.unlock_dialog.winfo_exists():
                    return
            except tk.TclError:
                pass
        dialog = tk.Toplevel(self.root)
        self.unlock_dialog = dialog
        dialog.withdraw()

        dialog.title("Unlock Your Vault")
        dialog.configure(bg="#0D1016")
        dialog.geometry("1200x800")
        dialog.minsize(900, 600)
        dialog.resizable(True, True)

        dialog.protocol(
            "WM_DELETE_WINDOW",
            self.shutdown,
        )

        # Center card
        card = tk.Frame(
            dialog,
            bg="#181B23",
            highlightbackground="#454A55",
            highlightthickness=1,
        )

        # Heading
        tk.Label(
            card,
            text="Unlock Your Vault",
            bg="#181B23",
            fg="#F8FAFC",
            font=("Segoe UI", 17, "bold"),
        ).pack(pady=(55, 8))

        # Subtitle
        tk.Label(
            card,
            text="Enter your master password to unlock your vault.",
            bg="#181B23",
            fg="#94A3B8",
            font=("Segoe UI", 9),
        ).pack(pady=(0, 28))

        # Password label
        tk.Label(
            card,
            text="Master Password",
            bg="#181B23",
            fg="#F8FAFC",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w", padx=36, pady=(0, 7))

        # Password input container
        password_frame = tk.Frame(
            card,
            bg="#0D1016",
            highlightbackground="#454A55",
            highlightthickness=1,
        )
        password_frame.pack(
            fill="x",
            padx=36,
        )

        password_entry = tk.Entry(
            password_frame,
            show="*",
            bg="#0D1016",
            fg="#F8FAFC",
            insertbackground="#FFFFFF",
            relief="flat",
            font=("Segoe UI", 12),
            bd=0,
        )
        password_entry.pack(
            side="left",
            fill="x",
            expand=True,
            padx=10,
            pady=11,
        )

        # Password visibility toggle
        visible = False

        eye = tk.Canvas(
            password_frame,
            width=28,
            height=28,
            bg="#0D1016",
            highlightthickness=0,
            cursor="hand2",
        )
        eye.pack(side="right", padx=10)

        def draw_eye():
            eye.delete("all")

            eye.create_line(
                3, 14, 8, 8, 14, 5,
                20, 8, 25, 14,
                20, 20, 14, 23,
                8, 20, 3, 14,
                smooth=True,
                fill="#A5B4FC",
                width=1.5,
            )

            eye.create_oval(
                10, 10, 18, 18,
                outline="#A5B4FC",
                width=1.5,
            )

            eye.create_oval(
                13, 13, 15, 15,
                fill="#A5B4FC",
                outline="#A5B4FC",
            )

            if not visible:
                eye.create_line(
                    4, 24, 24, 4,
                    fill="#A5B4FC",
                    width=1.5,
                )

        def toggle_visibility(event=None):
            nonlocal visible

            visible = not visible

            password_entry.config(
                show="" if visible else "*"
            )

            draw_eye()

        eye.bind("<Button-1>", toggle_visibility)
        draw_eye()

        # Unlock button
        unlock_button = tk.Button(
            card,
            text="Unlock Vault",
            command=lambda: self.unlock_ui(
                dialog,
                password_entry.get(),
            ),
            bg="#6366F1",
            fg="#FFFFFF",
            activebackground="#4F46E5",
            activeforeground="#FFFFFF",
            relief="flat",
            bd=0,
            font=("Segoe UI", 10, "bold"),
            cursor="hand2",
        )
        unlock_button.pack(
            fill="x",
            padx=36,
            pady=(20, 0),
            ipady=9,
        )

        # Enter key also unlocks the vault
        password_entry.bind(
            "<Return>",
            lambda event: self.unlock_ui(
                dialog,
                password_entry.get(),
            ),
        )


        def show_dialog():
            if not dialog.winfo_exists():
                return

            # Start the dialog invisible.
            dialog.attributes("-alpha", 0.0)

            # Display and maximize the dialog.
            dialog.deiconify()
            dialog.update_idletasks()
            dialog.state("zoomed")

            def center_card():
                if not dialog.winfo_exists():
                    return

                # Wait until Windows finishes maximizing.
                if dialog.state() != "zoomed":
                    dialog.after(50, center_card)
                    return

                # Center card in the final window dimensions.
                card.place(
                    relx=0.5,
                    rely=0.5,
                    anchor="center",
                    width=480,
                    height=310,
                )

                dialog.update_idletasks()
                dialog.lift()
                dialog.focus_force()
                password_entry.focus_set()

                # Fade in the unlock window.
                def fade_in(step=0):
                    if not dialog.winfo_exists():
                        return

                    if step >= 10:
                        dialog.attributes("-alpha", 1.0)

                        if on_shown:
                            dialog.after(200, on_shown)

                        return

                    alpha = (step + 1) / 10
                    dialog.attributes("-alpha", alpha)

                    dialog.after(
                        30,
                        lambda: fade_in(step + 1),
                    )

                fade_in()

            dialog.after(100, center_card)


        dialog.after(0, show_dialog)




    def unlock_ui(self, dialog, master_password):
        if not master_password:
            messagebox.showwarning(
                "Password Required",
                "Please enter the master password.",
                parent=dialog,
            )
            return

        try:
            self.vault.unlock(master_password)

        except Exception:
            messagebox.showerror(
                "Unlock Failed",
                "Incorrect master password or corrupted vault.",
                parent=dialog,
            )
            return

        self.refresh_credentials()

        self.is_unlocked = True
        self.vault.update_activity()
        self.empty_message.config(text="No credentials to display.")
        self.update_ui_state()

        # Keep the password dialog above the main application.
        dialog.attributes("-topmost", True)
        dialog.lift()

        # Restore the main application behind the dialog.
        self.root.deiconify()
        self.root.state("zoomed")
        self.root.update_idletasks()

        def start_transition():
            if not dialog.winfo_exists():
                return

            # Allow the main application to finish rendering.
            self.root.update_idletasks()

            # Fade out only after the main window is restored.
            def fade_out(step=0):
                if not dialog.winfo_exists():
                    return

                if step >= 10:
                    dialog.destroy()

                    self.unlock_dialog = None
                    self.unlock_prompt_pending = False

                    self.root.lift()
                    self.root.focus_force()
                    return

                alpha = 1.0 - ((step + 1) / 10)

                dialog.attributes("-alpha", alpha)

                dialog.after(
                    30,
                    lambda: fade_out(step + 1),
                )

            fade_out()

        # Give Windows time to display the main window first.
        dialog.after(200, start_transition)




    def show_password_generator(self, password_entry):
        def use_generated_password(password):
            password_entry.delete(0, tk.END)
            password_entry.insert(0, password)

        PasswordGeneratorUI(
            self.root,
            on_password_generated=use_generated_password,
        )

    def show_add_credential_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Credential")
        dialog.geometry("500x540")
        dialog.configure(bg=self.bg_color)

        dialog.resizable(False, False)

        dialog.transient(self.root)

        dialog.grab_set()

        ttk.Label(dialog, text="Title:").pack(anchor="w", padx=20, pady=(20, 5))
        title_entry = ttk.Entry(dialog)
        title_entry.pack(fill="x", padx=20)

        ttk.Label(dialog, text="Username:").pack(anchor="w", padx=20, pady=(10, 5))
        username_entry = ttk.Entry(dialog)
        username_entry.pack(fill="x", padx=20)

        ttk.Label(
            dialog,
            text="Password:"
        ).pack(anchor="w", padx=20, pady=(10, 5))

        password_frame = ttk.Frame(dialog)
        password_frame.pack(fill="x", padx=20)

        password_var = tk.StringVar()

        password_entry = ttk.Entry(
            password_frame,
            textvariable=password_var,
            show="*",
        )
        password_entry.pack(
            side="left",
            fill="x",
            expand=True,
        )

        
        strength_label = ttk.Label(
            dialog,
            text="Password strength: Not entered"
        )
        strength_label.pack(
            anchor="w",
            padx=20,
            pady=(5, 0)
        )

        def update_password_strength(*args):
            password = password_var.get()

            if not password:
                strength_label.config(
                    text="Password strength: Not entered"
                )
                return

            try:
                result = evaluate_password_strength(password)
                score = result["score"]

                strength_names = [
                    "Very Weak",
                    "Weak",
                    "Fair",
                    "Strong",
                    "Very Strong"
                ]

                feedback = (
                    f"Password strength: "
                    f"{strength_names[score]} ({score}/4)"
                )

                strength_label.config(text=feedback)

            except (ValueError, TypeError):
                strength_label.config(
                    text="Password strength: Unable to evaluate"
                )

        password_var.trace_add(
            "write",
            update_password_strength
        )


        ttk.Button(
            password_frame,
            text="Generate",
            command=lambda: self.show_password_generator(
                password_entry
            ),
        ).pack(
            side="left",
            padx=(10, 0),
        )

        
        def check_password_breach_ui():
            password = password_entry.get()

            if not password:
                messagebox.showwarning(
                    "Password Required",
                    "Enter or generate a password first.",
                    parent=dialog,
                )
                return

            try:
                breach_count = check_password_breach(
                    password,
                    timeout=5,
                )

                if breach_count > 0:
                    messagebox.showwarning(
                        "Password Found in Breaches",
                        f"This password appears {breach_count:,} "
                        "times in the breach database. Choose a "
                        "different password.",
                        parent=dialog,
                    )
                else:
                    messagebox.showinfo(
                        "No Match Found",
                        "No match was found in the breach database. "
                        "This does not guarantee that the password "
                        "has never been exposed.",
                        parent=dialog,
                    )

            except requests.RequestException:
                messagebox.showwarning(
                    "Check Unavailable",
                    "Could not contact the breach-check service. "
                    "Check your internet connection and try again.",
                    parent=dialog,
                )

        ttk.Button(
            password_frame,
            text="Check Breach",
            command=check_password_breach_ui,
        ).pack(
            side="left",
            padx=(10, 0),
        )


        ttk.Label(dialog, text="URL:").pack(anchor="w", padx=20, pady=(10, 5))
        url_entry = ttk.Entry(dialog)
        url_entry.pack(fill="x", padx=20)

        ttk.Label(dialog, text="Notes:").pack(anchor="w", padx=20, pady=(10, 5))
        notes_entry = ttk.Entry(dialog)
        notes_entry.pack(fill="x", padx=20)

        ttk.Button(
            dialog,
            text="Save",
            command=lambda: self.save_credential(
                dialog,
                title_entry,
                username_entry,
                password_entry,
                url_entry,
                notes_entry,
            ),
        ).pack(pady=20)

    
    def copy_password_to_clipboard(self, password):
        """Copy a password without adding it to Windows clipboard history."""
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        user32.OpenClipboard.argtypes = [ctypes.c_void_p]
        user32.OpenClipboard.restype = ctypes.c_bool
        user32.EmptyClipboard.restype = ctypes.c_bool
        user32.CloseClipboard.restype = ctypes.c_bool
        user32.RegisterClipboardFormatW.argtypes = [ctypes.c_wchar_p]
        user32.RegisterClipboardFormatW.restype = ctypes.c_uint
        user32.SetClipboardData.argtypes = [
            ctypes.c_uint,
            ctypes.c_void_p,
        ]
        user32.SetClipboardData.restype = ctypes.c_void_p

        kernel32.GlobalAlloc.argtypes = [
            ctypes.c_uint,
            ctypes.c_size_t,
        ]
        kernel32.GlobalAlloc.restype = ctypes.c_void_p
        kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalLock.restype = ctypes.c_void_p
        kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
        kernel32.GlobalFree.restype = ctypes.c_void_p

        CF_UNICODETEXT = 13
        GMEM_MOVEABLE = 0x0002

        text_buffer = ctypes.create_unicode_buffer(password)
        text_size = ctypes.sizeof(text_buffer)

        text_handle = None
        flag_handle = None
        text_transferred = False
        flag_transferred = False
        clipboard_open = False

        try:
            history_format = user32.RegisterClipboardFormatW(
                "CanIncludeInClipboardHistory"
            )

            if not history_format:
                raise OSError("Could not register clipboard history format.")

            text_handle = kernel32.GlobalAlloc(
                GMEM_MOVEABLE, text_size
            )
            flag_handle = kernel32.GlobalAlloc(
                GMEM_MOVEABLE, ctypes.sizeof(ctypes.c_uint32)
            )

            if not text_handle or not flag_handle:
                raise MemoryError("Could not allocate clipboard memory.")

            text_pointer = kernel32.GlobalLock(text_handle)
            flag_pointer = kernel32.GlobalLock(flag_handle)

            if not text_pointer or not flag_pointer:
                raise OSError("Could not lock clipboard memory.")

            try:
                ctypes.memmove(
                    text_pointer,
                    ctypes.addressof(text_buffer),
                    text_size,
                )
                ctypes.cast(
                    flag_pointer,
                    ctypes.POINTER(ctypes.c_uint32),
                )[0] = 0
            finally:
                kernel32.GlobalUnlock(text_handle)
                kernel32.GlobalUnlock(flag_handle)

            if not user32.OpenClipboard(None):
                raise ctypes.WinError(ctypes.get_last_error())

            clipboard_open = True

            if not user32.EmptyClipboard():
                raise ctypes.WinError(ctypes.get_last_error())

            if not user32.SetClipboardData(
                history_format, flag_handle
            ):
                raise ctypes.WinError(ctypes.get_last_error())

            flag_transferred = True

            if not user32.SetClipboardData(
                CF_UNICODETEXT, text_handle
            ):
                raise ctypes.WinError(ctypes.get_last_error())

            text_transferred = True

        except Exception as error:
            logger.warning("Clipboard copy operation failed.")
            return

        finally:
            if clipboard_open:
                user32.CloseClipboard()

            if text_handle and not text_transferred:
                kernel32.GlobalFree(text_handle)

            if flag_handle and not flag_transferred:
                kernel32.GlobalFree(flag_handle)

        self.clipboard_password = password

        if self.clipboard_clear_job is not None:
            self.root.after_cancel(self.clipboard_clear_job)

        self.clipboard_clear_job = self.root.after(
            30_000,
            self.clear_password_clipboard,
        )


        
    def _clear_tracked_clipboard_password(self):
        """Clear the clipboard only if it still contains our password."""
        import ctypes

        if self.clipboard_password is None:
            return True

        copied_password = self.clipboard_password

        try:
            user32 = ctypes.WinDLL("user32", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            CF_UNICODETEXT = 13

            user32.OpenClipboard.argtypes = [ctypes.c_void_p]
            user32.OpenClipboard.restype = ctypes.c_bool
            user32.GetClipboardData.argtypes = [ctypes.c_uint]
            user32.GetClipboardData.restype = ctypes.c_void_p
            user32.EmptyClipboard.restype = ctypes.c_bool
            user32.CloseClipboard.restype = ctypes.c_bool

            kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
            kernel32.GlobalLock.restype = ctypes.c_void_p
            kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
            kernel32.GlobalUnlock.restype = ctypes.c_bool

            if not user32.OpenClipboard(None):
                return False

            try:
                handle = user32.GetClipboardData(CF_UNICODETEXT)

                if not handle:
                    return True

                pointer = kernel32.GlobalLock(handle)

                if not pointer:
                    return False

                try:
                    clipboard_text = ctypes.wstring_at(pointer)
                finally:
                    kernel32.GlobalUnlock(handle)

                if clipboard_text == copied_password:
                    return bool(user32.EmptyClipboard())

                return True

            finally:
                user32.CloseClipboard()

        except Exception as error:
            logger.warning("Clipboard clearing operation failed.")
            return False


    def clear_password_clipboard(self):
        """Clear our copied password and retry if the clipboard is busy."""

        self.clipboard_clear_job = None

        if self.clipboard_password is None:
            if getattr(self, "is_closing", False):
                self.root.destroy()
            return

        cleared = self._clear_tracked_clipboard_password()

        if not cleared:
            self.clipboard_clear_job = self.root.after(
                1000,
                self.clear_password_clipboard,
            )
            return

        self.clipboard_password = None

        # Finish shutdown after clipboard cleanup succeeds.
        if getattr(self, "is_closing", False):
            self.root.destroy()


    def save_credential(
        self,
        dialog,
        title_entry,
        username_entry,
        password_entry,
        url_entry,
        notes_entry,
    ):
        if not self.is_unlocked:
            messagebox.showwarning(
                "Vault Locked",
                "The vault has been automatically locked. Please unlock it again.",
                parent=dialog,
            )
            dialog.destroy()
            return

        title = title_entry.get().strip()
        username = username_entry.get().strip()
        password = password_entry.get()
        url = url_entry.get().strip()
        notes = notes_entry.get().strip()

        # Required fields
        if not title:
            messagebox.showerror(
                "Invalid Input",
                "Title is required.",
                parent=dialog,
            )
            title_entry.focus()
            return

        if not username:
            messagebox.showerror(
                "Invalid Input",
                "Username is required.",
                parent=dialog,
            )
            username_entry.focus()
            return

        if not password:
            messagebox.showerror(
                "Invalid Input",
                "Password is required.",
                parent=dialog,
            )
            password_entry.focus()
            return

        # URL validation
        if url and not (
            url.startswith("https://") or url.startswith("http://")
        ):
            messagebox.showerror(
                "Invalid URL",
                "URL must start with http:// or https://.",
                parent=dialog,
            )
            url_entry.focus()
            return

        credential = Credential(
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
        )

        # Save credential safely.
        try:
            self.vault.add_credential(credential)

        except Exception:
            messagebox.showerror(
                "Save Failed",
                "The credential could not be saved. "
                "Please try again.",
                parent=dialog,
            )
            return

        try:
            self.refresh_credentials()

        except Exception:
            messagebox.showerror(
                "Refresh Failed",
                "The credential was saved, but the credential list "
                "could not be refreshed. Please refresh the list.",
                parent=dialog,
            )
            dialog.destroy()
            return

        dialog.destroy()


    def show_selected_credential(self, event=None):
        if not self.is_unlocked:
            return

        selected = self.credential_list.selection()

        if not selected:
            return

        selected_id = selected[0]

        if selected_id == "__empty__":
            return

        index = int(selected_id)

        if index >= len(self.displayed_credentials):
            return

        credential = self.displayed_credentials[index]

        self.display_credential_details(credential)



    def display_credential_details(self, credential):
        # Clear previous credential details
        for widget in self.details_content.winfo_children():
            widget.destroy()

        # Main colors
        bg = self.card_color
        field_bg = self.input_color
        text = self.text_color
        muted = self.secondary_text
        border = self.border_color
        accent = self.accent_color

        # Credential title
        tk.Label(
            self.details_content,
            text=credential.title,
            bg=bg,
            fg=text,
            font=("Segoe UI", 14, "bold"),
            anchor="w",
        ).pack(fill="x", pady=(5, 25))

        # Reusable section heading
        def create_section_label(label):
            tk.Label(
                self.details_content,
                text=label.upper(),
                bg=bg,
                fg=muted,
                font=("Segoe UI", 9, "bold"),
                anchor="w",
            ).pack(fill="x", pady=(10, 5))

        # Reusable dark entry field
        def create_field(value, show=None):
            field_frame = tk.Frame(
                self.details_content,
                bg=field_bg,
                highlightbackground=border,
                highlightthickness=1,
            )
            field_frame.pack(fill="x", pady=(0, 5))

            entry = tk.Entry(
                field_frame,
                bg=field_bg,
                fg=text,
                readonlybackground=field_bg,
                disabledbackground=field_bg,
                disabledforeground=text,
                insertbackground=text,
                relief="flat",
                bd=0,
                font=("Segoe UI", 10),
                show=show if show else "",
            )

            entry.insert(0, str(value or ""))
            entry.config(state="readonly")

            entry.pack(
                side="left",
                fill="x",
                expand=True,
                padx=10,
                ipady=8,
            )

            return field_frame, entry

        # USERNAME
        create_section_label("Username / Email")

        create_field(credential.username)

        # PASSWORD
        create_section_label("Password")

        password_frame, password_entry = create_field(
            credential.password,
            show="•",
        )

        show_password = False

        def toggle_password():
            nonlocal show_password

            show_password = not show_password

            password_entry.config(
                show="" if show_password else "•"
            )

            show_button.config(
                text="Hide" if show_password else "Show"
            )

        show_button = tk.Button(
            password_frame,
            text="Show",
            command=toggle_password,
            bg="#252B36",
            fg="#FFFFFF",
            activebackground="#343C49",
            activeforeground="#FFFFFF",
            relief="flat",
            bd=0,
            cursor="hand2",
            font=("Segoe UI", 9),
        )

        show_button.pack(
            side="right",
            padx=5,
            pady=4,
        )

        # PASSWORD ACTION
        ttk.Button(
            self.details_content,
            text="Copy Password",
            command=lambda: self.copy_password_to_clipboard(
                credential.password
            ),
        ).pack(
            anchor="w",
            pady=(5, 15),
        )

        # WEBSITE - Show only if provided
        if credential.url and credential.url.strip():
            create_section_label("Website")
            create_field(credential.url)

        # NOTES - Show only if provided
        if credential.notes and credential.notes.strip():
            create_section_label("Notes")

            notes_frame = tk.Frame(
                self.details_content,
                bg=field_bg,
                highlightbackground=border,
                highlightthickness=1,
            )

            notes_frame.pack(
                fill="x",
                expand=False,
                pady=(0, 15),
            )

            notes_text = tk.Text(
                notes_frame,
                bg=field_bg,
                fg=text,
                insertbackground=text,
                relief="flat",
                bd=0,
                wrap="word",
                font=("Segoe UI", 10),
                padx=10,
                pady=10,
                height=5,
            )

            notes_text.insert(
                "1.0",
                credential.notes,
            )

            notes_text.config(state="disabled")

            notes_text.pack(
                fill="both",
                expand=True,
            )

        # BOTTOM ACTION: EXISTING DELETE FUNCTIONALITY
        delete_button = tk.Button(
            self.details_content,
            text="Delete Credential",
            command=self.delete_selected_credential,
            bg="#EF4444",
            fg="#FFFFFF",
            activebackground="#DC2626",
            activeforeground="#FFFFFF",
            relief="flat",
            bd=0,
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
            padx=12,
            pady=8,
        )

        delete_button.pack(
            anchor="w",
            pady=(5, 0),
        )


    def refresh_credentials(self):
        # Clear existing rows
        for item in self.credential_list.get_children():
            self.credential_list.delete(item)

        credentials = self.vault.get_credentials()
        self.displayed_credentials = credentials

        self.clear_details_panel()

        if not credentials:
            self.credential_list.insert(
                "",
                "end",
                iid="__empty__",
                values=("No credentials to display", "")
            )
            return

        for index, credential in enumerate(credentials):
            self.credential_list.insert(
                "",
                "end",
                iid=str(index),
                values=(credential.title, credential.username)
            )

    def clear_details_panel(self):
        for widget in self.details_content.winfo_children():
            widget.destroy()

        self.details_placeholder = tk.Label(
            self.details_content,
            text="Select a credential to view its details",
            bg=self.card_color,
            fg=self.secondary_text,
            font=("Segoe UI", 11)
        )
        self.details_placeholder.pack(pady=30)
    


    def delete_selected_credential(self):
        selected = self.credential_list.selection()

        if not selected:
            messagebox.showwarning(
                "No Selection",
                "Please select a credential to delete."
            )
            return

        selected_id = selected[0]

        if selected_id == "__empty__":
            return

        index = int(selected_id)

        if index >= len(self.displayed_credentials):
            return

        credential = self.displayed_credentials[index]

        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete '{credential.title}'?"
        )

        if not confirm:
            return

        all_credentials = self.vault.get_credentials()
        actual_index = all_credentials.index(credential)

        self.vault.delete_credential(actual_index)

        self.refresh_credentials()

        messagebox.showinfo(
            "Deleted",
            "Credential deleted successfully."
        )



    def search_credentials(self, event=None):
        if not self.is_unlocked:
            return

        query = self.search_var.get().strip().lower()

        if query == "search credentials...":
            query = ""

        for item in self.credential_list.get_children():
            self.credential_list.delete(item)

        self.clear_details_panel()

        credentials = self.vault.get_credentials()

        self.displayed_credentials = [
            credential for credential in credentials
            if query in credential.title.lower()
            or query in credential.username.lower()
            or query in credential.url.lower()
        ]

        if not self.displayed_credentials:
            self.credential_list.insert(
                "",
                "end",
                iid="__empty__",
                values=("No matching credentials", "")
            )
            return

        for index, credential in enumerate(self.displayed_credentials):
            self.credential_list.insert(
                "",
                "end",
                iid=str(index),
                values=(credential.title, credential.username)
            )

    def close_credential_detail_dialogs(self):
        for dialog, password_entry in list(
            self.credential_detail_dialogs.items()
        ):
            try:
                if dialog.winfo_exists():
                    password_entry.config(state="normal")
                    password_entry.delete(0, tk.END)
                    dialog.destroy()

            except tk.TclError:
                pass

        self.credential_detail_dialogs.clear()



    def lock_vault_ui(self, show_prompt=True):
        if not self.is_unlocked:
            return

        # Cancel the pending clipboard timer.
        if self.clipboard_clear_job is not None:
            self.root.after_cancel(self.clipboard_clear_job)
            self.clipboard_clear_job = None

        # Safely clear our copied password.
        if self.clipboard_password is not None:
            cleared = self._clear_tracked_clipboard_password()

            if cleared:
                self.clipboard_password = None
            else:
                self.clipboard_clear_job = self.root.after(
                    1000,
                    self.clear_password_clipboard,
                )

        # Close any legacy credential detail dialogs.
        self.close_credential_detail_dialogs()

        # Lock the vault.
        self.vault.lock()

        self.is_unlocked = False
        self.displayed_credentials = []

        # Clear the Treeview.
        for item in self.credential_list.get_children():
            self.credential_list.delete(item)

        # Clear sensitive details from the right panel.
        self.clear_details_panel()

        self.empty_message.config(
            text="Vault is locked."
        )

        self.update_ui_state()

        if not show_prompt:
            # Keep the main window available in the taskbar.
            # Show the unlock prompt when the user returns.
            self.unlock_prompt_pending = True

            # If SPM is already focused, show the prompt immediately.
            if self.is_app_in_foreground():
                self.unlock_prompt_pending = False
                self.show_unlock_dialog()

            return

        # Manual lock: preserve the existing behavior.
        def close_main_window():
            self.root.withdraw()
            self.root.attributes("-alpha", 1.0)

        self.show_unlock_dialog(
            on_shown=close_main_window
        )


    
    def export_vault_ui(self):
        if not self.is_unlocked:
            messagebox.showwarning(
                "Vault Locked",
                "Please unlock the vault before exporting.",
            )
            return

        file_path = filedialog.asksaveasfilename(
            title="Export Encrypted Vault",
            defaultextension=".json",
            filetypes=[
                ("Encrypted Vault", "*.json"),
                ("All Files", "*.*"),
            ],
        )

        if not file_path:
            return

        try:
            self.vault.export_to_file(file_path)
            messagebox.showinfo(
                "Export Successful",
                "Your encrypted vault was exported successfully.",
            )
        except Exception as error:
            messagebox.showerror(
                "Export Failed",
                f"Could not export the vault:\n{error}",
            )

    
    def import_csv_ui(self):
        if not self.is_unlocked:
            messagebox.showwarning(
                "Vault Locked",
                "Please unlock the vault before importing CSV files.",
                parent=self.root,
            )
            return

        file_path = filedialog.askopenfilename(
            title="Import Credentials from CSV",
            filetypes=[
                ("CSV Files", "*.csv"),
                ("All Files", "*.*"),
            ],
        )

        if not file_path:
            return

        try:
            # Preview and validate the CSV before importing.
            from imports.csv_importer import import_csv

            records = import_csv(file_path)

            if not records:
                messagebox.showinfo(
                    "No Credentials",
                    "The selected CSV file contains no credentials to import.",
                    parent=self.root,
                )
                return

            confirmed = messagebox.askyesno(
                "Confirm CSV Import",
                f"Import {len(records)} credential(s) into your current vault?\n\n"
                "Existing credentials will be preserved.",
                parent=self.root,
            )

            if not confirmed:
                return

            imported_count = self.vault.import_csv_credentials(file_path)

            self.refresh_credentials()
            self.update_ui_state()

            messagebox.showinfo(
                "CSV Import Successful",
                f"Successfully imported {imported_count} credential(s).",
                parent=self.root,
            )

        except Exception as error:
            messagebox.showerror(
                "CSV Import Failed",
                f"Could not import the CSV file:\n{error}",
                parent=self.root,
            )


    def import_keepass_ui(self):
        if not self.is_unlocked:
            messagebox.showwarning(
                "Vault Locked",
                "Please unlock the vault before importing KeePass XML files.",
                parent=self.root,
            )
            return

        file_path = filedialog.askopenfilename(
            title="Import Credentials from KeePass XML",
            filetypes=[
                ("KeePass XML Files", "*.xml"),
                ("All Files", "*.*"),
            ],
        )

        if not file_path:
            return

        try:
            # Preview and validate the KeePass XML before importing.
            from imports.keepass_importer import import_keepass_xml

            records = import_keepass_xml(file_path)

            if not records:
                messagebox.showinfo(
                    "No Credentials",
                    "The selected KeePass XML file contains no credentials to import.",
                    parent=self.root,
                )
                return

            confirmed = messagebox.askyesno(
                "Confirm KeePass Import",
                f"Import {len(records)} credential(s) into your current vault?\n\n"
                "Existing credentials will be preserved.",
                parent=self.root,
            )

            if not confirmed:
                return

            imported_count = self.vault.import_keepass_credentials(
                file_path
            )

            self.refresh_credentials()
            self.update_ui_state()

            messagebox.showinfo(
                "KeePass Import Successful",
                f"Successfully imported {imported_count} credential(s).",
                parent=self.root,
            )

        except Exception as error:
            messagebox.showerror(
                "KeePass Import Failed",
                f"Could not import the KeePass XML file:\n{error}",
                parent=self.root,
            )


    
    def import_vault_ui(self):
        if not self.is_unlocked:
            messagebox.showwarning(
                "Vault Locked",
                "Please unlock the current vault before importing.",
            )
            return

        file_path = filedialog.askopenfilename(
            title="Import Encrypted Vault",
            filetypes=[
                ("Encrypted Vault", "*.json"),
                ("All Files", "*.*"),
            ],
        )

        if not file_path:
            return

        password_dialog = tk.Toplevel(self.root)
        password_dialog.title("Import Vault")
        password_dialog.transient(self.root)
        password_dialog.grab_set()
        password_dialog.resizable(False, False)

        ttk.Label(
            password_dialog,
            text="Enter the master password for the imported vault:",
            padding=(15, 15, 15, 5),
        ).pack()

        password_var = tk.StringVar()

        password_entry = ttk.Entry(
            password_dialog,
            textvariable=password_var,
            show="*",
            width=35,
        )
        password_entry.pack(padx=15, pady=5)
        password_entry.focus_set()

        def submit_import():
            master_password = password_var.get()

            if not master_password:
                messagebox.showwarning(
                    "Password Required",
                    "Enter the imported vault's master password.",
                    parent=password_dialog,
                )
                return

            password_dialog.destroy()

            try:
                imported_vault = Vault()
                imported_vault.import_from_file(
                    file_path,
                    master_password,
                )
            except Exception:
                messagebox.showerror(
                    "Import Failed",
                    "The vault could not be imported. Check the file "
                    "and master password.",
                    parent=self.root,
                )
                return

            confirmed = messagebox.askyesno(
                "Replace Current Vault?",
                "Import succeeded. Replacing the current vault will "
                "overwrite its saved contents. Continue?",
                icon="warning",
                parent=self.root,
            )

            if not confirmed:
                imported_vault.lock()
                return

            try:
                imported_vault.save_to_database()

            except Exception:
                imported_vault.lock()

                messagebox.showerror(
                    "Import Failed",
                    "The imported vault could not be saved. "
                    "Please check your database before trying again.",
                    parent=self.root,
                )
                return

            # Activate the imported vault after the database save succeeds.
            self.vault.lock()

            self.vault = imported_vault
            self.is_unlocked = True
            self.vault.update_activity()

            try:
                self.refresh_credentials()
                self.update_ui_state()

            except Exception:
                messagebox.showwarning(
                    "Import Saved",
                    "The imported vault was saved and activated, "
                    "but the interface could not be refreshed. "
                    "Please restart the application.",
                    parent=self.root,
                )
                return

            messagebox.showinfo(
                "Import Successful",
                "The imported vault has been saved successfully.",
                parent=self.root,
            )

        password_entry.bind(
            "<Return>",
            lambda event: submit_import(),
        )

        ttk.Button(
            password_dialog,
            text="Import",
            command=submit_import,
        ).pack(pady=(5, 15))

        password_dialog.protocol(
            "WM_DELETE_WINDOW",
            password_dialog.destroy,
        )

    def shutdown(self):
        if self.is_closing:
            return

        self.is_closing = True

        # Cancel the auto-lock timer.
        if self.auto_lock_job is not None:
            self.root.after_cancel(self.auto_lock_job)
            self.auto_lock_job = None

        # Lock the vault before closing.
        if self.is_unlocked:
            self.vault.lock()
            self.is_unlocked = False

        # Cancel the existing clipboard timer.
        if self.clipboard_clear_job is not None:
            self.root.after_cancel(self.clipboard_clear_job)
            self.clipboard_clear_job = None

        # Clear the tracked password before destroying the window.
        if self.clipboard_password is not None:
            cleared = self._clear_tracked_clipboard_password()

            if not cleared:
                self.clipboard_clear_job = self.root.after(
                    1000,
                    self.clear_password_clipboard,
                )
                return

            self.clipboard_password = None

        self.root.destroy()

    def track_user_activity(self, event=None):
        if self.is_unlocked:
            self.vault.update_activity()

    def handle_app_focus(self, event=None):
        if not self.unlock_prompt_pending or self.is_closing:
            return

        try:
            if event.widget.winfo_toplevel() is not self.root:
                return
        except tk.TclError:
            return

        self.unlock_prompt_pending = False

        # Hide the main window after the unlock dialog appears.
        def close_main_window():
            self.root.withdraw()
            self.root.attributes("-alpha", 1.0)

        self.show_unlock_dialog(
            on_shown=close_main_window
        )

    def is_app_in_foreground(self):
        try:
            foreground_window = ctypes.windll.user32.GetForegroundWindow()

            if not foreground_window:
                return False

            root_window = self.root.winfo_id()

            root_hwnd = ctypes.windll.user32.GetAncestor(
                root_window,
                2,  # GA_ROOT
            )

            foreground_root = ctypes.windll.user32.GetAncestor(
                foreground_window,
                2,
            )

            return root_hwnd == foreground_root

        except Exception:
            return False

    def run(self):
        self.root.mainloop()