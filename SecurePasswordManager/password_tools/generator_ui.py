import tkinter as tk
from tkinter import ttk, messagebox

from password_tools.generator import generate_password


class PasswordGeneratorUI:
    def __init__(self, parent, on_password_generated=None):
        self.parent = parent
        self.on_password_generated = on_password_generated

        self.window = tk.Toplevel(parent)
        self.window.title("Password Generator")
        self.window.geometry("450x430")
        self.window.resizable(False, False)
        self.window.configure(bg="#0F172A")
        self.window.transient(parent)
        self.window.grab_set()
        self.window.lift()
        self.window.focus_force()

        self.create_widgets()

    
    def create_custom_checkbox(self, parent, text, variable, row):
        checkbox = ttk.Frame(parent)
        checkbox.grid(
            row=row,
            column=0,
            columnspan=2,
            sticky="w",
            pady=5,
        )

        indicator = tk.Label(
            checkbox,
            text="",
            bg="#0F172A",
            fg="#22C55E",
            font=("Segoe UI Emoji", 12),
            cursor="hand2",
        )
        indicator.pack(side="left", padx=(0, 8))

        label = tk.Label(
            checkbox,
            text=text,
            bg="#0F172A",
            fg="#F8FAFC",
            font=("Segoe UI", 10),
            cursor="hand2",
        )
        label.pack(side="left")

        def refresh():
            indicator.config(
                text="✅" if variable.get() else "⬜"
            )

        def toggle(event=None):
            variable.set(not variable.get())
            refresh()

        indicator.bind("<Button-1>", toggle)
        label.bind("<Button-1>", toggle)
        checkbox.bind("<Button-1>", toggle)

        refresh()
        return checkbox


    def create_widgets(self):
        frame = ttk.Frame(self.window, padding=20)
        frame.pack(fill="both", expand=True)

        ttk.Label(
            frame,
            text="Password Length:",
        ).grid(row=0, column=0, sticky="w", pady=5)

        self.length_var = tk.IntVar(value=16)

        self.length_spinbox = ttk.Spinbox(
            frame,
            from_=4,
            to=128,
            textvariable=self.length_var,
            width=10,
        )
        self.length_spinbox.grid(
            row=0,
            column=1,
            sticky="w",
            padx=10,
            pady=5,
        )

        self.uppercase_var = tk.BooleanVar(value=True)
        self.lowercase_var = tk.BooleanVar(value=True)
        self.numbers_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)

        
        self.create_custom_checkbox(
            frame, "Uppercase letters", self.uppercase_var, 1
        )

        self.create_custom_checkbox(
            frame, "Lowercase letters", self.lowercase_var, 2
        )

        self.create_custom_checkbox(
            frame, "Numbers", self.numbers_var, 3
        )

        self.create_custom_checkbox(
            frame, "Symbols", self.symbols_var, 4
        )


        ttk.Label(
            frame,
            text="Generated Password:",
        ).grid(
            row=5,
            column=0,
            columnspan=2,
            sticky="w",
            pady=(20, 5),
        )

        self.password_var = tk.StringVar()

        self.password_entry = ttk.Entry(
            frame,
            textvariable=self.password_var,
            state="readonly",
            width=45,
        )
        self.password_entry.grid(
            row=6,
            column=0,
            columnspan=2,
            sticky="ew",
        )

        ttk.Button(
            frame,
            text="Generate Password",
            command=self.generate,
        ).grid(
            row=7,
            column=0,
            columnspan=2,
            pady=15,
        )

        ttk.Button(
            frame,
            text="Use Password",
            command=self.use_password,
        ).grid(
            row=9,
            column=0,
            columnspan=2,
            pady=5,
        )

        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)

    def generate(self):
        try:
            length = int(self.length_var.get())

            password = generate_password(
                length=length,
                use_uppercase=self.uppercase_var.get(),
                use_lowercase=self.lowercase_var.get(),
                use_numbers=self.numbers_var.get(),
                use_symbols=self.symbols_var.get(),
            )

            self.password_var.set(password)

        except (ValueError, tk.TclError) as error:
            messagebox.showerror(
                "Password Generation Failed",
                str(error),
                parent=self.window,
            )

    def copy_password(self):
        password = self.password_var.get()

        if not password:
            messagebox.showwarning(
                "No Password",
                "Generate a password first.",
                parent=self.window,
            )
            return

        self.window.clipboard_clear()
        self.window.clipboard_append(password)
        self.window.update()

        messagebox.showinfo(
            "Password Copied",
            "The generated password has been copied to the clipboard.",
            parent=self.window,
        )

    def use_password(self):
        password = self.password_var.get()

        if not password:
            messagebox.showwarning(
                "No Password",
                "Generate a password first.",
                parent=self.window,
            )
            return

        if self.on_password_generated:
            self.on_password_generated(password)

        self.window.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()

    PasswordGeneratorUI(root)

    root.mainloop()