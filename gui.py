import tkinter as tk
from tkinter import ttk
import threading
import requests

# API endpoint
API_URL = "https://secure-asf-password-manager.onrender.com"

class SecureASFApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure ASF Password Manager")
        self.geometry("500x450")
        self.resizable(False, False)
        self.username = None
        self.master_password = None

        container = ttk.Frame(self)
        container.pack(fill='both', expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        # Initialize frames
        self.frames = {}
        frame_classes = [MainMenu, RegisterFrame, LoginFrame, RecoverFrame,
                         UserMenuFrame, WalletFrame, CredentialsFrame,
                         DocumentsFrame, AccountSettingsFrame]
        for F in frame_classes:
            frame = F(parent=container, controller=self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky='nsew')

        self.show_frame(MainMenu)

    def show_frame(self, frame_class):
        frame = self.frames[frame_class]
        frame.tkraise()

class MainMenu(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        ttk.Label(self, text="Secure ASF Client", font=('Helvetica', 18)).pack(pady=30)
        ttk.Button(self, text="Login", command=lambda: controller.show_frame(LoginFrame))\
.pack(fill='x', padx=100, pady=5)
        ttk.Button(self, text="Register", command=lambda: controller.show_frame(RegisterFrame))\
.pack(fill='x', padx=100, pady=5)
        ttk.Button(self, text="Recover Account", command=lambda: controller.show_frame(RecoverFrame))\
.pack(fill='x', padx=100, pady=5)
        ttk.Button(self, text="Exit", command=controller.destroy)\
.pack(fill='x', padx=100, pady=20)

class RegisterFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        ttk.Label(self, text="Register New Account", font=('Helvetica', 16)).pack(pady=10)
        self.vars = {name: tk.StringVar() for name in [
            'username', 'pw', 'pw_conf', 'pin', 'pin_conf'
        ]}
        labels = [
            ('Username:', 'username', False),
            ('Master Password:', 'pw', True),
            ('Confirm Password:', 'pw_conf', True),
            ('Recovery PIN (6 digits):', 'pin', True),
            ('Confirm PIN:', 'pin_conf', True)
        ]
        for text, key, is_pwd in labels:
            ttk.Label(self, text=text).pack(anchor='w', padx=50)
            ttk.Entry(self, textvariable=self.vars[key], show='*' if is_pwd else None)\
.pack(pady=2, padx=50, fill='x')
        btn = ttk.Button(self, text="Submit", command=self.register)
        btn.pack(pady=10)
        ttk.Button(self, text="Back", command=lambda: controller.show_frame(MainMenu)).pack()

    def register(self):
        user = self.vars['username'].get().strip()
        pw = self.vars['pw'].get()
        pw_conf = self.vars['pw_conf'].get()
        pin = self.vars['pin'].get()
        pin_conf = self.vars['pin_conf'].get()
        if not all([user, pw, pw_conf, pin, pin_conf]):
            self.show_status("All fields are required.")
            return
        if pw != pw_conf:
            self.show_status("Passwords do not match.")
            return
        if pin != pin_conf or not pin.isdigit() or len(pin) != 6:
            self.show_status("PINs must match and be 6 digits.")
            return
        payload = {
            "username": user,
            "master_password": pw,
            "confirm_master_password": pw_conf,
            "recovery_pin": pin,
            "confirm_recovery_pin": pin_conf
        }
        self.api_post('/register', payload, next_frame=MainMenu)

    def api_post(self, path, payload, next_frame=None):
        def task():
            try:
                resp = requests.post(API_URL+path, json=payload)
                resp.raise_for_status()
                msg = resp.json().get('message','Success')
                self.show_status(msg)
                if next_frame:
                    self.controller.show_frame(next_frame)
            except Exception as e:
                self.show_status(str(e))
        threading.Thread(target=task).start()

    def show_status(self, msg):
        if hasattr(self, '_status_label'): self._status_label.destroy()
        self._status_label = ttk.Label(self, text=msg)
        self._status_label.pack()

class LoginFrame(RegisterFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        ttk.Label(self, text="Login", font=('Helvetica', 16)).pack(pady=10)
        # reuse vars but rename keys
        self.vars = {'username': tk.StringVar(), 'pw': tk.StringVar()}
        labels = [('Username:', 'username', False), ('Master Password:', 'pw', True)]
        for text, key, is_pwd in labels:
            ttk.Label(self, text=text).pack(anchor='w', padx=50)
            ttk.Entry(self, textvariable=self.vars[key], show='*' if is_pwd else None)\
.pack(pady=2, padx=50, fill='x')
        btn = ttk.Button(self, text="Login", command=self.login)
        btn.pack(pady=10)
        ttk.Button(self, text="Back", command=lambda: controller.show_frame(MainMenu)).pack()

    def login(self):
        user = self.vars['username'].get().strip()
        pw = self.vars['pw'].get()
        if not all([user, pw]):
            self.show_status("Username and password are required.")
            return
        payload = {"username": user, "master_password": pw}
        self.api_post('/login', payload, next_frame=UserMenuFrame)

class RecoverFrame(LoginFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        ttk.Label(self, text="Recover Account", font=('Helvetica', 16)).pack(pady=10)
        self.vars = {'username': tk.StringVar(), 'pin': tk.StringVar(),
                     'pw': tk.StringVar(), 'pw_conf': tk.StringVar()}
        labels = [
            ('Username:', 'username', False),
            ('Recovery PIN:', 'pin', True),
            ('New Password:', 'pw', True),
            ('Confirm Password:', 'pw_conf', True)
        ]
        for text, key, is_pwd in labels:
            ttk.Label(self, text=text).pack(anchor='w', padx=50)
            ttk.Entry(self, textvariable=self.vars[key], show='*' if is_pwd else None)\
.pack(pady=2, padx=50, fill='x')
        btn = ttk.Button(self, text="Recover", command=self.recover)
        btn.pack(pady=10)
        ttk.Button(self, text="Back", command=lambda: controller.show_frame(MainMenu)).pack()

    def recover(self):
        user = self.vars['username'].get().strip()
        pin = self.vars['pin'].get()
        pw = self.vars['pw'].get()
        pw_conf = self.vars['pw_conf'].get()
        if not all([user, pin, pw, pw_conf]):
            self.show_status("All fields are required.")
            return
        if pw != pw_conf:
            self.show_status("Passwords do not match.")
            return
        payload = {"username": user, "recovery_pin": pin, "new_master_password": pw}
        self.api_post('/reset_master_password', payload, next_frame=MainMenu)

class UserMenuFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        ttk.Label(self, text=lambda: f"Logged in as {controller.username}", font=('Helvetica', 14))\
.pack(pady=10)
        items = [
            ("Wallet Vault", WalletFrame),
            ("Site Credentials Vault", CredentialsFrame),
            ("Secure Documents Vault", DocumentsFrame),
            ("Account Settings", AccountSettingsFrame)
        ]
        for text, frame in items:
            ttk.Button(self, text=text, command=lambda f=frame: controller.show_frame(f))\
.pack(fill='x', padx=100, pady=5)
        ttk.Button(self, text="Logout", command=lambda: controller.show_frame(MainMenu))\
.pack(pady=20)

class CategoryFrame(ttk.Frame):
    def __init__(self, parent, controller, title, actions):
        super().__init__(parent)
        self.controller = controller
        self.title = title
        ttk.Label(self, text=title, font=('Helvetica', 16)).pack(pady=10)
        self.actions = actions  # dict of button_text: method
        for text, method in actions.items():
            ttk.Button(self, text=text, command=getattr(self, method))\
.pack(fill='x', padx=100, pady=2)
        ttk.Button(self, text="Back", command=lambda: controller.show_frame(UserMenuFrame))\
.pack(pady=10)
        self.form_frame = ttk.Frame(self)

    def clear_form(self):
        for widget in self.form_frame.winfo_children(): widget.destroy()
        self.form_frame.pack_forget()

    def show_menu(self):
        self.clear_form()

    def build_form(self, title, fields, api_path, include_master=True):
        self.clear_form()
        ttk.Label(self.form_frame, text=title, font=('Helvetica', 16)).pack(pady=10)
        self.vars = {}
        for label_text, key, is_pwd in fields:
            ttk.Label(self.form_frame, text=label_text).pack(anchor='w', padx=50)
            var = tk.StringVar()
            entry = ttk.Entry(self.form_frame, textvariable=var, show='*' if is_pwd else None)
            entry.pack(pady=2, padx=50, fill='x')
            self.vars[key] = var
        submit_btn = ttk.Button(self.form_frame, text="Submit", command=lambda: self.submit(api_path, include_master))
        submit_btn.pack(pady=10)
        self.status_label = ttk.Label(self.form_frame, text="")
        self.status_label.pack()
        ttk.Button(self.form_frame, text="Back", command=self.show_menu).pack(pady=5)
        self.form_frame.pack()

    def submit(self, api_path, include_master):
        payload = {k: v.get() for k, v in self.vars.items()}
        payload['username'] = self.controller.username
        if include_master:
            payload['master_password'] = self.controller.master_password
        def task():
            try:
                resp = requests.post(API_URL+api_path, json=payload)
                resp.raise_for_status()
                data = resp.json()
                self.status_label.config(text=str(data))
            except Exception as e:
                self.status_label.config(text=str(e))
        threading.Thread(target=task).start()

    def list_items(self, api_path, include_master=False):
        self.clear_form()
        text = tk.Text(self.form_frame, height=10)
        text.pack(pady=10)
        def task():
            try:
                payload = {'username': self.controller.username}
                if include_master:
                    payload['master_password'] = self.controller.master_password
                resp = requests.post(API_URL+api_path, json=payload)
                resp.raise_for_status()
                data = resp.json()
                text.insert('1.0', '\n'.join(map(str, data)))
            except Exception as e:
                text.insert('1.0', str(e))
        threading.Thread(target=task).start()
        ttk.Button(self.form_frame, text="Back", command=self.show_menu).pack(pady=5)
        self.form_frame.pack()

class WalletFrame(CategoryFrame):
    def __init__(self, parent, controller):
        actions = {
            "Add Wallet": "add_wallet",
            "View Wallet": "view_wallet",
            "List All Wallets": "list_wallets",
            "Delete Wallet": "delete_wallet"
        }
        super().__init__(parent, controller, "Wallet Vault", actions)

    def add_wallet(self):
        fields = [
            ('Wallet Name:', 'wallet_name', False),
            ('Wallet Username:', 'w_username', False),
            ('Wallet Password:', 'w_password', True),
            ('Recovery Phrase:', 'recovery_phrase', False),
            ('Recovery PIN:', 'pin', True)
        ]
        self.build_form("Add Wallet", fields, '/add_wallet')

    def view_wallet(self):
        fields = [('Wallet Name:', 'wallet_name', False), ('Recovery PIN:', 'pin', True)]
        self.build_form("View Wallet", fields, '/get_wallet')

    def list_wallets(self):
        self.list_items('/get_all_wallets')

    def delete_wallet(self):
        fields = [('Wallet Name:', 'wallet_name', False)]
        self.build_form("Delete Wallet", fields, '/delete_wallet', include_master=False)

class CredentialsFrame(WalletFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.title = "Site Credentials Vault"

    def add_wallet(self): self.build_form = self.add_cred  # not used
    def add_cred(self): pass  # overridden

    def add_wallet(self):
        fields = [('Site Name:', 'site', False), ('Username:', 's_username', False), ('Password:', 's_password', True)]
        self.build_form("Add Credentials", fields, '/add_credentials')

    def view_wallet(self):
        fields = [('Site Name:', 'site', False)]
        self.build_form("View Credentials", fields, '/get_credentials')

    def list_wallets(self):
        self.list_items('/get_all_sites')

    def delete_wallet(self):
        fields = [('Site Name:', 'site', False)]
        self.build_form("Delete Credentials", fields, '/delete_credentials', include_master=False)

class DocumentsFrame(CategoryFrame):
    def __init__(self, parent, controller):
        actions = {
            "Add Document": "add_doc",
            "View Document": "view_doc",
            "List All Documents": "list_docs",
            "Update Document": "update_doc",
            "Delete Document": "delete_doc"
        }
        super().__init__(parent, controller, "Secure Documents Vault", actions)

    def add_doc(self):
        fields = [('Document Name:', 'doc_name', False), ('Contents:', 'doc_contents', False)]
        self.build_form("Add Document", fields, '/add_secure_doc')

    def view_doc(self):
        fields = [('Document Name:', 'doc_name', False)]
        self.build_form("View Document", fields, '/get_secure_doc')

    def list_docs(self):
        self.list_items('/get_all_docs')

    def update_doc(self):
        fields = [('Document Name:', 'doc_name', False), ('New Contents:', 'new_contents', False)]
        self.build_form("Update Document", fields, '/update_secure_doc')

    def delete_doc(self):
        fields = [('Document Name:', 'doc_name', False)]
        self.build_form("Delete Document", fields, '/delete_secure_doc', include_master=False)

class AccountSettingsFrame(CategoryFrame):
    def __init__(self, parent, controller):
        actions = {
            "Change Master Password": "change_password",
            "Enable 2FA": "enable_2fa",
            "Disable 2FA": "disable_2fa",
            "Delete All Data": "delete_all_data"
        }
        super().__init__(parent, controller, "Account Settings", actions)

    def change_password(self):
        fields = [('Current Password:', 'old_master_password', True),
                  ('New Password:', 'new_master_password', True),
                  ('Confirm Password:', 'confirm_new_password', True)]
        self.build_form("Change Master Password", fields, '/reset_master_password')

    def enable_2fa(self):
        self.list_items('/enable_2fa')

    def disable_2fa(self):
        fields = [('Recovery PIN:', 'pin', True)]
        self.build_form("Disable 2FA", fields, '/disable_2fa', include_master=False)

    def delete_all_data(self):
        fields = [('Recovery PIN:', 'pin', True)]
        self.build_form("Delete All Data", fields, '/delete_all_data', include_master=False)

if __name__ == '__main__':
    app = SecureASFApp()
    app.mainloop()
