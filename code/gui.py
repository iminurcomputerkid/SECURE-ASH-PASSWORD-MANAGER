import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import requests

# API endpoint
API_URL = "https://secure-asf-password-manager.onrender.com"

class SecureASFApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure ASF Password Manager")
        self.geometry("500x400")
        self.resizable(False, False)
        self.username = None
        self.master_password = None

        container = ttk.Frame(self)
        container.pack(fill='both', expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        # Initialize frames
        self.frames = {}
        for F in (MainMenu, RegisterFrame, LoginFrame, RecoverFrame,
                  UserMenuFrame, WalletFrame, CredentialsFrame,
                  DocumentsFrame, AccountSettingsFrame):
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
        self.controller = controller
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

        self.username_var = tk.StringVar()
        self.pw_var = tk.StringVar()
        self.pw_confirm_var = tk.StringVar()
        self.pin_var = tk.StringVar()
        self.pin_confirm_var = tk.StringVar()

        ttk.Label(self, text="Username:").pack(anchor='w', padx=50)
        ttk.Entry(self, textvariable=self.username_var).pack(pady=2, padx=50, fill='x')
        ttk.Label(self, text="Master Password:").pack(anchor='w', padx=50)
        ttk.Entry(self, textvariable=self.pw_var, show='*').pack(pady=2, padx=50, fill='x')
        ttk.Label(self, text="Confirm Password:").pack(anchor='w', padx=50)
        ttk.Entry(self, textvariable=self.pw_confirm_var, show='*').pack(pady=2, padx=50, fill='x')
        ttk.Label(self, text="Recovery PIN (6 digits):").pack(anchor='w', padx=50)
        ttk.Entry(self, textvariable=self.pin_var, show='*').pack(pady=2, padx=50, fill='x')
        ttk.Label(self, text="Confirm PIN:").pack(anchor='w', padx=50)
        ttk.Entry(self, textvariable=self.pin_confirm_var, show='*').pack(pady=2, padx=50, fill='x')

        self.submit_btn = ttk.Button(self, text="Submit", command=self.register)
        self.submit_btn.pack(pady=10)
        ttk.Button(self, text="Back", command=lambda: controller.show_frame(MainMenu)).pack()

    def register(self):
        self.submit_btn.config(text="Registering... please wait", state='disabled')
        def task():
            user = self.username_var.get().strip()
            pw = self.pw_var.get()
            pw_conf = self.pw_confirm_var.get()
            pin = self.pin_var.get()
            pin_conf = self.pin_confirm_var.get()
            if not (user and pw and pw_conf and pin and pin_conf):
                messagebox.showerror("Error", "All fields are required.")
            elif pw != pw_conf:
                messagebox.showerror("Error", "Passwords do not match.")
            elif pin != pin_conf or not pin.isdigit() or len(pin) != 6:
                messagebox.showerror("Error", "PINs must match and be 6 digits.")
            else:
                payload = {
                    "username": user,
                    "master_password": pw,
                    "confirm_master_password": pw_conf,
                    "recovery_pin": pin,
                    "confirm_recovery_pin": pin_conf
                }
                try:
                    resp = requests.post(f"{API_URL}/register", json=payload)
                    resp.raise_for_status()
                    messagebox.showinfo("Success", resp.json().get('message', 'Registered successfully.'))
                    self.controller.show_frame(MainMenu)
                except Exception as e:
                    messagebox.showerror("Registration Failed", str(e))
            self.submit_btn.config(text="Submit", state='normal')
        threading.Thread(target=task).start()

class LoginFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        ttk.Label(self, text="Login", font=('Helvetica', 16)).pack(pady=10)

        self.user_var = tk.StringVar()
        self.pw_var = tk.StringVar()

        ttk.Label(self, text="Username:").pack(anchor='w', padx=50)
        ttk.Entry(self, textvariable=self.user_var).pack(pady=2, padx=50, fill='x')
        ttk.Label(self, text="Master Password:").pack(anchor='w', padx=50)
        ttk.Entry(self, textvariable=self.pw_var, show='*').pack(pady=2, padx=50, fill='x')

        self.login_btn = ttk.Button(self, text="Login", command=self.login)
        self.login_btn.pack(pady=10)
        ttk.Button(self, text="Back", command=lambda: controller.show_frame(MainMenu)).pack()

    def login(self):
        self.login_btn.config(text="Logging in... please wait", state='disabled')
        def task():
            user = self.user_var.get().strip()
            pw = self.pw_var.get()
            if not (user and pw):
                messagebox.showerror("Error", "Username and password are required.")
            else:
                payload = {"username": user, "master_password": pw}
                try:
                    resp = requests.post(f"{API_URL}/login", json=payload)
                    if resp.status_code == 200 and resp.json().get('message','').lower().startswith('login successful'):
                        self.controller.username = user
                        self.controller.master_password = pw
                        messagebox.showinfo("Success", "Login successful.")
                        self.controller.show_frame(UserMenuFrame)
                    else:
                        detail = resp.json().get('detail', resp.text)
                        messagebox.showerror("Login Failed", detail)
                except Exception as e:
                    messagebox.showerror("Error", str(e))
            self.login_btn.config(text="Login", state='normal')
        threading.Thread(target=task).start()

class RecoverFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        ttk.Label(self, text="Recover Account", font=('Helvetica', 16)).pack(pady=10)

        self.user_var = tk.StringVar()
        self.pin_var = tk.StringVar()
        self.new_pw_var = tk.StringVar()
        self.new_pw_conf_var = tk.StringVar()

        ttk.Label(self, text="Username:").pack(anchor='w', padx=50)
        ttk.Entry(self, textvariable=self.user_var).pack(pady=2, padx=50, fill='x')
        ttk.Label(self, text="Recovery PIN:").pack(anchor='w', padx=50)
        ttk.Entry(self, textvariable=self.pin_var, show='*').pack(pady=2, padx=50, fill='x')
        ttk.Label(self, text="New Password:").pack(anchor='w', padx=50)
        ttk.Entry(self, textvariable=self.new_pw_var, show='*').pack(pady=2, padx=50, fill='x')
        ttk.Label(self, text="Confirm Password:").pack(anchor='w', padx=50)
        ttk.Entry(self, textvariable=self.new_pw_conf_var, show='*').pack(pady=2, padx=50, fill='x')

        self.recover_btn = ttk.Button(self, text="Recover", command=self.recover)
        self.recover_btn.pack(pady=10)
        ttk.Button(self, text="Back", command=lambda: controller.show_frame(MainMenu)).pack()

    def recover(self):
        self.recover_btn.config(text="Recovering... please wait", state='disabled')
        def task():
            user = self.user_var.get().strip()
            pin = self.pin_var.get()
            new_pw = self.new_pw_var.get()
            new_conf = self.new_pw_conf_var.get()
            if not (user and pin and new_pw and new_conf):
                messagebox.showerror("Error", "All fields are required.")
            elif new_pw != new_conf:
                messagebox.showerror("Error", "Passwords do not match.")
            else:
                payload = {"username": user, "recovery_pin": pin, "new_master_password": new_pw}
                try:
                    resp = requests.post(f"{API_URL}/reset_master_password", json=payload)
                    resp.raise_for_status()
                    messagebox.showinfo("Success", resp.json().get('message', 'Password reset successful.'))
                    self.controller.show_frame(MainMenu)
                except Exception as e:
                    messagebox.showerror("Recovery Failed", str(e))
            self.recover_btn.config(text="Recover", state='normal')
        threading.Thread(target=task).start()

class UserMenuFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        ttk.Label(self, text=lambda: f"Logged in as {controller.username}", font=('Helvetica', 14))\
            .pack(pady=10)
        ttk.Button(self, text="Wallet Vault", command=lambda: controller.show_frame(WalletFrame))\
            .pack(fill='x', padx=100, pady=5)
        ttk.Button(self, text="Site Credentials Vault", command=lambda: controller.show_frame(CredentialsFrame))\
            .pack(fill='x', padx=100, pady=5)
        ttk.Button(self, text="Secure Documents Vault", command=lambda: controller.show_frame(DocumentsFrame))\
            .pack(fill='x', padx=100, pady=5)
        ttk.Button(self, text="Account Settings", command=lambda: controller.show_frame(AccountSettingsFrame))\
            .pack(fill='x', padx=100, pady=5)
        self.logout_btn = ttk.Button(self, text="Logout", command=self.logout)
        self.logout_btn.pack(pady=20)

    def logout(self):
        self.logout_btn.config(text="Logging out... please wait", state='disabled')
        self.controller.username = None
        self.controller.master_password = None
        self.controller.show_frame(MainMenu)
        self.logout_btn.config(text="Logout", state='normal')

class WalletFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        ttk.Label(self, text="Wallet Vault", font=('Helvetica', 16)).pack(pady=10)
        ttk.Button(self, text="Add Wallet", command=self.add_wallet)\
            .pack(fill='x', padx=100, pady=2)
        ttk.Button(self, text="View Wallet", command=self.view_wallet)\
            .pack(fill='x', padx=100, pady=2)
        ttk.Button(self, text="List All Wallets", command=self.list_wallets)\
            .pack(fill='x', padx=100, pady=2)
        ttk.Button(self, text="Delete Wallet", command=self.delete_wallet)\
            .pack(fill='x', padx=100, pady=2)
        ttk.Button(self, text="Back", command=lambda: controller.show_frame(UserMenuFrame))\
            .pack(pady=10)

    def add_wallet(self):
        name = simpledialog.askstring("Wallet Name", "Enter wallet name:")
        if not name: return
        wuser = simpledialog.askstring("Username", "Enter wallet username (or '0'):")
        if wuser is None: return
        wpw = simpledialog.askstring("Password", "Enter wallet password (or 'gen'):", show='*')
        if wpw is None: return
        phrase = simpledialog.askstring("Recovery Phrase", "Enter recovery phrase (or '0'):")
        if phrase is None: return
        pin = simpledialog.askstring("PIN", "Enter recovery PIN:", show='*')
        if pin is None: return
        self._api_call('/add_wallet', {
            'username': self.controller.username,
            'master_password': self.controller.master_password,
            'wallet_name': name,
            'w_username': wuser,
            'w_password': wpw,
            'recovery_phrase': phrase,
            'pin': pin
        })

    def view_wallet(self):
        name = simpledialog.askstring("Wallet Name", "Enter wallet name:")
        if not name: return
        pin = simpledialog.askstring("PIN", "Enter recovery PIN:", show='*')
        if pin is None: return
        self._api_call('/get_wallet', {
            'username': self.controller.username,
            'master_password': self.controller.master_password,
            'wallet_name': name,
            'pin': pin
        })

    def list_wallets(self):
        self._api_call('/get_all_wallets', {'username': self.controller.username})

    def delete_wallet(self):
        name = simpledialog.askstring("Wallet Name", "Enter wallet name to delete:")
        if not name: return
        self._api_call('/delete_wallet', {
            'username': self.controller.username,
            'wallet_name': name
        })

    def _api_call(self, path, payload):
        def task():
            try:
                resp = requests.post(f"{API_URL}{path}", json=payload)
                resp.raise_for_status()
                messagebox.showinfo("Success", resp.json())
            except Exception as e:
                messagebox.showerror("Error", str(e))
        threading.Thread(target=task).start()

class CredentialsFrame(WalletFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        for widget in self.winfo_children():
            widget.destroy()
        ttk.Label(self, text="Site Credentials Vault", font=('Helvetica', 16)).pack(pady=10)
        ttk.Button(self, text="Add Credentials", command=self.add_cred)\
            .pack(fill='x', padx=100, pady=2)
        ttk.Button(self, text="View Credentials", command=self.view_cred)\
            .pack(fill='x', padx=100, pady=2)
        ttk.Button(self, text="List All Sites", command=self.list_cred)\
            .pack(fill='x', padx=100, pady=2)
        ttk.Button(self, text="Delete Credentials", command=self.delete_cred)\
            .pack(fill='x', padx=100, pady=2)
        ttk.Button(self, text="Back", command=lambda: controller.show_frame(UserMenuFrame))\
            .pack(pady=10)

    def add_cred(self):
        site = simpledialog.askstring("Site", "Enter site name:")
        if not site: return
        user = simpledialog.askstring("Username", "Enter site username (or '0'):")
        if user is None: return
        pwd = simpledialog.askstring("Password", "Enter site password (or 'gen'):", show='*')
        if pwd is None: return
        self._api_call('/add_credentials', {
            'username': self.controller.username,
            'master_password': self.controller.master_password,
            'site': site,
            's_username': user,
            's_password': pwd
        })

    def view_cred(self):
        site = simpledialog.askstring("Site", "Enter site name:")
        if not site: return
        self._api_call('/get_credentials', {
            'username': self.controller.username,
            'master_password': self.controller.master_password,
            'site': site
        })

    def list_cred(self):
        self._api_call('/get_all_sites', {'username': self.controller.username})

    def delete_cred(self):
        site = simpledialog.askstring("Site", "Enter site name to delete:")
        if not site: return
        self._api_call('/delete_credentials', {
            'username': self.controller.username,
            'site': site
        })

class DocumentsFrame(WalletFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        for widget in self.winfo_children():
            widget.destroy()
        ttk.Label(self, text="Secure Documents Vault", font=('Helvetica', 16)).pack(pady=10)
        ttk.Button(self, text="Add Document", command=self.add_doc)\
            .pack(fill='x', padx=100, pady=2)
        ttk.Button(self, text="View Document", command=self.view_doc)\
            .pack(fill='x', padx=100, pady=2)
        ttk.Button(self, text="List All Documents", command=self.list_docs)\
            .pack(fill='x', padx=100, pady=2)
        ttk.Button(self, text="Update Document", command=self.update_doc)\
            .pack(fill='x', padx=100, pady=2)
        ttk.Button(self, text="Delete Document", command=self.delete_doc)\
            .pack(fill='x', padx=100, pady=2)
        ttk.Button(self, text="Back", command=lambda: controller.show_frame(UserMenuFrame))\
            .pack(pady=10)

    def add_doc(self):
        name = simpledialog.askstring("Document Name", "Enter document name:")
        if not name: return
        contents = simpledialog.askstring("Contents", "Enter document contents:")
        if contents is None: return
        self._api_call('/add_secure_doc', {
            'username': self.controller.username,
            'master_password': self.controller.master_password,
            'doc_name': name,
            'doc_contents': contents
        })

    def view_doc(self):
        name = simpledialog.askstring("Document Name", "Enter document name:")
        if not name: return
        self._api_call('/get_secure_doc', {
            'username': self.controller.username,
            'master_password': self.controller.master_password,
            'doc_name': name
        })

    def list_docs(self):
        self._api_call('/get_all_docs', {'username': self.controller.username})

    def update_doc(self):
        name = simpledialog.askstring("Document Name", "Enter document name to update:")
        if not name: return
        new = simpledialog.askstring("New Contents", "Enter new contents:")
        if new is None: return
        self._api_call('/update_secure_doc', {
            'username': self.controller.username,
            'master_password': self.controller.master_password,
            'doc_name': name,
            'new_contents': new
        })

    def delete_doc(self):
        name = simpledialog.askstring("Document Name", "Enter document name to delete:")
        if not name: return
        self._api_call('/delete_secure_doc', {
            'username': self.controller.username,
            'doc_name': name
        })

class AccountSettingsFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        ttk.Label(self, text="Account Settings", font=('Helvetica', 16)).pack(pady=10)
        ttk.Button(self, text="Change Master Password", command=self.change_password)\
            .pack(fill='x', padx=100, pady=2)
        ttk.Button(self, text="Enable 2FA", command=self.enable_2fa)\
            .pack(fill='x', padx=100, pady=2)
        ttk.Button(self, text="Disable 2FA", command=self.disable_2fa)\
            .pack(fill='x', padx=100, pady=2)
        ttk.Button(self, text="Delete All Data", command=self.delete_all)\
            .pack(fill='x', padx=100, pady=2)
        ttk.Button(self, text="Back", command=lambda: controller.show_frame(UserMenuFrame))\
            .pack(pady=10)

    def change_password(self):
        old = simpledialog.askstring("Current Password", "Enter current master password:", show='*')
        if old is None: return
        new = simpledialog.askstring("New Password", "Enter new master password:", show='*')
        if new is None: return
        conf = simpledialog.askstring("Confirm Password", "Confirm new master password:", show='*')
        if conf != new:
            messagebox.showerror("Error", "Passwords don't match!")
            return
        self._api_call('/reset_master_password', {
            'username': self.controller.username,
            'old_master_password': old,
            'new_master_password': new
        })

    def enable_2fa(self):
        self._api_call('/enable_2fa', {'username': self.controller.username})

    def disable_2fa(self):
        pin = simpledialog.askstring("Recovery PIN", "Enter recovery PIN to disable 2FA:", show='*')
        if pin is None: return
        self._api_call('/disable_2fa', {'username': self.controller.username, 'pin': pin})

    def delete_all(self):
        pin = simpledialog.askstring("Recovery PIN", "Enter recovery PIN:", show='*')
        if pin is None: return
        if messagebox.askyesno("Confirm", "Are you sure? This will delete ALL your data."):
            self._api_call('/delete_all_data', {'username': self.controller.username, 'pin': pin})

    def _api_call(self, path, payload):
        def task():
            try:
                resp = requests.post(f"{API_URL}{path}", json=payload)
                resp.raise_for_status()
                messagebox.showinfo("Success", resp.json())
            except Exception as e:
                messagebox.showerror("Error", str(e))
        threading.Thread(target=task).start()

if __name__ == '__main__':
    app = SecureASFApp()
    app.mainloop()
