import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import json

class SecureManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password & Wallet Manager")
        self.root.geometry("900x600")
        
        # Initialize core functionality
        self.password_file = 'passw.txt'
        self.master_hash_file = 'master_hash.txt'
        self.wallet_file = 'wallets.txt'
        self.SECRET_PIN = "10001"
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        self.password_dict = {}
        self.wallet_dict = {}
        
        self.initialize_storage()
        self.setup_gui()

    def initialize_storage(self):
        for file in [self.password_file, self.master_hash_file, self.wallet_file]:
            if not os.path.exists(file):
                with open(file, 'wb') as f:
                    f.write(b'')

    def setup_gui(self):
        style = ttk.Style()
        style.configure('Header.TLabel', font=('Helvetica', 16, 'bold'))
        style.configure('SubHeader.TLabel', font=('Helvetica', 12))
        style.configure('Action.TButton', padding=8)
        
        self.main_frame = ttk.Frame(self.root, padding="20")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.show_login_screen()

    def show_login_screen(self):
        self.clear_frame()
        
        ttk.Label(
            self.main_frame, 
            text="Secure Password & Wallet Manager", 
            style='Header.TLabel'
        ).grid(row=0, column=0, columnspan=2, pady=20)

        login_frame = ttk.LabelFrame(self.main_frame, text="Login", padding="20")
        login_frame.grid(row=1, column=0, columnspan=2, pady=10)

        ttk.Label(login_frame, text="Master Password:").grid(row=0, column=0, pady=5, padx=5)
        self.master_password = ttk.Entry(login_frame, show="*")
        self.master_password.grid(row=0, column=1, pady=5, padx=5)

        ttk.Button(
            login_frame,
            text="Login",
            command=self.handle_login,
            style='Action.TButton'
        ).grid(row=1, column=0, columnspan=2, pady=10)

        options_frame = ttk.Frame(self.main_frame)
        options_frame.grid(row=2, column=0, columnspan=2, pady=20)

        ttk.Button(
            options_frame,
            text="Reset Master Password",
            command=self.show_reset_password_dialog
        ).grid(row=0, column=0, padx=10)

        ttk.Button(
            options_frame,
            text="Exit",
            command=self.root.quit
        ).grid(row=0, column=1, padx=10)

    def show_reset_password_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Reset Master Password")
        dialog.geometry("400x250")
        
        frame = ttk.Frame(dialog, padding="20")
        frame.grid(row=0, column=0)
        
        ttk.Label(frame, text="Recovery PIN:").grid(row=0, column=0, pady=5)
        pin_entry = ttk.Entry(frame, show="*")
        pin_entry.grid(row=0, column=1, pady=5)
        
        ttk.Label(frame, text="New Master Password:").grid(row=1, column=0, pady=5)
        new_pass_entry = ttk.Entry(frame, show="*")
        new_pass_entry.grid(row=1, column=1, pady=5)
        
        def reset():
            try:
                if self.reset_master_password(pin_entry.get(), new_pass_entry.get()):
                    messagebox.showinfo("Success", "Master password reset successful!")
                    dialog.destroy()
            except ValueError:
                messagebox.showerror("Error", "Invalid PIN!")
        
        ttk.Button(frame, text="Reset Password", command=reset).grid(row=2, column=0, columnspan=2, pady=10)

    def reset_master_password(self, pin, new_master_password):
        if pin != self.SECRET_PIN:
            raise ValueError("Invalid PIN")
        
        new_key = self.create_key(new_master_password)
        with open(self.master_hash_file, 'wb') as f:
            f.write(new_key)
        
        self.key = new_key
        self.fer = Fernet(self.key)
        self.save_data()
        self.save_wallet_data()
        return True

    def show_main_screen(self):
        self.clear_frame()
        
        notebook = ttk.Notebook(self.main_frame)
        notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Passwords tab
        passwords_frame = ttk.Frame(notebook, padding="10")
        notebook.add(passwords_frame, text="Passwords")
        
        ttk.Button(
            passwords_frame,
            text="Add Password",
            command=self.show_add_password_dialog
        ).grid(row=0, column=0, pady=5, padx=5)
        
        ttk.Button(
            passwords_frame,
            text="View Password",
            command=self.show_view_password_dialog
        ).grid(row=0, column=1, pady=5, padx=5)
        
        ttk.Button(
            passwords_frame,
            text="List All Passwords",
            command=self.show_password_list
        ).grid(row=0, column=2, pady=5, padx=5)
        
        # Wallets tab
        wallets_frame = ttk.Frame(notebook, padding="10")
        notebook.add(wallets_frame, text="Wallets")
        
        ttk.Button(
            wallets_frame,
            text="Add Wallet",
            command=self.show_add_wallet_dialog
        ).grid(row=0, column=0, pady=5, padx=5)
        
        ttk.Button(
            wallets_frame,
            text="View Wallet",
            command=self.show_view_wallet_dialog
        ).grid(row=0, column=1, pady=5, padx=5)
        
        ttk.Button(
            wallets_frame,
            text="List All Wallets",
            command=self.show_wallet_list
        ).grid(row=0, column=2, pady=5, padx=5)
        
        # Settings tab
        settings_frame = ttk.Frame(notebook, padding="10")
        notebook.add(settings_frame, text="Settings")
        
        ttk.Button(
            settings_frame,
            text="Change Master Password",
            command=self.show_change_password_dialog
        ).grid(row=0, column=0, pady=5)
        
        ttk.Button(
            settings_frame,
            text="Delete All Data",
            command=self.show_delete_confirmation
        ).grid(row=1, column=0, pady=5)
        
        # Logout button
        ttk.Button(
            self.main_frame,
            text="Logout",
            command=self.show_login_screen
        ).grid(row=1, column=0, pady=20)

    def show_password_list(self):
        sites = list(self.password_dict.keys())
        if sites:
            messagebox.showinfo("Stored Sites", "\n".join(sites))
        else:
            messagebox.showinfo("Stored Sites", "No passwords stored yet")

    def show_wallet_list(self):
        wallets = list(self.wallet_dict.keys())
        if wallets:
            messagebox.showinfo("Stored Wallets", "\n".join(wallets))
        else:
            messagebox.showinfo("Stored Wallets", "No wallets stored yet")

    def show_change_password_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Change Master Password")
        dialog.geometry("400x300")
        
        frame = ttk.Frame(dialog, padding="20")
        frame.grid(row=0, column=0)
        
        ttk.Label(frame, text="Current Password:").grid(row=0, column=0, pady=5)
        current_pass_entry = ttk.Entry(frame, show="*")
        current_pass_entry.grid(row=0, column=1, pady=5)
        
        ttk.Label(frame, text="New Password:").grid(row=1, column=0, pady=5)
        new_pass_entry = ttk.Entry(frame, show="*")
        new_pass_entry.grid(row=1, column=1, pady=5)
        
        ttk.Label(frame, text="PIN:").grid(row=2, column=0, pady=5)
        pin_entry = ttk.Entry(frame, show="*")
        pin_entry.grid(row=2, column=1, pady=5)
        
        def change():
            if self.verify_master_password(current_pass_entry.get()):
                try:
                    self.reset_master_password(pin_entry.get(), new_pass_entry.get())
                    messagebox.showinfo("Success", "Password changed successfully!")
                    dialog.destroy()
                except ValueError:
                    messagebox.showerror("Error", "Invalid PIN!")
            else:
                messagebox.showerror("Error", "Invalid current password!")
        
        ttk.Button(frame, text="Change Password", command=change).grid(row=3, column=0, columnspan=2, pady=10)

    def show_delete_confirmation(self):
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete all data?"):
            dialog = tk.Toplevel(self.root)
            dialog.title("Delete All Data")
            dialog.geometry("300x150")
            
            frame = ttk.Frame(dialog, padding="20")
            frame.grid(row=0, column=0)
            
            ttk.Label(frame, text="Enter PIN to confirm:").grid(row=0, column=0, pady=5)
            pin_entry = ttk.Entry(frame, show="*")
            pin_entry.grid(row=1, column=0, pady=5)
            
            def delete():
                try:
                    self.delete_all_data(pin_entry.get())
                    messagebox.showinfo("Success", "All data deleted successfully!")
                    dialog.destroy()
                    self.show_login_screen()
                except ValueError:
                    messagebox.showerror("Error", "Invalid PIN!")
            
            ttk.Button(frame, text="Delete All Data", command=delete).grid(row=2, column=0, pady=10)

    def delete_all_data(self, pin):
        if pin != self.SECRET_PIN:
            raise ValueError("Invalid PIN")
        for file in [self.password_file, self.master_hash_file, self.wallet_file]:
            if os.path.exists(file):
                os.remove(file)
        self.initialize_storage()
        self.password_dict = {}
        self.wallet_dict = {}

    def clear_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    # Cryptographic methods
    def create_key(self, master_password):
        salt = b'salt_'  
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key

    def verify_master_password(self, master_password):
        if os.path.getsize(self.master_hash_file) == 0:
            with open(self.master_hash_file, 'wb') as f:
                f.write(self.create_key(master_password))
            return True
        with open(self.master_hash_file, 'rb') as f:
            stored_hash = f.read()
        return stored_hash == self.create_key(master_password)

    def load_key(self, master_password):
        if not self.verify_master_password(master_password):
            raise ValueError("Invalid master password")
        self.key = self.create_key(master_password)
        self.fer = Fernet(self.key)
        self.load_data()

    def handle_login(self):
        try:
            self.load_key(self.master_password.get())
            self.show_main_screen()
        except ValueError:
            messagebox.messagebox.showerror("Error", "Invalid master password!")

    def load_data(self):
        self.password_dict = {}
        self.wallet_dict = {}
        if os.path.getsize(self.password_file) > 0:
            with open(self.password_file, 'rb') as f:
                encrypted_data = f.read()
                try:
                    decrypted_data = self.fer.decrypt(encrypted_data)
                    self.password_dict = json.loads(decrypted_data)
                except:
                    pass
        
        if os.path.getsize(self.wallet_file) > 0:
            with open(self.wallet_file, 'rb') as f:
                encrypted_data = f.read()
                try:
                    decrypted_data = self.fer.decrypt(encrypted_data)
                    self.wallet_dict = json.loads(decrypted_data)
                except:
                    pass

    def save_data(self):
        encrypted_data = self.fer.encrypt(json.dumps(self.password_dict).encode())
        with open(self.password_file, 'wb') as f:
            f.write(encrypted_data)

    def save_wallet_data(self):
        encrypted_data = self.fer.encrypt(json.dumps(self.wallet_dict).encode())
        with open(self.wallet_file, 'wb') as f:
            f.write(encrypted_data)

    def add_credentials(self, site, username, password):
        self.password_dict[site] = {"username": username, "password": password}
        self.save_data()

    def get_credentials(self, site, master_password):
        if not self.verify_master_password(master_password):
            raise ValueError("Invalid master password")
        return self.password_dict.get(site)

    def add_wallet(self, wallet_name, public_key, private_key, master_password, pin):
        if not self.verify_master_password(master_password) or pin != self.SECRET_PIN:
            raise ValueError("Invalid credentials")
        
        self.wallet_dict[wallet_name] = {
            "public_key": public_key,
            "private_key": self.rsa_encrypt(private_key)
        }
        self.save_wallet_data()

    def get_wallet(self, wallet_name, master_password, pin):
        if not self.verify_master_password(master_password) or pin != self.SECRET_PIN:
            raise ValueError("Invalid credentials")
        return self.wallet_dict.get(wallet_name)

    def rsa_encrypt(self, message):
        return self.public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def rsa_decrypt(self, encrypted_message):
        return self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()

def main():
    root = tk.Tk()
    app = SecureManagerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()

