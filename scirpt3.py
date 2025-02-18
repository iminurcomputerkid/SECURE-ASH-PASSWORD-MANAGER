from script3_sql import DatabaseConnector
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from getpass import getpass
import asyncio
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

class DynamicPasswordManager:
    def __init__(self, username):
        self.username = username
        self.db = DatabaseConnector()
        self.ph = PasswordHasher(
            time_cost=2,
            memory_cost=102400,
            parallelism=8,
            hash_len=32,
            salt_len=16
        )

    async def create_key(self, master_password):
        return self.ph.hash(master_password)

    async def create_account(self, master_password, recovery_pin):
        user_salt = os.urandom(16)
        hash_value = await self.create_key(master_password)
        pin_hash = self.ph.hash(recovery_pin)
        await self.db.create_user_with_pin(self.username, hash_value, pin_hash)
        await self.db.store_user_salt(self.username, user_salt)

    async def verify_recovery_pin(self, recovery_pin):
        stored_pin = await self.db.get_recovery_pin(self.username)
        if not stored_pin:
            return False
        try:
            return self.ph.verify(stored_pin, recovery_pin)
        except VerifyMismatchError:
            return False

    async def reset_master_password(self, new_password):
        hash_value = await self.create_key(new_password)
        await self.db.update_master_password(self.username, hash_value)
        user_salt = await self.db.get_user_salt(self.username)
        if not user_salt:
            user_salt = os.urandom(16)
            await self.db.store_user_salt(self.username, user_salt)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=user_salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(new_password.encode()))
        self.fer = Fernet(key)

    async def verify_master_password(self, master_password):
        try:
            stored_pass = await self.db.get_user_password(self.username)
            if not stored_pass:
                print(f"Invalid username or password for inputted user")
                return False
            return self.ph.verify(stored_pass, master_password)
        except AttributeError:
            print(f"\nLogin failed")
            return False
        except Exception:
            print(f"\nLogin failed")
            return False

    async def load_key(self, master_password):
        try:
            if not await self.verify_master_password(master_password):
                raise ValueError("Invalid master password")
            user_salt = await self.db.get_user_salt(self.username)
            if not user_salt:
                raise ValueError("User salt not found")
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=user_salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
            self.fer = Fernet(key)
        except ValueError as e:
            print(f"\n{str(e)}")
            raise
        except Exception as e:
            print("\nError during key generation")
            raise

    async def add_credentials(self, site, username, password):
        try:
            username = '' if username == '0' else username
            password = '' if password == '0' else password
            encrypted_username = self.fer.encrypt(username.encode()).decode()
            encrypted_password = self.fer.encrypt(password.encode()).decode()
            await self.db.store_site(self.username, site, encrypted_username, encrypted_password)
            return True
        except Exception as e:
            print(f"\nError adding credentials: {str(e)}")
            return False

    async def get_credentials(self, site, master_password):
        if not await self.verify_master_password(master_password):
            raise ValueError("Invalid master password")
        result = await self.db.get_site_credentials(self.username, site)
        if result:
            decrypted_username = self.fer.decrypt(result[0].encode()).decode()
            decrypted_password = self.fer.decrypt(result[1].encode()).decode()
            return {
                "username": decrypted_username or "No username",
                "password": decrypted_password or "No password"
            }
        return None

    async def add_wallet(self, wallet_name, username, password, recovery_phrase, master_password, pin):
        if not await self.verify_recovery_pin(pin):
            raise ValueError("Invalid PIN")
        username = '' if username == '0' else username
        password = '' if password == '0' else password
        recovery_phrase = '' if recovery_phrase == '0' else recovery_phrase
        encrypted_username = self.fer.encrypt(username.encode()).decode()
        encrypted_password = self.fer.encrypt(password.encode()).decode()
        encrypted_recovery = self.fer.encrypt(recovery_phrase.encode()).decode()
        await self.db.store_wallet(self.username, wallet_name, encrypted_username,
                                   encrypted_password, encrypted_recovery)

    async def get_wallet(self, wallet_name, master_password, pin):
        if not await self.verify_recovery_pin(pin):
            raise ValueError("Invalid PIN")
        result = await self.db.get_wallet(self.username, wallet_name)
        if result:
            try:
                decrypted_username = self.fer.decrypt(result[0].encode()).decode() if result[0] else ""
                decrypted_password = self.fer.decrypt(result[1].encode()).decode() if result[1] else ""
                decrypted_recovery = self.fer.decrypt(result[2].encode()).decode() if result[2] else ""
                return {
                    "username": decrypted_username or "No username",
                    "password": decrypted_password or "No password",
                    "recovery_phrase": decrypted_recovery or "No recovery phrase"
                }
            except Exception as e:
                print(f"Error: {str(e)}")
        return None

    async def delete_all_data(self, pin):
        if not await self.verify_recovery_pin(pin):
            raise ValueError("Invalid PIN")
        await self.db.delete_user_data(self.username)

    async def add_secure_doc(self, doc_name, doc_contents):
        encrypted_contents = self.fer.encrypt(doc_contents.encode()).decode()
        await self.db.store_doc(self.username, doc_name, encrypted_contents)

    async def get_secure_doc(self, doc_name, master_password):
        result = await self.db.get_doc(self.username, doc_name)
        if result:
            try:
                decrypted_contents = self.fer.decrypt(result[1].encode()).decode()
                return {
                    "name": doc_name,
                    "contents": decrypted_contents
                }
            except Exception as e:
                print(f"Decryption error: {str(e)}")
        return None

    async def get_all_docs(self):
        encrypted_docs = await self.db.get_all_docs(self.username)
        docs = []
        for doc in encrypted_docs:
            try:
                if isinstance(doc, bytes):
                    doc = doc.decode()
                docs.append(doc)
            except:
                continue
        return docs

    async def update_secure_doc(self, doc_name, new_contents, master_password):
        encrypted_contents = self.fer.encrypt(new_contents.encode()).decode()
        await self.db.update_doc(self.username, doc_name, encrypted_contents)

    async def delete_secure_doc(self, doc_name, master_password):
        await self.db.delete_doc(self.username, doc_name)

    async def close(self):
        await self.db.close()

async def get_secure_input(prompt, is_password=False):
    while True:
        if is_password:
            user_input = getpass(f"{prompt} (Type 'esc' to go back): ")
        else:
            user_input = input(f"{prompt} (Type 'esc' to go back): ")
        if 'esc' in user_input.lower():
            return None
        if user_input:
            return user_input

async def main():
    print("Welcome to SECURE ASF Password Manager!")
    while True:
        try:
            print("\n=== SECURE ASF PASSW MANAGER ===")
            print("1. Login")
            print("2. Register")
            print("3. Recover Account")
            print("4. Exit")

            initial_choice = input("\nEnter your choice: ")

            if initial_choice == '1':
                username = await get_secure_input("Enter username:")
                if username is None:
                    continue

                master_password = await get_secure_input("Enter master password:", is_password=True)
                if master_password is None:
                    continue

                pm = DynamicPasswordManager(username)
                try:
                    await pm.load_key(master_password)

                    while True:
                        print("\n=== SECURE ASF ===")
                        print("1. Access Wallet Vault")
                        print("2. Access Site Credentials Vault")
                        print("3. Access Secure Documents Vault")
                        print("4. Account Settings")
                        print("5. Logout")

                        choice = input("\nEnter your choice: ")

                        if choice == '1':
                            while True:
                                print("\n=== WALLET VAULT ===")
                                print("1. Add Wallet")
                                print("2. View Wallet")
                                print("3. List All Wallets")
                                print("4. Return to Main Menu")

                                wallet_choice = input("\nEnter your choice: ")

                                if wallet_choice == '1':
                                    wallet_name = await get_secure_input("Enter wallet name:")
                                    if wallet_name is None:
                                        continue
                                    print("If no username exists, enter '0'")
                                    w_username = await get_secure_input("Enter username:")
                                    if w_username is None:
                                        continue
                                    print("If no password exists, enter '0'")
                                    w_password = await get_secure_input("Enter password:", is_password=True)
                                    if w_password is None:
                                        continue
                                    print("If no recovery phrase exists, enter '0'")
                                    recovery = await get_secure_input("Enter recovery phrase:")
                                    if recovery is None:
                                        continue
                                    pin = await get_secure_input("Enter PIN:", is_password=True)
                                    if pin is None:
                                        continue
                                    try:
                                        await pm.add_wallet(wallet_name, w_username, w_password, recovery, master_password, pin)
                                        print("Wallet added successfully!")
                                    except ValueError as e:
                                        print(f"Error: {e}")

                                elif wallet_choice == '2':
                                    wallet_name = await get_secure_input("Enter wallet name:")
                                    if wallet_name is None:
                                        continue
                                    pin = await get_secure_input("Enter PIN:", is_password=True)
                                    if pin is None:
                                        continue
                                    try:
                                        wallet = await pm.get_wallet(wallet_name, master_password, pin)
                                        if wallet:
                                            print(f"\nWallet Name: {wallet_name}")
                                            print(f"Username: {wallet['username']}")
                                            print(f"Password: {wallet['password']}")
                                            print(f"Recovery Phrase: {wallet['recovery_phrase']}")
                                        else:
                                            print("Wallet not found!")
                                    except ValueError as e:
                                        print(f"Error: {e}")

                                elif wallet_choice == '3':
                                    wallets = await pm.db.get_all_wallets(pm.username)
                                    print("\nStored wallets:")
                                    for w in wallets:
                                        print(w)

                                elif wallet_choice == '4':
                                    break

                        elif choice == '2':
                            while True:
                                print("\n=== CREDENTIALS VAULT ===")
                                print("1. Add Credentials")
                                print("2. View Credentials")
                                print("3. List All Sites")
                                print("4. Return to Main Menu")

                                cred_choice = input("\nEnter your choice: ")

                                if cred_choice == '1':
                                    site = await get_secure_input("Enter site:")
                                    if site is None:
                                        continue
                                    print("If no username exists, enter '0'")
                                    s_username = await get_secure_input("Enter username:")
                                    if s_username is None:
                                        continue
                                    print("If no password exists, enter '0'")
                                    s_password = await get_secure_input("Enter password:", is_password=True)
                                    if s_password is None:
                                        continue
                                    success = await pm.add_credentials(site, s_username, s_password)
                                    if success:
                                        print("Credentials added successfully!")
                                    else:
                                        print("Could not add credentials.")

                                elif cred_choice == '2':
                                    site = await get_secure_input("Enter site:")
                                    if site is None:
                                        continue
                                    try:
                                        creds = await pm.get_credentials(site, master_password)
                                        if creds:
                                            print(f"\nSite: {site}")
                                            print(f"Username: {creds['username']}")
                                            print(f"Password: {creds['password']}")
                                        else:
                                            print("Site not found!")
                                    except ValueError as e:
                                        print(f"Error: {e}")

                                elif cred_choice == '3':
                                    sites = await pm.db.get_all_sites(pm.username)
                                    print("\nStored sites:")
                                    for s in sites:
                                        print(s)

                                elif cred_choice == '4':
                                    break

                        elif choice == '3':
                            while True:
                                print("\n=== DOCUMENTS VAULT ===")
                                print("1. Add Secure Document")
                                print("2. View Document")
                                print("3. List All Documents")
                                print("4. Update Document")
                                print("5. Delete Document")
                                print("6. Return to Main Menu")

                                doc_choice = input("\nEnter your choice: ")

                                if doc_choice == '1':
                                    doc_name = await get_secure_input("Enter doc name:")
                                    if doc_name is None:
                                        continue
                                    doc_contents = await get_secure_input("Enter doc contents:")
                                    if doc_contents is None:
                                        continue
                                    await pm.add_secure_doc(doc_name, doc_contents)
                                    print("Secure note added successfully!")

                                elif doc_choice == '2':
                                    doc_name = await get_secure_input("Enter doc name:")
                                    if doc_name is None:
                                        continue
                                    doc = await pm.get_secure_doc(doc_name, master_password)
                                    if doc:
                                        print(f"\nDoc Name: {doc['name']}")
                                        print(f"Contents: {doc['contents']}")
                                    else:
                                        print("Doc not found!")

                                elif doc_choice == '3':
                                    docs = await pm.get_all_docs()
                                    print("\nStored docs:")
                                    for d in docs:
                                        print(d)

                                elif doc_choice == '4':
                                    doc_name = await get_secure_input("Enter doc name to update:")
                                    if doc_name is None:
                                        continue
                                    new_contents = await get_secure_input("Enter new contents:")
                                    if new_contents is None:
                                        continue
                                    await pm.update_secure_doc(doc_name, new_contents, master_password)
                                    print("Secure doc updated successfully!")

                                elif doc_choice == '5':
                                    doc_name = await get_secure_input("Enter doc name to delete:")
                                    if doc_name is None:
                                        continue
                                    print("\n⚠️ WARNING: This will permanently delete the selected document.")
                                    confirm = input("Type 'APPLY' to confirm deletion: ")
                                    if confirm.upper() == 'APPLY':
                                        await pm.delete_secure_doc(doc_name, master_password)
                                        print("Secure doc deleted successfully!")
                                    else:
                                        print("Deletion cancelled.")

                                elif doc_choice == '6':
                                    break

                        elif choice == '4':
                            pin = await get_secure_input("Enter PIN to access settings:", is_password=True)
                            if pin is None:
                                continue

                            if not await pm.verify_recovery_pin(pin):
                                print("Invalid PIN! Access denied.")
                                continue

                            while True:
                                print("\n=== ACCOUNT SETTINGS ===")
                                print("1. Change Master Password")
                                print("2. Delete All Data")
                                print("3. Return to Main Menu")

                                settings_choice = input("\nEnter your choice: ")

                                if settings_choice == '1':
                                    new_password = await get_secure_input("Enter new master password:", is_password=True)
                                    if new_password is None:
                                        continue
                                    confirm_password = await get_secure_input("Confirm new master password:", is_password=True)
                                    if confirm_password is None:
                                        continue
                                    if new_password != confirm_password:
                                        print("Passwords don't match!")
                                        continue
                                    await pm.reset_master_password(new_password)
                                    print("Master password reset successfully!")
                                    break

                                elif settings_choice == '2':
                                    print("\nWARNING: This action will permanently delete all your stored data.")
                                    pin_confirm = await get_secure_input("Enter recovery PIN:", is_password=True)
                                    if pin_confirm is None:
                                        continue
                                    try:
                                        await pm.delete_all_data(pin_confirm)
                                        print("All data has been permanently deleted.")
                                        return
                                    except ValueError as e:
                                        print(f"Error: {e}")
                                        return

                                elif settings_choice == '3':
                                    break

                        elif choice == '5':
                            break

                except ValueError as e:
                    print(f"Error: {str(e)}")
                finally:
                    await pm.close()

            elif initial_choice == '2':
                username = await get_secure_input("Enter username:")
                if username is None:
                    continue

                master_password = await get_secure_input("Enter master password:", is_password=True)
                if master_password is None:
                    continue

                confirm_password = await get_secure_input("Confirm master password:", is_password=True)
                if confirm_password is None:
                    continue
                if master_password != confirm_password:
                    print("Passwords don't match!")
                    continue

                recovery_pin = await get_secure_input("Enter 6-digit recovery PIN:", is_password=True)
                if recovery_pin is None:
                    continue
                if not recovery_pin.isdigit() or len(recovery_pin) != 6:
                    print("PIN must be exactly 6 digits!")
                    continue

                confirm_pin = await get_secure_input("Confirm recovery PIN:", is_password=True)
                if confirm_pin is None:
                    continue
                if recovery_pin != confirm_pin:
                    print("PINs don't match!")
                    continue

                pm = DynamicPasswordManager(username)
                try:
                    await pm.create_account(master_password, recovery_pin)
                    print("Account created successfully!")
                except ValueError as e:
                    print(f"Error: {str(e)}")
                finally:
                    await pm.close()

            elif initial_choice == '3':
                username = await get_secure_input("Enter username:")
                if username is None:
                    continue

                recovery_pin = await get_secure_input("Enter recovery PIN:", is_password=True)
                if recovery_pin is None:
                    continue

                pm = DynamicPasswordManager(username)
                try:
                    if await pm.verify_recovery_pin(recovery_pin):
                        new_password = await get_secure_input("Enter new master password:", is_password=True)
                        if new_password is None:
                            continue
                        confirm_password = await get_secure_input("Confirm new master password:", is_password=True)
                        if confirm_password is None:
                            continue
                        if new_password != confirm_password:
                            print("Passwords don't match!")
                            continue
                        await pm.reset_master_password(new_password)
                        print("Master password reset successfully!")
                    else:
                        print("Invalid recovery PIN!")
                except ValueError as e:
                    print(f"Error: {str(e)}")
                finally:
                    await pm.close()

            elif initial_choice == '4':
                print("Thank you for using SECURE ASF!")
                break

        except Exception as e:
            print(f"\n[!] An unexpected error occurred: {e}")
            print("Returning to main menu...")

if __name__ == "__main__":
    asyncio.run(main())
