from script3_sql import DatabaseConnector
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from getpass import getpass
import asyncio
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
        hash_value = await self.create_key(master_password)
        pin_hash = self.ph.hash(recovery_pin)
        await self.db.create_user_with_pin(self.username, hash_value, pin_hash)

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

    async def verify_master_password(self, master_password):
        stored_pass = await self.db.get_user_password(self.username)
        if not stored_pass:
            if await self.db.check_username_exists(self.username):
                print(f"Username '{self.username}' is already taken.")
                return False
            
            hash_value = await self.create_key(master_password)
            await self.db.create_user(self.username, hash_value)
            print(f"New user '{self.username}' created successfully!")
            return True
            
        try:
            return self.ph.verify(stored_pass, master_password)
        except VerifyMismatchError:
            return False

    async def load_key(self, master_password):
        if not await self.verify_master_password(master_password):
            raise ValueError("Invalid master password")
    
        salt = b'salt_'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        self.fer = Fernet(key)

    async def add_credentials(self, site, username, password):
        username = '' if username == '0' else username
        password = '' if password == '0' else password
        encrypted_username = self.fer.encrypt(username.encode()).decode()
        encrypted_password = self.fer.encrypt(password.encode()).decode()
        await self.db.store_site(self.username, site, encrypted_username, encrypted_password)

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
            decrypted_username = self.fer.decrypt(result[0].encode()).decode()
            decrypted_password = self.fer.decrypt(result[1].encode()).decode()
            decrypted_recovery = self.fer.decrypt(result[2].encode()).decode()
            return {
                "username": decrypted_username or "No username",
                "password": decrypted_password or "No password",
                "recovery_phrase": decrypted_recovery or "No recovery phrase"
            }
        return None
    
    async def delete_all_data(self, pin):
        if not await self.verify_recovery_pin(pin):
            raise ValueError("Invalid PIN")
        await self.db.delete_user_data(self.username)

    async def add_secure_doc(self, doc_name, doc_contents):
        encrypted_name = self.fer.encrypt(doc_name.encode())
        encrypted_contents = self.fer.encrypt(doc_contents.encode())
        await self.db.store_doc(self.username, encrypted_name, encrypted_contents)

    async def get_secure_doc(self, doc_name, master_password):
       ## if not await self.verify_master_password(master_password):
           ## raise ValueError("Invalid master password")
        result = await self.db.get_doc(self.username, doc_name)
        if result:
            decrypted_name = self.fer.decrypt((result[0]).decode())
            decrypted_contents = self.fer.decrypt((result[1]).decode())
            return {
                "name": decrypted_name,
                "contents": decrypted_contents
            }
        return None
    
    async def get_all_docs(self):
        encrypted_docs = await self.db.get_all_docs(self.username)
        decrypted_docs = []
        for doc in encrypted_docs:
            try:
                decrypted_name = self.fer.decrypt((doc.encode()).decode())
                decrypted_docs.append(decrypted_name)
            except:
                continue
        return decrypted_docs

    
    async def update_secure_doc(self, doc_name, new_contents, master_password):
        if not await self.verify_master_password(master_password):
            raise ValueError("Invalid master password")
        encrypted_contents = self.fer.encrypt(new_contents.encode())
        await self.db.update_doc(self.username, doc_name, encrypted_contents)

    async def delete_secure_doc(self, doc_name, master_password):
        if not await self.verify_master_password(master_password):
            raise ValueError("Invalid master password")
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
        print("\n=== SECURE ASF PASSW MANAGER ===")
        print("1. Login")
        print("2. Register")
        print("3. Recover Account")
        print("4. Exit")
        
        initial_choice = input("\nEnter your choice: ")
        
        if initial_choice == '1':  # Login
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
                    print("1. Add credentials")
                    print("2. Get credentials")
                    print("3. List all sites")
                    print("4. Add wallet")
                    print("5. View wallet")
                    print("6. List all wallets")
                    print("7. Add secure doc")
                    print("8. View secure doc")
                    print("9. List all docs")
                    print("10. Delete secure doc(s)")
                    print("11. Update secure doc")
                    print("12. Delete all data")                    
                    print("13. Logout")
                    
                    choice = input("\nEnter your choice: ")
                    
                    if choice == '1':
                        site = await get_secure_input("Enter site:")
                        if site is None:
                            continue
                        print("If no username exists, enter '0'")
                        username = await get_secure_input("Enter username:")
                        if username is None:
                            continue
                        print("If no password exists, enter '0'")
                        password = await get_secure_input("Enter password:", is_password=True)
                        if password is None:
                            continue
                        await pm.add_credentials(site, username, password)
                        print("Credentials added successfully!")
                        
                    elif choice == '2':
                        site = await get_secure_input("Enter site:")
                        if site is None:
                            continue
                        creds = await pm.get_credentials(site, master_password)
                        if creds:
                            print(f"\nSite: {site}")
                            print(f"Username: {creds['username']}")
                            print(f"Password: {creds['password']}")
                        else:
                            print("Site not found!")
                            
                    elif choice == '3':
                        sites = await pm.db.get_all_sites(pm.username)
                        print("\nStored sites:")
                        for site in sites:
                            print(site)

                    elif choice == '4':
                        wallet_name = await get_secure_input("Enter wallet name:")
                        if wallet_name is None:
                            continue
                        print("If no username exists, enter '0'")
                        username = await get_secure_input("Enter username:")
                        if username is None:
                            continue
                        print("If no password exists, enter '0'")
                        password = await get_secure_input("Enter password:", is_password=True)
                        if password is None:
                            continue
                        print("If no recovery phrase exists, enter '0'")
                        recovery = await get_secure_input("Enter recovery phrase:")
                        if recovery is None:
                            continue
                        pin = await get_secure_input("Enter PIN:", is_password=True)
                        if pin is None:
                            continue
                        await pm.add_wallet(wallet_name, username, password, recovery, master_password, pin)
                        print("Wallet added successfully!")
                            
                    elif choice == '5':
                        wallet_name = await get_secure_input("Enter wallet name:")
                        if wallet_name is None:
                            continue
                        pin = await get_secure_input("Enter PIN:", is_password=True)
                        if pin is None:
                            continue
                        wallet = await pm.get_wallet(wallet_name, master_password, pin)
                        if wallet:
                            print(f"\nWallet Name: {wallet_name}")
                            print(f"Username: {wallet['username']}")
                            print(f"Password: {wallet['password']}")
                            print(f"Recovery Phrase: {wallet['recovery_phrase']}")
                        else:
                            print("Wallet not found!")
                            
                    elif choice == '6':
                        wallets = await pm.db.get_all_wallets(pm.username)
                        print("\nStored wallets:")
                        for wallet in wallets:
                            print(wallet)

                    elif choice == '7':
                        doc_name = await get_secure_input("Enter doc name:")
                        if doc_name is None:
                            continue
                        doc_contents = await get_secure_input("Enter doc contents:")
                        if doc_contents is None:
                             continue
                        await pm.add_secure_doc(doc_name, doc_contents)
                        print("Secure note added successfully!")

                    elif choice == '8':
                        doc_name = await get_secure_input("Enter doc name:")
                        if doc_name is None:
                            continue
                        doc = await pm.get_secure_doc(username, doc_name)
                        if doc:
                            print(f"\nDoc Name: {doc['name']}")
                            print(f"Contents: {doc['contents']}")
                        else:
                            print("Doc not found!")

                    elif choice == '9':
                        docs = await pm.get_all_docs()
                        print("\nStored docs:")
                        for doc in docs:
                            print(doc)

                    elif choice == '10':
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

                    elif choice == '11':
                        doc_name = await get_secure_input("Enter doc name to update:")
                        if doc_name is None:
                            continue
                        new_contents = await get_secure_input("Enter new contents:")
                        if new_contents is None:
                            continue
                        await pm.update_secure_doc(doc_name, new_contents, master_password)
                        print("Secure doc updated successfully!")
                
                    elif choice == '12':
                        print("\n⚠️ WARNING: This action will permanently delete all your stored data.")
                        pin = await get_secure_input("Enter recovery PIN:", is_password=True)
                        if pin is None:
                            continue
                        await pm.delete_all_data(pin)
                        print("All data has been permanently deleted.")
                        break

                    elif choice == '13':
                        break

            except ValueError as e:
                print(f"Error: {str(e)}")
            finally:
                await pm.close()
                
        elif initial_choice == '2':  # Register
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
                
        elif initial_choice == '3':  # Recover Account
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
if __name__ == "__main__":
    asyncio.run(main())

