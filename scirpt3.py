import requests
import getpass

API_URL = "https://secure-asf-password-manager.onrender.com"

def get_secure_input(prompt, is_password=False):
    while True:
        if is_password:
            user_input = getpass.getpass(f"{prompt} (Type 'esc' to go back): ")
        else:
            user_input = input(f"{prompt} (Type 'esc' to go back): ")
        if 'esc' in user_input.lower():
            return None
        if user_input:
            return user_input
        
def make_secure_request(method, endpoint, **kwargs):
    verify_ssl = True
    return requests.request(
        method,
        f"{API_URL}/{endpoint}",
        verify=verify_ssl,
        **kwargs
    )

def register_account():
    print("\n=== SECURE ASF PASSW MANAGER ===")
    print("Register a New Account")
    username = get_secure_input("Enter username:")
    if username is None:
        return
    master_password = get_secure_input("Enter master password:", is_password=True)
    if master_password is None:
        return
    confirm_master_password = get_secure_input("Confirm master password:", is_password=True)
    if confirm_master_password is None:
        return
    if master_password != confirm_master_password:
        print("Passwords don't match!")
        return
    recovery_pin = get_secure_input("Enter 6-digit recovery PIN:", is_password=True)
    if recovery_pin is None:
        return
    if not recovery_pin.isdigit() or len(recovery_pin) != 6:
        print("PIN must be exactly 6 digits!")
        return
    confirm_pin = get_secure_input("Confirm recovery PIN:", is_password=True)
    if confirm_pin is None:
        return
    if recovery_pin != confirm_pin:
        print("PINs don't match!")
        return
    payload = {
        "username": username,
        "master_password": master_password,
        "confirm_master_password": confirm_master_password,
        "recovery_pin": recovery_pin,
        "confirm_recovery_pin": confirm_pin
    }
    try:
        response = requests.post(f"{API_URL}/register", json=payload)
        print(response.json())
    except Exception as e:
        print(f"Registration error: {e}")

def login():
    print("\n=== SECURE ASF PASSW MANAGER ===")
    print("Login")
    username = get_secure_input("Enter username:")
    if username is None:
        return None, None
    master_password = get_secure_input("Enter master password:", is_password=True)
    if master_password is None:
        return None, None
    payload = {
        "username": username,
        "master_password": master_password
    }
    try:
        response = requests.post(f"{API_URL}/login", json=payload)
        data = response.json()
        print(data)
        if data.get("message", "").lower() == "login successful":
            return username, master_password
        else:
            return None, None
    except Exception as e:
        print(f"Login error: {e}")
        return None, None

def recover_account():
    print("\n=== SECURE ASF PASSW MANAGER ===")
    print("Recover Account")
    username = get_secure_input("Enter username:")
    if username is None:
        return
    recovery_pin = get_secure_input("Enter recovery PIN:", is_password=True)
    if recovery_pin is None:
        return
    payload = {
        "username": username,
        "recovery_pin": recovery_pin
    }
    try:
        new_password = get_secure_input("Enter new master password:", is_password=True)
        if new_password is None:
            return
        confirm_password = get_secure_input("Confirm new master password:", is_password=True)
        if confirm_password is None:
            return
        if new_password != confirm_password:
            print("Passwords don't match!")
            return
        payload["new_master_password"] = new_password
        response = requests.post(f"{API_URL}/reset_master_password", json=payload)
        print(response.json())
    except Exception as e:
        print(f"Account recovery error: {e}")

def wallet_menu(username, master_password):
    while True:
        print("\n=== WALLET VAULT ===")
        print("1. Add Wallet")
        print("2. View Wallet")
        print("3. List All Wallets")
        print("4. Return to Main Menu")
        choice = input("Enter your choice: ")
        if choice == '1':
            wallet_name = get_secure_input("Enter wallet name:")
            if wallet_name is None:
                continue
            print("If no username exists, enter '0'")
            w_username = get_secure_input("Enter wallet username:")
            if w_username is None:
                continue
            print("If no password exists, enter '0'")
            w_password = get_secure_input("Enter wallet password (or type 'gen' to auto-generate):", is_password=True)
            if w_password is None:
                continue
            print("If no recovery phrase exists, enter '0'")
            recovery_phrase = get_secure_input("Enter recovery phrase:")
            if recovery_phrase is None:
                continue
            pin = get_secure_input("Enter PIN:", is_password=True)
            if pin is None:
                continue
            payload = {
                "username": username,
                "master_password": master_password,
                "wallet_name": wallet_name,
                "w_username": w_username,
                "w_password": w_password,
                "recovery_phrase": recovery_phrase,
                "pin": pin
            }
            try:
                response = requests.post(f"{API_URL}/add_wallet", json=payload)
                print(response.json())
            except Exception as e:
                print(f"Error adding wallet: {e}")
        elif choice == '2':
            wallet_name = get_secure_input("Enter wallet name:")
            if wallet_name is None:
                continue
            pin = get_secure_input("Enter PIN:", is_password=True)
            if pin is None:
                continue
            payload = {
                "username": username,
                "master_password": master_password,
                "wallet_name": wallet_name,
                "pin": pin
            }
            try:
                response = requests.post(f"{API_URL}/get_wallet", json=payload)
                print(response.json())
            except Exception as e:
                print(f"Error retrieving wallet: {e}")
        elif choice == '3':
            params = {"username": username}
            try:
                response = requests.get(f"{API_URL}/get_all_wallets", params=params)
                print("Stored Wallets:")
                for wallet in response.json().get("wallets", []):
                    print(wallet)
            except Exception as e:
                print(f"Error listing wallets: {e}")
        elif choice == '4':
            break
        else:
            print("Invalid choice. Try again.")

def credentials_menu(username, master_password):
    while True:
        print("\n=== CREDENTIALS VAULT ===")
        print("1. Add Credentials")
        print("2. View Credentials")
        print("3. List All Sites")
        print("4. Return to Main Menu")
        choice = input("Enter your choice: ")
        if choice == '1':
            site = get_secure_input("Enter site:")
            if site is None:
                continue
            print("If no username exists, enter '0'")
            s_username = get_secure_input("Enter site username:")
            if s_username is None:
                continue
            print("If no password exists, enter '0'")
            s_password = get_secure_input("Enter site password (or type 'gen' to auto-generate):", is_password=True)
            if s_password is None:
                continue
            payload = {
                "username": username,
                "master_password": master_password,
                "site": site,
                "s_username": s_username,
                "s_password": s_password
            }
            try:
                response = requests.post(f"{API_URL}/add_credentials", json=payload)
                print(response.json())
            except Exception as e:
                print(f"Error adding credentials: {e}")
        elif choice == '2':
            site = get_secure_input("Enter site:")
            if site is None:
                continue
            payload = {
                "username": username,
                "master_password": master_password,
                "site": site
            }
            try:
                response = requests.post(f"{API_URL}/get_credentials", json=payload)
                print(response.json())
            except Exception as e:
                print(f"Error retrieving credentials: {e}")
        elif choice == '3':
            params = {"username": username}
            try:
                response = requests.get(f"{API_URL}/get_all_sites", params=params)
                print("Stored Sites:")
                for site in response.json().get("sites", []):
                    print(site)
            except Exception as e:
                print(f"Error listing sites: {e}")
        elif choice == '4':
            break
        else:
            print("Invalid choice. Try again.")

def documents_menu(username, master_password):
    while True:
        print("\n=== DOCUMENTS VAULT ===")
        print("1. Add Secure Document")
        print("2. View Document")
        print("3. List All Documents")
        print("4. Update Document")
        print("5. Delete Document")
        print("6. Return to Main Menu")
        choice = input("Enter your choice: ")
        if choice == '1':
            doc_name = get_secure_input("Enter document name:")
            if doc_name is None:
                continue
            doc_contents = get_secure_input("Enter document contents:")
            if doc_contents is None:
                continue
            payload = {
                "username": username,
                "master_password": master_password,
                "doc_name": doc_name,
                "doc_contents": doc_contents
            }
            try:
                response = requests.post(f"{API_URL}/add_secure_doc", json=payload)
                print(response.json())
            except Exception as e:
                print(f"Error adding document: {e}")
        elif choice == '2':
            doc_name = get_secure_input("Enter document name:")
            if doc_name is None:
                continue
            payload = {
                "username": username,
                "master_password": master_password,
                "doc_name": doc_name
            }
            try:
                response = requests.post(f"{API_URL}/get_secure_doc", json=payload)
                print(response.json())
            except Exception as e:
                print(f"Error viewing document: {e}")
        elif choice == '3':
            params = {"username": username}
            try:
                response = requests.get(f"{API_URL}/get_all_docs", params=params)
                print("Stored Documents:")
                for doc in response.json().get("documents", []):
                    print(doc)
            except Exception as e:
                print(f"Error listing documents: {e}")
        elif choice == '4':
            doc_name = get_secure_input("Enter document name to update:")
            if doc_name is None:
                continue
            new_contents = get_secure_input("Enter new contents:")
            if new_contents is None:
                continue
            payload = {
                "username": username,
                "master_password": master_password,
                "doc_name": doc_name,
                "new_contents": new_contents
            }
            try:
                response = requests.post(f"{API_URL}/update_secure_doc", json=payload)
                print(response.json())
            except Exception as e:
                print(f"Error updating document: {e}")
        elif choice == '5':
            doc_name = get_secure_input("Enter document name to delete:")
            if doc_name is None:
                continue
            payload = {
                "username": username,
                "doc_name": doc_name
            }
            try:
                response = requests.post(f"{API_URL}/delete_secure_doc", json=payload)
                print(response.json())
            except Exception as e:
                print(f"Error deleting document: {e}")
        elif choice == '6':
            break
        else:
            print("Invalid choice. Try again.")

def account_settings_menu(username, master_password):
    while True:
        print("\n=== ACCOUNT SETTINGS ===")
        print("1. Change Master Password")
        print("2. 2FA Settings")
        print("3. Delete All Data")
        print("4. Return to Main Menu")
        choice = input("Enter your choice: ")
        if choice == '1':
            new_password = get_secure_input("Enter new master password:", is_password=True)
            if new_password is None:
                continue
            confirm_password = get_secure_input("Confirm new master password:", is_password=True)
            if confirm_password is None:
                continue
            if new_password != confirm_password:
                print("Passwords don't match!")
                continue
            payload = {"username": username, "new_master_password": new_password}
            try:
                response = requests.post(f"{API_URL}/reset_master_password", json=payload)
                print(response.json())
                master_password = new_password
            except Exception as e:
                print(f"Error resetting password: {e}")
        elif choice == '2':
            while True:
                print("\n=== 2FA SETTINGS ===")
                print("1. Enable 2FA")
                print("2. Disable 2FA")
                print("3. Return to Account Settings")
                sub_choice = input("Enter your choice: ")
                if sub_choice == '1':
                    payload = {"username": username}
                    try:
                        response = requests.post(f"{API_URL}/enable_2fa", json=payload)
                        print(response.json())
                    except Exception as e:
                        print(f"Error enabling 2FA: {e}")
                elif sub_choice == '2':
                    payload = {"username": username}
                    try:
                        response = requests.post(f"{API_URL}/disable_2fa", json=payload)
                        print(response.json())
                    except Exception as e:
                        print(f"Error disabling 2FA: {e}")
                elif sub_choice == '3':
                    break
                else:
                    print("Invalid choice. Try again.")
        elif choice == '3':
            pin = get_secure_input("Enter PIN to confirm deletion:", is_password=True)
            if pin is None:
                continue
            payload = {"username": username, "pin": pin}
            try:
                response = requests.post(f"{API_URL}/delete_all_data", json=payload)
                print(response.json())
            except Exception as e:
                print(f"Error deleting all data: {e}")
        elif choice == '4':
            break
        else:
            print("Invalid choice. Try again.")

def main_menu():
    while True:
        print("\n=== SECURE ASF CLIENT ===")
        print("1. Login")
        print("2. Register")
        print("3. Recover Account")
        print("4. Exit")
        choice = input("Enter your choice: ")
        if choice == '1':
            creds = login()
            if creds[0]:
                user_menu(creds[0], creds[1])
        elif choice == '2':
            register_account()
        elif choice == '3':
            recover_account()
        elif choice == '4':
            print("Thank you for using SECURE ASF!")
            break
        else:
            print("Invalid choice. Try again.")

def user_menu(username, master_password):
    while True:
        print(f"\n=== SECURE ASF === (Logged in as {username})")
        print("1. Access Wallet Vault")
        print("2. Access Site Credentials Vault")
        print("3. Access Secure Documents Vault")
        print("4. Account Settings")
        print("5. Logout")
        choice = input("Enter your choice: ")
        if choice == '1':
            wallet_menu(username, master_password)
        elif choice == '2':
            credentials_menu(username, master_password)
        elif choice == '3':
            documents_menu(username, master_password)
        elif choice == '4':
            account_settings_menu(username, master_password)
        elif choice == '5':
            print("Logging out...")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main_menu()
