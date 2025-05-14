import requests
import getpass
from requests.exceptions import HTTPError

API_URL = "https://secure-asf-password-manager.onrender.com"

def get_secure_input(prompt, is_password=False):
    while True:
        if is_password:
            user_input = getpass.getpass(f"{prompt} (Type 'esc' to go back): ")
        else:
            user_input = input(f"{prompt} (Type 'esc' to go back): ")
        if user_input.lower() == 'esc':
            return None
        if user_input:
            return user_input

def register_account():
    print("\n=== SECURE ASF PASSWORD MANAGER ===")
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
        response.raise_for_status()
        print(response.json())
    except HTTPError:
        print("Registration failed: please check your inputs or try again later.")
    except Exception as e:
        print(f"Registration error: {e}")

def login():
    print("\n=== SECURE ASF PASSW MANAGER ===")
    print("Login")
    username = get_secure_input("Enter username:")
    if username is None:
        return None, None

    # initial prompt
    master_password = get_secure_input("Enter master password:", is_password=True)
    if master_password is None:
        return None, None

    payload = {
        "username": username,
        "master_password": master_password
        # totp_code and recovery_pin will be added if needed
    }

    while True:
        try:
            resp = requests.post(f"{API_URL}/login", json=payload)
        except Exception as e:
            print(f"Login error: {e}")
            return None, None

        # 1) Wrong password → 401
        if resp.status_code == 401:
            print("Invalid username or password. Try again.")
            master_password = get_secure_input("Enter master password:", is_password=True)
            if master_password is None:
                return None, None
            payload["master_password"] = master_password
            continue

        # 2) Locked out / PIN / TOTP → 403
        if resp.status_code == 403:
            detail = resp.json().get("detail", "").lower()

            if "invalid recovery pin" in detail or "recovery pin" in detail:
                # 6th+ wrong → need PIN
                recovery_pin = get_secure_input("Enter recovery PIN:", is_password=True)
                if recovery_pin is None:
                    return None, None
                payload["recovery_pin"] = recovery_pin
                continue

            elif "invalid or missing totp" in detail or "2fa" in detail:
                # 2FA required
                print("Two-factor authentication required.")
                totp_code = get_secure_input("Enter 2FA code:")
                if totp_code is None:
                    return None, None
                payload["totp_code"] = totp_code
                continue

            else:
                # e.g. “User locked out. Try again in XXX seconds.”
                print(detail)
                return None, None

        # 3) Success!
        if resp.ok:
            data = resp.json()
            if data.get("message", "").lower() == "login successful":
                return username, master_password
            else:
                print("Login failed:", data.get("detail", data))
                return None, None

        # any other status
        print(f"Unexpected response {resp.status_code}: {resp.text}")
        return None, None


def wallet_menu(username, master_password):
    while True:
        print("\n=== WALLET VAULT ===")
        print("1. Add Wallet")
        print("2. View Wallet")
        print("3. List All Wallets")
        print("4. Delete Wallet")
        print("5. Return to Main Menu")
        choice = input("Enter your choice: ")

        if choice == '1':
            wallet_name = get_secure_input("Enter wallet name:")
            if wallet_name is None:
                continue
            w_username = get_secure_input("Enter wallet username (or '0'):")
            if w_username is None:
                continue
            w_password = get_secure_input("Enter wallet password (or 'gen'):", is_password=True)
            if w_password is None:
                continue
            recovery_phrase = get_secure_input("Enter recovery phrase (or '0'):")
            if recovery_phrase is None:
                continue
            pin = get_secure_input("Enter recovery PIN:", is_password=True)
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
                resp = requests.post(f"{API_URL}/add_wallet", json=payload)
                resp.raise_for_status()
                print(resp.json())
            except HTTPError:
                print("Error adding wallet: check your inputs.")
            except Exception as e:
                print(f"Error adding wallet: {e}")

        elif choice == '2':
            wallet_name = get_secure_input("Enter wallet name:")
            if wallet_name is None:
                continue
            pin = get_secure_input("Enter recovery PIN:", is_password=True)
            if pin is None:
                continue

            payload = {
                "username": username,
                "master_password": master_password,
                "wallet_name": wallet_name,
                "pin": pin
            }
            try:
                resp = requests.post(f"{API_URL}/get_wallet", json=payload)
                resp.raise_for_status()
                print(resp.json())
            except HTTPError:
                print("Error retrieving wallet: invalid credentials or PIN.")
            except Exception as e:
                print(f"Error retrieving wallet: {e}")

        elif choice == '3':
            try:
                resp = requests.post(f"{API_URL}/get_all_wallets", json={"username": username})
                resp.raise_for_status()
                print("Stored Wallets:")
                for w in resp.json().get("wallets", []):
                    print(" -", w)
            except HTTPError:
                print("Error listing wallets.")
            except Exception as e:
                print(f"Error listing wallets: {e}")

        elif choice == '4':
            wallet_name = get_secure_input("Enter wallet name to delete:")
            if wallet_name is None:
                continue
            payload = {"username": username, "wallet_name": wallet_name}
            try:
                resp = requests.post(f"{API_URL}/delete_wallet", json=payload)
                resp.raise_for_status()
                print(resp.json())
            except HTTPError:
                print("Error deleting wallet.")
            except Exception as e:
                print(f"Error deleting wallet: {e}")

        elif choice == '5':
            break
        else:
            print("Invalid choice. Try again.")

def credentials_menu(username, master_password):
    while True:
        print("\n=== CREDENTIALS VAULT ===")
        print("1. Add Credentials")
        print("2. View Credentials")
        print("3. List All Sites")
        print("4. Delete Credentials")
        print("5. Return to Main Menu")
        choice = input("Enter your choice: ")

        if choice == '1':
            site = get_secure_input("Enter site:")
            if site is None:
                continue
            s_username = get_secure_input("Enter site username (or '0'):")
            if s_username is None:
                continue
            s_password = get_secure_input("Enter site password (or 'gen'):", is_password=True)
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
                resp = requests.post(f"{API_URL}/add_credentials", json=payload)
                resp.raise_for_status()
                print(resp.json())
            except HTTPError:
                print("Error adding credentials.")
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
                resp = requests.post(f"{API_URL}/get_credentials", json=payload)
                resp.raise_for_status()
                print(resp.json())
            except HTTPError:
                print("Error retrieving credentials.")
            except Exception as e:
                print(f"Error retrieving credentials: {e}")

        elif choice == '3':
            try:
                resp = requests.post(f"{API_URL}/get_all_sites", json={"username": username})
                resp.raise_for_status()
                print("Stored Sites:")
                for s in resp.json().get("sites", []):
                    print(" -", s)
            except HTTPError:
                print("Error listing sites.")
            except Exception as e:
                print(f"Error listing sites: {e}") 

        elif choice == '4':
            site = get_secure_input("Enter site to delete:")
            if site is None:
                continue
            payload = {"username": username, "site": site}
            try:
                resp = requests.post(f"{API_URL}/delete_credentials", json=payload)
                resp.raise_for_status()
                print(resp.json())
            except HTTPError:
                print("Error deleting credentials.")
            except Exception as e:
                print(f"Error deleting credentials: {e}")

        elif choice == '5':
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
                resp = requests.post(f"{API_URL}/add_secure_doc", json=payload)
                resp.raise_for_status()
                print(resp.json())
            except HTTPError:
                print("Error adding document.")
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
                resp = requests.post(f"{API_URL}/get_secure_doc", json=payload)
                resp.raise_for_status()
                print(resp.json())
            except HTTPError:
                print("Error viewing document.")
            except Exception as e:
                print(f"Error viewing document: {e}")

        elif choice == '3':
            try:
                resp = requests.get(f"{API_URL}/get_all_docs", params={"username": username})
                resp.raise_for_status()
                print("Stored Documents:")
                for d in resp.json().get("documents", []):
                    print(" -", d)
            except HTTPError:
                print("Error listing documents.")
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
                resp = requests.post(f"{API_URL}/update_secure_doc", json=payload)
                resp.raise_for_status()
                print(resp.json())
            except HTTPError:
                print("Error updating document.")
            except Exception as e:
                print(f"Error updating document: {e}")

        elif choice == '5':
            doc_name = get_secure_input("Enter document name to delete:")
            if doc_name is None:
                continue

            payload = {"username": username, "doc_name": doc_name}
            try:
                resp = requests.post(f"{API_URL}/delete_secure_doc", json=payload)
                resp.raise_for_status()
                print(resp.json())
            except HTTPError:
                print("Error deleting document.")
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
            old_password = get_secure_input("Enter current master password:", is_password=True)
            if old_password is None:
                continue
            new_password = get_secure_input("Enter new master password:", is_password=True)
            if new_password is None:
                continue
            confirm_password = get_secure_input("Confirm new master password:", is_password=True)
            if confirm_password is None or new_password != confirm_password:
                print("Passwords don't match!")
                continue

            payload = {
                "username": username,
                "old_master_password": old_password,
                "new_master_password": new_password
            }
            try:
                resp = requests.post(f"{API_URL}/reset_master_password", json=payload)
                resp.raise_for_status()
                print(resp.json())
                master_password = new_password
            except HTTPError:
                print("Error resetting password.")
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
                        resp = requests.post(f"{API_URL}/enable_2fa", json=payload)
                        resp.raise_for_status()
                        data = resp.json()
                        print("2FA enabled. Secret:", data.get("totp_secret"))
                        print("Provisioning URI:", data.get("provisioning_uri"))
                    except HTTPError:
                        print("Error enabling 2FA.")
                    except Exception as e:
                        print(f"Error enabling 2FA: {e}")

                elif sub_choice == '2':
                    pin = get_secure_input("Enter recovery PIN to disable 2FA:", is_password=True)
                    if pin is None:
                        continue
                    payload = {
                        "username": username,
                        "pin": pin
                    }
                    try:
                        resp = requests.post(f"{API_URL}/disable_2fa", json=payload)
                        resp.raise_for_status()
                        print(resp.json())
                    except HTTPError:
                        print("Error disabling 2FA: invalid recovery PIN.")
                    except Exception as e:
                        print(f"Error disabling 2FA: {e}")
                
                elif sub_choice == '3':
                    break

        elif choice == '3':
            pin = get_secure_input("Enter recovery PIN:", is_password=True)
            if pin is None:
                continue
            payload = {"username": username, "pin": pin}
            try:
                resp = requests.post(f"{API_URL}/delete_all_data", json=payload)
                resp.raise_for_status()
                print(resp.json())
            except HTTPError:
                print("Error deleting all data.")
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
        print("3. Exit")
        choice = input("Enter your choice: ")
        if choice == '1':
            creds = login()
            if creds[0]:
                user_menu(creds[0], creds[1])
        elif choice == '2':
            register_account()
        elif choice == '3':
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
