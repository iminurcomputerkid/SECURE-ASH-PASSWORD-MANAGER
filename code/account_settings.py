import requests
from requests.exceptions import HTTPError

from config import API_URL          
from utils import get_secure_input 

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