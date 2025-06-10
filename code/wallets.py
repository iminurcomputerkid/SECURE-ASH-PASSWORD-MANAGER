import requests
from requests.exceptions import HTTPError

from config import API_URL          
from utils import get_secure_input 

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
            pin = get_secure_input("Enter recovery PIN:", is_password=True)
            if pin is None:
                continue
            payload = {
                "username": username,
                "wallet_name": wallet_name,
                "pin": pin
            }
            try:
                resp = requests.post(f"{API_URL}/delete_wallet", json=payload)
                resp.raise_for_status()
                print(resp.json())
            except HTTPError:
                print("Error deleting wallet: invalid PIN.")
            except Exception as e:
                print(f"Error deleting wallet: {e}")

        elif choice == '5':
            break
        else:
            print("Invalid choice. Try again.")
