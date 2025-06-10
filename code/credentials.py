import requests
from requests.exceptions import HTTPError

from config import API_URL          
from utils import get_secure_input 

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
            pin = get_secure_input("Enter recovery PIN:", is_password=True)
            if pin is None:
                continue
            payload = {
                "username": username,
                "site": site,
                "pin": pin
            }
            try:
                resp = requests.post(f"{API_URL}/delete_credentials", json=payload)
                resp.raise_for_status()
                print(resp.json())
            except HTTPError:
                print("Error deleting credentials: invalid PIN.")
            except Exception as e:
                print(f"Error deleting credentials: {e}")

        elif choice == '5':
            break
        else:
            print("Invalid choice. Try again.")