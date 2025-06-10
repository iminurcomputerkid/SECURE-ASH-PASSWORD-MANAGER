import requests
from requests.exceptions import HTTPError

from config import API_URL          
from utils import get_secure_input 

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
            pin = get_secure_input("Enter recovery PIN:", is_password=True)
            if pin is None:
                continue
            payload = {
                "username": username,
                "doc_name": doc_name,
                "pin": pin
            }
            try:
                resp = requests.post(f"{API_URL}/delete_secure_doc", json=payload)
                resp.raise_for_status()
                print(resp.json())
            except HTTPError:
                print("Error deleting document: invalid PIN.")
            except Exception as e:
                print(f"Error deleting document: {e}")

        elif choice == '6':
            break
        else:
            print("Invalid choice. Try again.")