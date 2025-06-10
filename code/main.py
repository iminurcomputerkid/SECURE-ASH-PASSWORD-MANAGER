from auth import login, register_account
from wallets import wallet_menu
from credentials import credentials_menu
from documents import documents_menu
from account_settings import account_settings_menu

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


