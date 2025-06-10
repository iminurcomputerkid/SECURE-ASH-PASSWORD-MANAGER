import requests
from requests.exceptions import HTTPError

from config import API_URL          # from config
from utils import get_secure_input  # get_secure_input from utils


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