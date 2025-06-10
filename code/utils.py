import getpass

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