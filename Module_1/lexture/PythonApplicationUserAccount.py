import hashlib
import os
import json
import base64

USER_FILE = "users.json"
users = {}
VALID_ROLES = {"admin", "user"}

# -----------------------------
# Helper Functions
# -----------------------------
def hash_with_salt(password, salt):
    return hashlib.sha256(salt + password.encode()).hexdigest()

def encode_salt(salt):
    return base64.b64encode(salt).decode('utf-8')

def decode_salt(salt_str):
    return base64.b64decode(salt_str.encode('utf-8'))

"""Detecting whether or not the user input is blank and prompting them to try again if it is."""
def prompt_non_empty(prompt_text):
    while True:
        value = input(prompt_text).strip()
        if value:
            return value
        print("Input cannot be blank. Please try again.")

def prompt_role(prompt_text="Enter role (admin/user): "):
    role = input(prompt_text).strip().lower()
    if role not in VALID_ROLES:
        print("Invalid role. Defaulting to 'user'.")
        return "user"
    return role

def prompt_menu_choice(valid_choices):
    while True:
        choice = input(f"Enter choice ({'/'.join(sorted(valid_choices))}): ").strip()
        if choice in valid_choices:
            return choice
        print("Invalid choice. Please try again.")

# -----------------------------
# File Operations
# -----------------------------
def load_users():
    global users
    if not os.path.exists(USER_FILE):
        print("No existing user file found. Starting fresh.")
        return
    """Checking to make sure the file is valid JSON and can be read, otherwise it will start with an empty user list."""
    try:
        with open(USER_FILE, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Could not read '{USER_FILE}'. Starting fresh. ({exc})")
        return

    loaded = 0
    for username, info in data.items():
        """Making sure the user entry has the required fields and that the role is valid, otherwise it will skip that entry."""
        try:
            users[username] = {
                "salt": decode_salt(info["salt"]),
                "hash": info["hash"],
                "role": info.get("role", "user")
            }
            if users[username]["role"] not in VALID_ROLES:
                users[username]["role"] = "user"
            loaded += 1
        except Exception:
            # Skip malformed entries rather than crashing.
            continue
    print(f"Loaded {len(users)} user(s) from file.")

def save_users():
    data = {}
    for username, info in users.items():
        data[username] = {
            "salt": encode_salt(info["salt"]),
            "hash": info["hash"],
            "role": info["role"]
        }
    with open(USER_FILE, "w") as f:
        json.dump(data, f, indent=4)
    print("User data saved to file.")

# -----------------------------
# Core Functionality
# -----------------------------
def register_user():
    username = prompt_non_empty("Enter new username: ")
    if username in users:
        print(f"User '{username}' already exists.")
        return
    password = prompt_non_empty("Enter password: ")
    role = prompt_role()
    salt = os.urandom(16)
    password_hash = hash_with_salt(password, salt)
    users[username] = {
        "salt": salt,
        "hash": password_hash,
        "role": role
    }
    print(f"User '{username}' registered successfully.")

def list_users():
    if not users:
        print("No users registered.")
        return
    print("\nCurrent users (salt & hash shown, passwords hidden):")
    for username, info in users.items():
        print(f"{username}:")
        print(f"  salt: {encode_salt(info['salt'])}")
        print(f"  hash: {info['hash']}")
        print(f"  role: {info['role']}")
    print()

def validate_user():
    username = prompt_non_empty("Enter username to validate: ")
    password = prompt_non_empty("Enter password to check: ")
    if username not in users:
        print("Invalid Credentials!!!")
        return
    salt = users[username]["salt"]
    stored_password_hash = users[username]["hash"]
    password_hash = hash_with_salt(password, salt)
    if password_hash == stored_password_hash:
        print("Password correct!")
        if users[username]["role"] == "admin":
            print("Access: admin panel allowed.")
        else:
            print("Access: standard user privileges.")
    else:
        print("Invalid Credentials!!!")

# -----------------------------
# Main Program Loop
# -----------------------------
def main():
    load_users()
    """Incase of a keyboard interrupt, the program will save the user data before exiting."""
    try:
        while True:
            print("\n--- Secure Auth System ---")
            print("1. Create a new user")
            print("2. List users")
            print("3. Validate a user's password")
            print("4. Exit")
            choice = prompt_menu_choice({"1", "2", "3", "4"})
            if choice == "1":
                register_user()
            elif choice == "2":
                list_users()
            elif choice == "3":
                validate_user()
            else:
                save_users()
                print("Exiting program.")
                break
    except KeyboardInterrupt:
        print("\nInterrupted. Saving user data...")
        save_users()

if __name__ == "__main__":
    main()
