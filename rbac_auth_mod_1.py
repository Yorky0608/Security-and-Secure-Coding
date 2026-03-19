"RBAC schedule app"


from __future__ import annotations

from dataclasses import dataclass


ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"  # demo-only

"Stores the users, their passwords, and roles along with the schedule"
@dataclass(frozen=True)
class AuthenticatedUser:
    username: str
    role: str  # "admin" or "user"


def build_initial_state() -> tuple[dict[str, dict[str, str]], list[str]]:
    users = {
        ADMIN_USERNAME: {"password": ADMIN_PASSWORD, "role": "admin"},
        "user": {"password": "password", "role": "user"},
    }

    schedule = [
        "Mon 09:00 - Team standup",
        "Wed 14:00 - Project work session",
        "Fri 16:00 - Weekly review",
    ]
    return users, schedule

"""
Allows the user to login
If user is admin, they can view and edit the schedule and create new users.
If user is a regular user, they can only view the schedule.
"""
def login(users: dict[str, dict[str, str]]) -> AuthenticatedUser:
    username = input("Username: ").strip()
    password = input("Password: ")

    record = users.get(username)
    if not record or record.get("password") != password:
        raise ValueError("Invalid username or password")
    role = record.get("role", "user")
    if role not in {"admin", "user"}:
        role = "user"
    return AuthenticatedUser(username=username, role=role)


def print_schedule(schedule: list[str]) -> None:
    print("\nSchedule")
    print("--------")
    if not schedule:
        print("(empty)")
        return
    for idx, item in enumerate(schedule, start=1):
        print(f"{idx}. {item}")


def prompt_int(prompt: str, *, min_value: int, max_value: int) -> int:
    while True:
        raw = input(prompt).strip()
        try:
            value = int(raw)
        except ValueError:
            print("Enter a number.")
            continue
        if value < min_value or value > max_value:
            print(f"Enter a number between {min_value} and {max_value}.")
            continue
        return value


def admin_edit_schedule(schedule: list[str]) -> None:
    while True:
        print_schedule(schedule)
        print("\nAdmin options")
        print("-------------")
        print("1) Add item")
        print("2) Edit item")
        print("3) Delete item")
        print("4) Return")
        choice = input("Choose: ").strip()

        if choice == "1":
            new_item = input("New schedule line: ").strip()
            if new_item:
                schedule.append(new_item)
            else:
                print("No change (empty input).")

        elif choice == "2":
            if not schedule:
                print("Schedule is empty.")
                continue
            idx = prompt_int("Item number to edit: ", min_value=1, max_value=len(schedule))
            updated = input("Updated line: ").strip()
            if updated:
                schedule[idx - 1] = updated
            else:
                print("No change (empty input).")

        elif choice == "3":
            if not schedule:
                print("Schedule is empty.")
                continue
            idx = prompt_int("Item number to delete: ", min_value=1, max_value=len(schedule))
            removed = schedule.pop(idx - 1)
            print(f"Removed: {removed}")

        elif choice == "4":
            return
        else:
            print("Invalid choice.")


def admin_create_user(users: dict[str, dict[str, str]]) -> None:
    print("\nCreate user")
    print("-----------")
    while True:
        username = input("New username: ").strip()
        if not username:
            print("Username cannot be empty.")
            continue
        if username in users:
            print("That username already exists.")
            continue
        if username == ADMIN_USERNAME:
            print("That username is reserved.")
            continue
        break

    password = input("New password: ")
    users[username] = {"password": password, "role": "user"}
    print(f"Created user: {username}")


def user_menu(user: AuthenticatedUser, users: dict[str, dict[str, str]], schedule: list[str]) -> None:
    while True:
        print(f"\nLogged in as: {user.username} ({user.role})")
        print("1) View schedule")
        print("2) Logout")
        print("3) Exit")
        choice = input("Choose: ").strip()
        if choice == "1":
            print_schedule(schedule)
        elif choice == "2":
            return
        elif choice == "3":
            raise SystemExit(0)
        else:
            print("Invalid choice.")


def admin_menu(user: AuthenticatedUser, users: dict[str, dict[str, str]], schedule: list[str]) -> None:
    while True:
        print(f"\nLogged in as: {user.username} ({user.role})")
        print("1) View schedule")
        print("2) Edit schedule")
        print("3) Create user")
        print("4) Logout")
        print("5) Exit")
        choice = input("Choose: ").strip()
        if choice == "1":
            print_schedule(schedule)
        elif choice == "2":
            admin_edit_schedule(schedule)
        elif choice == "3":
            admin_create_user(users)
        elif choice == "4":
            return
        elif choice == "5":
            raise SystemExit(0)
        else:
            print("Invalid choice.")

"Automatically runs the app when executed"
def main() -> None:
    users, schedule = build_initial_state()
    print("RBAC Schedule App (bare-bones)")
    print("------------------------------")
    print(f"Demo accounts: admin/{ADMIN_PASSWORD} and user/password\n")

    while True:
        try:
            user = login(users)
        except ValueError as e:
            print(str(e))
            continue

        if user.role == "admin":
            admin_menu(user, users, schedule)
        else:
            user_menu(user, users, schedule)


if __name__ == "__main__":
    main()
