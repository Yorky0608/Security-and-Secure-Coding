from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class User:
	username: str
	role: str  # expected: "admin" or "user"


# Hardcoded "user database" (demo-only)
USERS: dict[str, User] = {
	"alice": User(username="alice", role="admin"),
	"bob": User(username="bob", role="user"),
}


"""
Simulates login using a hardcoded username.
Change LOGIN_AS to "alice" or "bob" to simulate different users.
"""
def login_simulation() -> User:
	LOGIN_AS = "alice"  # <-- change to "bob" to simulate a regular user
	return USERS[LOGIN_AS]


"""Protected action: only admins can access."""
def admin_only_action(current_user: User) -> None:
	if current_user.role != "admin":
		raise PermissionError("admin_only_action requires role=admin")
	print("[admin] Viewing admin-only report...")


"""Protected action: only regular users can access."""
def user_only_action(current_user: User) -> None:
	if current_user.role != "user":
		raise PermissionError("user_only_action requires role=user")
	print("[user] Viewing user-only dashboard...")


def main() -> None:
	current_user = login_simulation()
	print(f"Logged in as: {current_user.username} (role={current_user.role})")

	# Simulate two endpoints/routes/functions with access control.
	for action in (admin_only_action, user_only_action):
		try:
			action(current_user)
		except PermissionError as exc:
			print(f"DENIED: {exc}")


if __name__ == "__main__":
	main()
