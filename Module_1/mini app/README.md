# Module 1 — Authentication + RBAC (Mini Demo)

This module contains a minimal Python script that demonstrates the core ideas of:

- **Authentication (simulated login)**: a hardcoded user is selected in code
- **Roles**: two roles (`admin` and `user`)
- **Access control**: protected functions that enforce role checks

## Run

To simulate a different login, edit `LOGIN_AS` in `rbac_and_auth_mini_app.py` and re-run.

## CIA triad note

This demo highlights **Confidentiality**: the script denies access to protected actions unless the logged-in user has the required role. That prevents admin-only information/actions from being exposed to regular users.
