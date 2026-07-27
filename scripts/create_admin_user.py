"""
One-time CLI script to create the first admin user account.

Usage:
    python scripts/create_admin_user.py <username> <email>

You will be prompted for a password (not shown on screen).
"""

import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.auth import hash_password
from src.database.db_manager import DatabaseManager
from src.utils import Config


def main():
    if len(sys.argv) != 3:
        print("Usage: python scripts/create_admin_user.py <username> <email>")
        sys.exit(1)

    username = sys.argv[1]
    email = sys.argv[2]

    password = getpass.getpass("Password: ")
    password_confirm = getpass.getpass("Confirm password: ")

    if password != password_confirm:
        print("Error: passwords do not match")
        sys.exit(1)

    if len(password) < 8:
        print("Error: password must be at least 8 characters")
        sys.exit(1)

    config = Config('config/config.yaml')
    db = DatabaseManager(config.get('database.path', 'data/db/threats.db'))

    existing = db.get_user_by_username(username)
    if existing:
        print(f"Error: user '{username}' already exists")
        sys.exit(1)

    user_id = db.create_user(username, email, hash_password(password))
    print(f"Created user '{username}' (ID: {user_id})")


if __name__ == '__main__':
    main()
