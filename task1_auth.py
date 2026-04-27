import os
import re
import hashlib
import time
import getpass

class UserAuth:
    def __init__(self, storage_file="users.txt"):
     self.storage_file = storage_file
     self.users = {}

    def load_users(self):
        if not os.path.exists(self.storage_file):  #  Load users from a plain text file.
            return

        try:
            with open(self.storage_file, "r") as file:
             for line in file:
              line = line.strip()
            if line:
              parts = line.split(",")
            if len(parts) == 3:
               username, salt, password_hash = parts
            self.users[username] = {
             "salt": salt,
             "password_hash": password_hash
            }
        except:
            print("Error reading user file.")

    def save_users(self):
      try:
            with open(self.storage_file, "w") as file:#Save users to a plain text file.
                for username, data in self.users.items():
                    file.write(username + "," + data["salt"] + "," + data["password_hash"] + "\n")
      except:
            print("Error saving user file.")

    def check_password_strength(self, password):
      
        if len(password) < 12:
            return False, "Password must be at least 12 characters long."    

        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter."

        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter."

        if not re.search(r"[0-9]", password):
            return False, "Password must contain at least one number."

        if not re.search(r"[^A-Za-z0-9]", password):
            return False, "Password must contain at least one special character."

        return True, "Password is strong enough."

    def hash_password(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        password_hash = hashlib.pbkdf2_hmac(  #Hash password with PBKDF2-HMAC-SHA256.
            "sha256",
            password.encode(),
            salt,
            100000
        )

        return salt.hex(), password_hash.hex()

    def add_user(self, username, password):
        if username in self.users:
            print("Username already exists.")
            return False

        valid, message = self.check_password_strength(password)
        if not valid:
            print(message)
            return False

        salt, password_hash = self.hash_password(password)
        self.users[username] = {
            "salt": salt,
            "password_hash": password_hash
        }

        self.save_users()
        print("Account created successfully.")
        return True

    def verify_password(self, username, password):
      
        if username not in self.users:        #Check entered password against stored password.
            return False

        salt = bytes.fromhex(self.users[username]["salt"])
        stored_hash = self.users[username]["password_hash"]

        _, new_hash = self.hash_password(password, salt)

        if new_hash == stored_hash:
            return True
        return False

    def login(self, username, password):
                                               #Login with 2-second delay only on failure
        if username not in self.users:
            time.sleep(2)
            return False, "Invalid username or password."

        if not self.verify_password(username, password):
            time.sleep(2)
            return False, "Invalid username or password."

        return True, "Login successful."


def main():
    auth = UserAuth()

    while True:
        print("\n--- Secure Authentication System ---")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            username = input("Enter username: ")
            password = getpass.getpass("Enter password: ")
            auth.add_user(username, password)

        elif choice == "2":
            username = input("Enter username: ")
            password = getpass.getpass("Enter password: ")
            success, message = auth.login(username, password)
            print(message)

        elif choice == "3":
            print("Exiting program.")
            break

        else:
            print("Invalid choice. Please select 1, 2, or 3.")


if __name__ == "__main__":
    main()