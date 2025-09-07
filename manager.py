import os
import re
import hashlib
import json
import getpass
from sys import exit
from colorama import Fore
from cryptography.fernet import Fernet
from tabulate import tabulate

Fernet_Key = ""

def main():
    print(Fore.BLUE + "Welcome to CLI Password Manager!\n" + Fore.RESET)
    master_authentication()
    cli_run()
    print(Fore.BLUE + "\nClosing." + Fore.RESET)


# function that just displays the cli and uses match to call other funcs
def cli_run():
    while True:
        while True:
            try:
                choice = int(input(Fore.BLUE + "1. Add Password\n" \
                                "2. View Passwords\n" \
                                "3. Search\n" \
                                "4. Update\n" \
                                "5. Delete\n" \
                                "6. Exit\n" \
                                " > " + Fore.RESET))
                if 0 < choice < 7:
                    break
                raise ValueError()
            except ValueError:
                print(Fore.RED + "\nInvalid User Input." + Fore.RESET)

        match choice:
            case 1:
                add_password()
            case 2:
                view_passwords()
            case 3:
                search_json()
            case 4:
                update_json()
            case 5:
                delete_data()
            case 6:
                return
            case _:
                print(Fore.MAGENTA + "Congrats, You unlocked a impossible error!" + Fore.RESET)

        print()

# function to add passwords in json
def add_password():
    f = Fernet(Fernet_Key) # fernet instance 

    service = input(Fore.BLUE + "\nEnter service: " + Fore.RESET).strip().lower()
    username = input(Fore.BLUE + "Enter username: " + Fore.RESET).strip()
    password = getpass.getpass(Fore.BLUE + "Enter password: " + Fore.RESET).strip()

    if (not service) or (not username) or (not password):
        print(Fore.RED + "\nInformation cannot be empty." + Fore.RESET)
        return

    if not (match := re.search(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\._@#$!%^&*])[A-Za-z\d\._@#$!%^&*]{8,}$", password)):
        print(Fore.MAGENTA + "\nYour password may be too weak and can be at a risk of being compromised, Suggested to update it!" + Fore.RESET)

    encrypted_password = f.encrypt(password.encode())
    encrypted_password_str = encrypted_password.decode() # because json doesnt accept bytes and it should be a str, i think json library should get updated 

    if os.path.exists("info/vault.json"):
        with open("info/vault.json", "r") as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                data = {}
    else:
        data = {}

    data[service] = {
        "username": username,
        "password": encrypted_password_str
    }

    with open("info/vault.json", "w") as file:
        json.dump(data, file, indent = 4)

    print(Fore.GREEN + "Content successfully saved." + Fore.RESET)

# function to view passwords
def view_passwords():
    data = empty_vault_check()

    encrypted_data = []

    confirmation(input(Fore.BLUE + "\nFor Security purposes, Enter your password: " + Fore.RESET).strip())
    
    for key, value in data.items():
        encrypted_data.append({"service": key, "username": value["username"], "password": decrypt_password(value["password"])})

    print(Fore.GREEN + "\nYour Credentials: \n" + Fore.RESET)
    print(tabulate(encrypted_data, headers = "keys", tablefmt = "grid"))

# function to search for data and display it
def search_json():
    data = empty_vault_check()
    encrypted_data = []

    confirmation(input(Fore.BLUE + "\nFor Security purposes, Enter your password: " + Fore.RESET).strip())

    while True:
        search = input(Fore.BLUE + "\nSearch value: " + Fore.RESET).strip().lower()
        if search:
            break
        print(Fore.RED + "Search value cannot be empty." + Fore.RESET)

    for key, value in data.items():
        decrypted_password = decrypt_password(value["password"])
        if search == key.lower() or search == value["username"].lower() or search == decrypted_password.lower():
            encrypted_data.append({"service": key, "username": value["username"], "password": decrypt_password(value["password"])})

    if len(encrypted_data) == 0:
        print(Fore.RED + "Search Results: 0" + Fore.RESET)
        return
    print(Fore.GREEN + f"\nSearch Results : {len(encrypted_data)}\n" + Fore.RESET)
    print(tabulate(encrypted_data, headers = "keys", tablefmt = "grid"))

def update_json():
    f = Fernet(Fernet_Key)
    data = empty_vault_check()
    encrypted_data = []

    confirmation(input(Fore.BLUE + "\nFor Security purposes, Enter your password: " + Fore.RESET).strip())

    keys = list(data.keys())

    for key in keys:
        encrypted_data.append({
            "service": key,
            "username": data[key]["username"],
            "password": decrypt_password(data[key]["password"])
        })

    print(Fore.BLUE + "\nYour Credentials: \n" + Fore.RESET)
    print(tabulate(encrypted_data, headers="keys", tablefmt="grid"))

    while True:
        try:
            row = int(input(Fore.BLUE + "\nWhich row would you like to update: " + Fore.RESET))
            if 1 <= row <= len(keys):
                break
            print(Fore.RED + f"\nNumber must be between 1 and {len(keys)}.\n" + Fore.RESET)
        except ValueError:
            print(Fore.RED + "\nEnter an integer value.\n" + Fore.RESET)

    # Input new data
    new_service = input(Fore.BLUE + "\nEnter new service name: " + Fore.RESET).strip().lower()
    new_username = input(Fore.BLUE + "Enter new username: " + Fore.RESET).strip()
    new_password = getpass.getpass(Fore.BLUE + "Enter new password: " + Fore.RESET).strip()

    if not new_service or not new_username or not new_password:
        print(Fore.RED + "\nInformation cannot be empty." + Fore.RESET)
        return

    if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\._@#$!%^&*])[A-Za-z\d\._@#$!%^&*]{8,}$", new_password):
        print(Fore.MAGENTA + "\nYour password may be too weak and can be at risk of being compromised. Suggested to update it!" + Fore.RESET)

    encrypted_password = f.encrypt(new_password.encode()).decode()

    # Perform the update
    old_service = keys[row - 1]
    del data[old_service]  # Remove the old entry
    data[new_service] = {
        "username": new_username,
        "password": encrypted_password
    }

    # Save updated data
    with open("info/vault.json", "w") as file:
        json.dump(data, file, indent=4)

    print(Fore.GREEN + f"\n✔ Successfully updated entry '{old_service}' → '{new_service}'.\n" + Fore.RESET)


def delete_data():
    data = empty_vault_check()
    encrypted_data = []

    confirmation(input(Fore.BLUE + "\nFor Security purposes, Enter your password: " + Fore.RESET).strip())

    keys = list(data.keys())

    for key in keys:
        encrypted_data.append({
            "service": key,
            "username": data[key]["username"],
            "password": decrypt_password(data[key]["password"])
        })

    print(Fore.BLUE + "\nYour Credentials: \n" + Fore.RESET)
    print(tabulate(encrypted_data, headers="keys", tablefmt="grid"))

    while True:
        try:
            row = int(input(Fore.BLUE + "\nWhich row would you like to delete: " + Fore.RESET))
            if 1 <= row <= len(keys):
                break
            print(Fore.RED + f"\nNumber must be between 1 and {len(keys)}.\n" + Fore.RESET)
        except ValueError:
            print(Fore.RED + "\nEnter an integer value.\n" + Fore.RESET)

    service_to_delete = keys[row - 1]
    del data[service_to_delete]

    with open("info/vault.json", "w") as file:
        json.dump(data, file, indent=4)

    print(Fore.GREEN + f"\n✔ Successfully deleted '{service_to_delete}'.\n" + Fore.RESET)


# function to make sure the data is not empty
def  empty_vault_check():
    try:
        with open("info/vault.json") as file:
            if os.path.getsize("info/vault.json") == 0:
                print(Fore.RED + "\nData Storage is empty.\n" + Fore.RESET)
                cli_run()
            data = json.load(file)
            return data
    except FileNotFoundError:
        print(Fore.RED + "Data storage is empty.\n" + Fore.RESET)
        cli_run()

# function to encrypted password
def decrypt_password(data):
    f = Fernet(Fernet_Key)
    try:
        return f.decrypt(data.encode("utf-8")).decode()
    except Exception as e:
        print(Fore.RED + f"[Error] Failed to decrypt password: {e}" + Fore.RESET)
        return "[Decryption Failed]"

# function to create or login password depends on whether password is already saved or not
def master_authentication():
    try:
        generate_fernet()
        with open("info/.masterclass") as file:
            hashed_password = get_hash(input(Fore.BLUE + "Enter Master Password: " + Fore.RESET).strip())
            for row in file:
                if hashed_password == row.strip():
                    print(Fore.GREEN + "✔ Access granted\n" + Fore.RESET)
                    return
                exit(Fore.RED + "✖ Access Denied" + Fore.RESET)
    except FileNotFoundError: 
        create_password()
        
# func to confirm password
def confirmation(password):
    if not password:
        exit(Fore.RED + "Wrong password <Safety_Logout>" + Fore.RESET)
    hashed_password = get_hash(password)
    with open("info/.masterclass") as file:
        for row in file:
            if hashed_password == row.strip():
                return
            else:
                exit(Fore.RED + "Wrong password <Safety_Logout>" + Fore.RESET)

# function to convert passsword to hexdigest hash
def get_hash(password):
    hash_object = hashlib.sha256(password.encode("utf-8"))
    return hash_object.hexdigest()

# function to create password, hash it and save it
def create_password():
    while True:
        print(Fore.BLUE + " > New Session" + Fore.RESET)
        password = input(Fore.BLUE + "Setup your master passoword: " + Fore.RESET).strip()
        if authenticate := re.search(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\._@#$!%^&*])[A-Za-z\d\._@#$!%^&*]{8,}$", password):
            hashed_password = get_hash(password)
            with open("info/.masterclass", "w") as file:
                file.write(hashed_password)
            print(Fore.GREEN + "\nPassword Saved." + Fore.RESET)
            exit(Fore.GREEN + "Restart Password Manager." + Fore.RESET)
            break
        print(Fore.RED + "\nPassword must consist of atleast one lower cased character, one upper cased character, one digit, one special character and total of 8 characters.\n" + Fore.RESET)

# function to assign the fernet key or generate it if it does not exist
def generate_fernet():
    global Fernet_Key
    try:
        with open("info/fernet.key", "rb") as file: 
            if os.path.getsize("info/fernet.key") == 0:
                raise FileNotFoundError()
            Fernet_Key = file.read().strip()
    except FileNotFoundError: # assumes its users first time so it creates the file and imports the fernet key in it
        Fernet_Key = Fernet.generate_key()
        with open("info/fernet.key", "wb") as file:
            file.write(Fernet_Key)

if __name__ == "__main__":
    main()