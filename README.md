# CLI Password Manager

A secure command-line password manager built with Python that allows users to safely store, view, search, update, and delete passwords using encryption and hashing techniques.

## Features

- Master password authentication with SHA-256 hashing
- Password encryption using Fernet symmetric encryption
- Add, view, search, update, and delete service credentials
- Password strength validation to encourage secure passwords
- Secure storage in an encrypted JSON vault
- User-friendly command-line interface with clear prompts and messages

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/your-username/cli-password-manager.git
   cd cli-password-manager
Create a virtual environment (optional but recommended):

python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
Install dependencies:

pip install -r requirements.txt
Usage
Run the password manager:

python password_manager.py
On first run, you'll be prompted to set up a master password.

After authentication, use the menu to add, view, search, update, or delete your stored passwords.

For security, you will be asked to re-enter your master password before viewing, updating, or deleting passwords.

Security
Master password is hashed using SHA-256 and never stored in plaintext.

Passwords are encrypted with Fernet symmetric encryption before saving.

Password strength is validated to ensure secure credentials.

Sensitive operations require re-authentication.

File Structure
├── info/
│   ├── vault.json          # Encrypted password storage
│   ├── fernet.key          # Encryption key (auto-generated)
│   └── .masterclass        # Hashed master password (auto-generated)
├── password_manager.py     # Main application script
├── requirements.txt        # Python dependencies
└── README.md               # Project documentation
Dependencies
Python 3.7+

cryptography

colorama

tabulate

Install with:

pip install cryptography colorama tabulate
Or via requirements.txt:

nginx
Copy code
cryptography
colorama
tabulate
Contribution
Contributions are welcome! Feel free to open issues or submit pull requests for improvements or new features.

License
This project is licensed under the MIT License. See the LICENSE file for details.
