# Password Manager:

## How It Works:
1. Encryption: The passwords are encrypted using the cryptography.Fernet symmetric encryption system. A key is generated and saved in a file (secret.key). This key is required for both encryption and decryption.
2. Password Generation: You can generate random passwords using the generate_password function.
3. Storing Passwords: When a password is generated or entered by the user, it's encrypted and stored in a CSV file (passwords.csv).
4. Viewing Passwords: Stored passwords are decrypted before being shown to the user.
5. File Security: Passwords are saved in a CSV file, and the contents are encrypted to ensure that even if the file is accessed, the passwords remain secure.

## Key Operations:
- Storing: When a password is stored, it is encrypted before being written to the CSV.
- Loading: When the stored passwords are viewed, they are decrypted using the saved encryption key.

## Example Interaction:
```
Password Manager
1. Generate a new password
2. Store a password
3. View stored passwords
4. Exit
Choose an option (1-4): 1
Generated Password: quick-4-flame-@dog-9-jumped

Password Manager
1. Generate a new password
2. Store a password
3. View stored passwords
4. Exit
Choose an option (1-4): 2
Enter the service name (e.g., 'Google'): Google
Enter the password to store (or leave empty to generate one): 

Password for Google stored successfully.

Password Manager
1. Generate a new password
2. Store a password
3. View stored passwords
4. Exit
Choose an option (1-4): 3

Stored Passwords:
Service: Google - Password: quick-4-flame-@dog-9-jumped
```