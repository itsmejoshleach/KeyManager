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


# SSH Manager:
## How the Script Works:
1. Generate/Load Encryption Key: Similar to the password manager, the script generates or loads a key for encrypting SSH credentials.
2. Store SSH Credentials: The store_ssh_credentials function encrypts the SSH credentials (username, password, and private key) before storing them in a CSV file.
3. Load SSH Credentials: The load_ssh_credentials function retrieves the credentials from the CSV file and decrypts them.
4. SSH Connection: Using the paramiko library, the script can connect to an SSH server using either password authentication or private key authentication.
## Key Features:
- Encryption: All SSH credentials (username, password, private key) are encrypted before storing them in the CSV file using symmetric encryption (Fernet).
- Private Key Support: The script supports storing SSH private keys securely.
- SSH Connection: You can connect to remote servers using stored credentials (password or private key).
## Example Usage:
1. Storing SSH Credentials:
```
SSH Manager
1. Store SSH credentials
2. View stored SSH credentials
3. Connect to a server using SSH
4. Exit
Choose an option (1-4): 1
Enter the service name (e.g., 'MyServer'): MyServer
Enter the SSH username: myuser
Enter the SSH password (leave empty if using private key): 
Enter the path to your private key file: /path/to/private_key.pem
SSH credentials for MyServer stored successfully.
```

2. Viewing Stored SSH Credentials:
```
SSH Manager
1. Store SSH credentials
2. View stored SSH credentials
3. Connect to a server using SSH
4. Exit
Choose an option (1-4): 2

Stored SSH Credentials:
Service: MyServer, Username: myuser, Password: , Private Key: /path/to/private_key.pem
```

3. Connecting via SSH:

```
SSH Manager
1. Store SSH credentials
2. View stored SSH credentials
3. Connect to a server using SSH
4. Exit
Choose an option (1-4): 3
Enter the service name to connect to (e.g., 'MyServer'): MyServer
Connecting to MyServer using private key...
Connected to localhost successfully.
```

## Notes:
- Security: Be sure to securely store the encryption key (ssh_secret.key). If this key is lost or compromised, the stored SSH credentials cannot be decrypted.
- Private Key Management: Make sure the private keys are handled securely. The path to private key files is stored as text, but the contents are encrypted before being saved to the CSV.