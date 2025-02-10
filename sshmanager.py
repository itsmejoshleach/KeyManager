import random
import string
import os
import csv
import base64
from cryptography.fernet import Fernet
import paramiko

# Generate a key for encryption (you should securely store this key)
def generate_key():
    return Fernet.generate_key()

# Save the key to a file (if necessary)
def save_key(key, filename="ssh_secret.key"):
    with open(filename, "wb") as key_file:
        key_file.write(key)

# Load the key from a file
def load_key(filename="ssh_secret.key"):
    with open(filename, "rb") as key_file:
        return key_file.read()

# Encrypt a message (used for SSH credentials)
def encrypt_message(message, key):
    if message != None:
        fernet = Fernet(key)
        encrypted_message = fernet.encrypt(message.encode())
        # Convert the encrypted message to base64 string for CSV storage
        return base64.b64encode(encrypted_message).decode()
    else:
        return "None"    

# Decrypt a message (used for SSH credentials)
def decrypt_message(encrypted_message, key):
    if encrypted_message != "None":
        fernet = Fernet(key)
        encrypted_message = base64.b64decode(encrypted_message.encode())  # Decode from base64
        decrypted_message = fernet.decrypt(encrypted_message).decode()
        return decrypted_message
    else:
        return "None"

# Store SSH credentials into CSV
def store_ssh_credentials(username, password, private_key, public_key, hostname, service_name, key, filename="ssh_credentials.csv"):
    encrypted_username = encrypt_message(username, key)
    encrypted_password = encrypt_message(password, key)
    encrypted_private_key = encrypt_message(private_key, key)
    encrypted_public_key = encrypt_message(public_key, key)
    
    # Check if the file exists. If not, create it with headers
    if not os.path.exists(filename):
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Service', 'Username', 'Password', 'PrivateKey', 'PublicKey', 'Hostname'])

    # Append the new SSH credentials to the CSV file
    with open(filename, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([service_name, encrypted_username, encrypted_password, encrypted_private_key, encrypted_public_key, hostname])

# Load SSH credentials from CSV and decrypt them
def load_ssh_credentials(key, filename="ssh_credentials.csv"):
    credentials = []
    if os.path.exists(filename):
        with open(filename, 'r', newline='') as f:
            reader = csv.reader(f)
            next(reader)  # Skip header row
            for row in reader:
                service_name, encrypted_username, encrypted_password, encrypted_private_key, encrypted_public_key, hostname = row
                username = decrypt_message(encrypted_username, key)
                password = decrypt_message(encrypted_password, key)
                private_key = decrypt_message(encrypted_private_key, key)
                public_key = decrypt_message(encrypted_public_key, key)
                credentials.append((service_name, username, password, private_key, public_key, hostname))
    return credentials

# Generate SSH key pair (private and public keys)
def generate_ssh_key_pair(service_name):
    private_key_path = f"./ssh_private_keys/{service_name}"
    public_key_path = f"{private_key_path}.pub"
    
    # Ensure the directory exists
    os.makedirs(os.path.dirname(private_key_path), exist_ok=True)

    # Generate an RSA key pair
    private_key = paramiko.RSAKey.generate(2048)
    private_key.write_private_key_file(private_key_path)
    
    # Save public key
    public_key = private_key.get_name() + " " + private_key.get_base64()
    with open(public_key_path, 'w') as pub_file:
        pub_file.write(public_key)
    
    return private_key_path, public_key_path

# Function to establish an SSH connection using credentials (username/password or key)
def connect_ssh(username, password=None, private_key=None, hostname='localhost', port=22):
    try:
        # Initialize SSH client
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if private_key:
            # Use private key authentication
            key = paramiko.RSAKey.from_private_key_file(private_key)
            client.connect(hostname, port=port, username=username, pkey=key)
        else:
            # Use password authentication
            client.connect(hostname, port=port, username=username, password=password)

        print(f"Connected to {hostname} successfully.")
        client.close()
    except Exception as e:
        print(f"Error connecting to SSH: {e}")

# Read public key from a file
def read_public_key(service_name):
    public_key_path = f"./ssh_private_keys/{service_name}.pub"
    try:
        with open(public_key_path, 'r') as pub_file:
            return pub_file.read()
    except FileNotFoundError:
        print(f"Public key for {service_name} not found.")
        return None

# Function to upload the SSH public key to the server's authorized_keys
def upload_ssh_key_to_server(hostname, username, password, private_key, service_name):
    try:
        # Read public key
        public_key = read_public_key(service_name)
        if not public_key:
            print("No public key found to upload.")
            return

        # Connect to the server using password authentication
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, username=username, password=password)

        # Create the .ssh directory if it doesn't exist
        stdin, stdout, stderr = client.exec_command("mkdir -p ~/.ssh")
        stdin, stdout, stderr = client.exec_command("chmod 700 ~/.ssh")

        # Upload the public key to the authorized_keys file
        stdin, stdout, stderr = client.exec_command(f"echo '{public_key}' >> ~/.ssh/authorized_keys")
        stdin, stdout, stderr = client.exec_command("chmod 600 ~/.ssh/authorized_keys")

        print(f"Public key successfully uploaded to {hostname}.")
        client.close()

        # Test SSH connection using the uploaded key
        print("Testing connection using the uploaded key...")
        connect_ssh(username=username, private_key=private_key, hostname=hostname)

    except Exception as e:
        print(f"Error uploading SSH key to {hostname}: {e}")

def update_creds(username, password, private_key, public_key, hostname, service_name, key, filename="ssh_credentials.csv"): # Update SSH credentials in the CSV file based on service_name
    # Load all the existing credentials
    credentials = load_ssh_credentials(key, filename)

    # Flag to check if the service was found
    updated = False

    # Encrypt the new data to store in CSV
    encrypted_username = encrypt_message(username, key)
    encrypted_password = encrypt_message(password, key)
    encrypted_private_key = encrypt_message(private_key, key)
    encrypted_public_key = encrypt_message(public_key, key)

    # Open the CSV file to overwrite the data
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Service', 'Username', 'Password', 'PrivateKey', 'PublicKey', 'Hostname'])  # Write the header

        for row in credentials:
            service, current_username, current_password, current_private_key, current_public_key, current_hostname = row

            if service == service_name:
                # If the service_name matches, replace with the new credentials
                writer.writerow([service_name, encrypted_username, encrypted_password, encrypted_private_key, encrypted_public_key, hostname])
                updated = True
            else:
                # Keep the existing credentials for other services
                writer.writerow([service, current_username, current_password, current_private_key, current_public_key, current_hostname])

    if updated:
        print(f"Credentials for {service_name} have been updated successfully.")
    else:
        print(f"Service {service_name} not found. No changes made.")



# Main function
def main():
    # Load or generate a key for encryption
    if not os.path.exists("ssh_secret.key"):
        key = generate_key()
        save_key(key)
        print("Encryption key created and saved.")
    else:
        key = load_key()
    
    # Display menu for user interaction
    while True:
        print("\nSSH Manager")
        print("1. Store SSH credentials")
        print("2. View stored SSH credentials")
        print("3. Test connection to a server using SSH")
        print("4. List public key")
        print("5. Upload newly generated SSH Key and test key")
        print("6. Exit")
        
        choice = input("Choose an option (1-6): ")
        
        if choice == "1":
            # Store SSH credentials
            service_name = input("Enter the service name (e.g., 'MyServer'): ")
            username = input("Enter the SSH username: ")
            password = input("Enter the SSH password (leave empty if using private key): ")
            private_key = None
            hostname = input("Enter the hostname (e.g., 'example.com'): ")

            # Ask if the user wants to provide an existing private key
            private_key_choice = input("Do you want to provide an existing SSH private key? (yes/no): ").strip().lower()

            if private_key_choice == 'yes':
                private_key = input("Enter the path to your SSH private key: ")
                # Load the public key associated with the private key
                public_key = read_public_key(service_name)
            elif not password:
                # If no password, generate a new SSH key pair
                private_key, public_key = generate_ssh_key_pair(service_name)
            else:
                public_key = None

            store_ssh_credentials(username, password, private_key, public_key, hostname, service_name, key)
            print(f"SSH credentials for {service_name} stored successfully.")
        
        elif choice == "2":
            # View stored SSH credentials
            print("\nStored SSH Credentials:")
            credentials = load_ssh_credentials(key)
            if credentials:
                for service, username, password, private_key, public_key, hostname in credentials:
                    print(f"Service: {service}, Username: {username}, Password: {password}, Private Key: {private_key}, Public Key: {public_key}, Hostname: {hostname}")
            else:
                print("No SSH credentials stored.")
        
        elif choice == "3":
            # Connect to an SSH server
            service_name = input("Enter the service name to connect to (e.g., 'MyServer'): ")
            credentials = load_ssh_credentials(key)
            
            service_credentials = None
            for service, username, password, private_key, public_key, hostname in credentials:
                if service == service_name:
                    service_credentials = (username, password, private_key, hostname)
                    break
            
            if service_credentials:
                username, password, private_key, hostname = service_credentials
                if private_key != "None":
                    print(f"Connecting to {service_name} using private key...")
                    connect_ssh(username=username, private_key=private_key, hostname=hostname)
                else:
                    print(f"Connecting to {service_name} using password...")
                    connect_ssh(username=username, password=password, hostname=hostname)
            else:
                print(f"No credentials found for {service_name}.")
        
        elif choice == "4":
            # List public key
            service_name = input("Enter the service name to list the public key (e.g., 'MyServer'): ")
            public_key = read_public_key(service_name)
            if public_key:
                print(f"Public Key for {service_name}:")
                print(public_key)
        
        elif choice == "5":
            # Upload and test SSH key
            service_name = input("Enter the service name to upload the SSH key (e.g., 'MyServer'): ")
            credentials = load_ssh_credentials(key)
            
            service_credentials = None
            for service, username, password, private_key, public_key, hostname in credentials:
                if service == service_name:
                    service_credentials = (username, password, private_key, hostname)
                    break

            if service_credentials:
                username, password, private_key, hostname = service_credentials
                if password != "None":
                    print(f"Uploading SSH key for {service_name} to {hostname}...")
                    if private_key == "None": # generate SSH key if necessary
                        private_key, public_key = generate_ssh_key_pair(service_name) # generate new key
                        update_creds(username, password, private_key, public_key, hostname, service_name, key) # update the stored creds
                    upload_ssh_key_to_server(hostname=hostname, username=username, password=password, private_key=private_key, service_name=service_name)
                else:
                    print(f"No password found for {service_name}. Unable to upload the key.")
            else:
                print(f"No credentials found for {service_name}.")
        
        elif choice == "6":
            print("Exiting SSH Manager...")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
