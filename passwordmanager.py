import random
import string
import pandas as pd
from cryptography.fernet import Fernet
import os
import csv
import base64

# Password generation function (using NLTK words)
import nltk
nltk.download('words')
from nltk.corpus import words

# Function to generate a random, pronounceable password
def generate_password():
    # Get a list of English words
    word_list = words.words()
    
    words_chosen = random.sample(word_list, random.randint(3, 5)) # Randomly pick 3 to 5 words
    words_chosen = [random.choice([word.upper(), word.lower()]) for word in words_chosen] # Randomly capitalize letters in words to mix uppercase and lowercase
    digits = ''.join(random.choices(string.digits, k=random.randint(3, 8))) # Generate 3 to 8 random digits (placed between words to maintain readability)
    symbols = ''.join(random.choices(string.punctuation, k=random.randint(3, 8))) # Generate 3 to 8 random symbols
    
    # Combine words with digits and symbols
    password_elements = []
    
    for word in words_chosen:
        password_elements.append(word)
        # Add a number or symbol after each word to make it secure but readable
        if random.choice([True, False]):
            password_elements.append(random.choice([digits, symbols]))
    
    random.shuffle(password_elements) # Shuffle the password elements to randomize order
    
    password = '-'.join(password_elements) # Join the elements with hyphens and ensure the structure stays pronounceable
    
    return password

# Generate a key for encryption (you should securely store this key)
def generate_key():
    return Fernet.generate_key()

# Save the key to a file (if necessary)
def save_key(key, filename="pw_secret.key"):
    with open(filename, "wb") as key_file:
        key_file.write(key)

# Load the key from a file
def load_key(filename="pw_secret.key"):
    try:
        with open(filename, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        print("Key file not found. Please generate a new key.")
        exit(1)  # Exit the program if the key is not found

# Encrypt a message
def encrypt_message(message, key):
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    # Convert the encrypted message to base64 string for CSV storage
    return base64.b64encode(encrypted_message).decode()

# Decrypt a message
def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    encrypted_message = base64.b64decode(encrypted_message.encode())  # Decode from base64
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message

# Store password into CSV
def store_password(password, service_name, key, filename="passwords.csv"):
    encrypted_password = encrypt_message(password, key)  # Encrypt the password
    
    # Check if the file exists. If not, create it with headers
    if not os.path.exists(filename):
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Service', 'Password'])
    
    # Append the new password to the CSV file
    with open(filename, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([service_name, encrypted_password])

# Load passwords from the CSV and decrypt them
def load_passwords(key, filename="passwords.csv"):
    passwords = []
    if os.path.exists(filename):
        with open(filename, 'r', newline='') as f:
            reader = csv.reader(f)
            next(reader)  # Skip header row
            for row in reader:
                service_name, encrypted_password = row
                decrypted_password = decrypt_message(encrypted_password, key)
                passwords.append((service_name, decrypted_password))
    return passwords

# Main function
def main():
    # Load or generate a key for encryption
    if not os.path.exists("secret.key"):
        key = generate_key()
        save_key(key)
        print("Encryption key created and saved.")
    else:
        key = load_key()
    
    # Display menu for user interaction
    while True:
        print("\nPassword Manager")
        print("1. Generate a new password")
        print("2. Store a password")
        print("3. View stored passwords")
        print("4. Exit")
        
        choice = input("Choose an option (1-4): ")
        
        if choice == "1":
            # Generate a password and display it
            password = generate_password()
            print(f"Generated Password: {password}")
        
        elif choice == "2":
            # Ask for service name and password to store
            service_name = input("Enter the service name (e.g., 'Google'): ")
            password = input("Enter the password to store (or leave empty to generate one): ")
            
            if not password:
                password = generate_password()
            
            store_password(password, service_name, key)
            print(f"Password for {service_name} stored successfully.")
        
        elif choice == "3":
            # View stored passwords
            print("\nStored Passwords:")
            passwords = load_passwords(key)
            if passwords:
                for service, password in passwords:
                    print(f"Service: {service} - Password: {password}")
            else:
                print("No passwords stored.")
        
        elif choice == "4":
            print("Exiting password manager...")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
