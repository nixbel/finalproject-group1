# Importing required libraries
import streamlit as st
from cryptography.fernet import Fernet
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Setting the Streamlit page configuration
st.set_page_config(
    page_title = "Cryptographic System",  # Title of the web page
    page_icon = "🔐",  # Icon to use for the web page
    layout = "wide"  # Layout setting for Streamlit
)

# Function to generate a Fernet key
def generate_keys():
    key = Fernet.generate_key()  # Generates a new Fernet key
    return key

# Function to encrypt a message with Fernet
def encrypt_messages(key, message):
    fernet = Fernet(key)  # Create a Fernet instance with the provided key
    encrypted_message = fernet.encrypt(message.encode())  # Encrypt the message
    return encrypted_message

# Function to decrypt a message with Fernet
def decrypt_messages(key, encrypted_message):
    fernet = Fernet(key)  # Create a Fernet instance with the provided key
    decrypted_message = fernet.decrypt(encrypted_message).decode()  # Decrypt the message
    return decrypted_message

# Function to hash a message using SHA-256
def hash_message(message):
    hashed_message = hashlib.sha256(message.encode()).hexdigest()  # Compute SHA-256 hash
    return hashed_message

# Function to encrypt a message with RSA using a public key
def encrypt_rsa(public_key, message):
    encrypted_message = public_key.encrypt(
        message.encode(),  # Convert the message to bytes
        padding.OAEP(  # Use OAEP padding with SHA-256 for encryption
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask generation function
            algorithm=hashes.SHA256(),  # Hash algorithm
            label=None  # No label
        )
    )
    return encrypted_message

# Function to generate a pair of RSA keys (public and private)
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(  # Create an RSA private key
        public_exponent=65537,  # Public exponent for the RSA key
        key_size=2048  # Key size in bits
    )
    public_key = private_key.public_key()  # Extract the public key from the private key
    return private_key, public_key  # Return both the private and public keys

# Function to decrypt a message with RSA using a private key
def decrypt_rsa(private_key, encrypted_message):
    decrypted_message = private_key.decrypt(
        encrypted_message,  # Encrypted message to decrypt
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask generation function
            algorithm=hashes.SHA256(),  # Hash algorithm
            label=None  # No label
        )
    ).decode()  # Convert the decrypted bytes to a string
    return decrypted_message

# Main function for Streamlit app
def main():
    st.title("Cryptographic Systems with Streamlit")  # Title of the Streamlit app

    # Fernet Encryption Section
    st.header("Fernet Encryption")  # Section header
    fernet_key = generate_keys()  # Generate a Fernet key
    message = st.text_input("Enter a message for Fernet encryption:")  # User input
    encrypted_message = encrypt_messages(fernet_key, message)  # Encrypt the message
    decrypted_message = decrypt_messages(fernet_key, encrypted_message)  # Decrypt the message

    # Displaying the encrypted and decrypted messages
    st.write("Encrypted Message:", encrypted_message)
    st.write("Decrypted Message:", decrypted_message)

    # Hashing Section
    st.header("Hashing")  # Section header
    message = st.text_input("Enter a message for hashing:")  # User input
    hashed_message = hash_message(message)  # Hash the message
    st.write("Hashed Message:", hashed_message)  # Display the hashed message

    # RSA Encryption Section
    st.header("RSA Encryption")  # Section header
    private_key, public_key = generate_rsa_key_pair()  # Generate RSA key pair
    message = st.text_input("Enter a message for RSA encryption:")  # User input
    encrypted_message = encrypt_rsa(public_key, message)  # Encrypt the message with RSA
    decrypted_message = decrypt_rsa(private_key, encrypted_message)  # Decrypt the RSA encrypted message

    # Displaying the RSA encrypted and decrypted messages
    st.write("Encrypted Message:", encrypted_message)
    st.write("Decrypted Message:", decrypted_message)

# Running the main function if this script is executed as the main program
if __name__ == "__main__":
    main()
