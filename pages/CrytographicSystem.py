import streamlit as st
from cryptography.fernet import Fernet
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

st.set_page_config(
    page_title = "Cryptographic System", page_icon="🔐",layout = "wide")

def generate_key():
    key = Fernet.generate_key()
    return key

def encrypt_message(key, message):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(key, encrypted_message):
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message

def hash_message(message):
    hashed_message = hashlib.sha256(message.encode()).hexdigest()
    return hashed_message

def encrypt_rsa(public_key, message):
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


def decrypt_rsa(private_key, encrypted_message):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()
    return decrypted_message

def main():
    st.title("Cryptographic Systems with Streamlit")

    # Fernet Encryption
    st.header("Fernet Encryption")
    fernet_key = generate_key()
    message = st.text_input("Enter a message for Fernet encryption:")
    encrypted_message = encrypt_message(fernet_key, message)
    decrypted_message = decrypt_message(fernet_key, encrypted_message)

    st.write("Encrypted Message:", encrypted_message)
    st.write("Decrypted Message:", decrypted_message)

    # Hashing
    st.header("Hashing")
    message = st.text_input("Enter a message for hashing:")
    hashed_message = hash_message(message)
    st.write("Hashed Message:", hashed_message)

    # RSA Encryption
    st.header("RSA Encryption")
    private_key, public_key = generate_rsa_key_pair()
    message = st.text_input("Enter a message for RSA encryption:")
    encrypted_message = encrypt_rsa(public_key, message)
    decrypted_message = decrypt_rsa(private_key, encrypted_message)

    st.write("Encrypted Message:", encrypted_message)
    st.write("Decrypted Message:", decrypted_message)

if __name__ == "__main__":
    main()
