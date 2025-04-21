import streamlit as st
import hashlib # to hash passwords
import json # to store data in json file
import os # to check if file exists
import time
from cryptography.fernet import Fernet # for data encryption
from base64 import urlsafe_b64encode # for encoding the key 
from hashlib import pbkdf2_hmac # for key generation

# === Data Information of user ===  

DATA_FILE = "secure_data.json"

SALT = b"secure_salt_value"  # Use a secure random salt in production

LOCKOUT_DURATION = 60 

# === Section login detail ===

if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state: 
    st.session_state.lockout_time = 0  

# if data is load

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)


def generate_key(passkey):
    key = pbkdf2_hmac("sha256" , passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

#== cryptography, fernet used ===
def encrypt_data(text, key):
    chipher = Fernet(generate_key(key))
    return chipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        chipher = Fernet(generate_key(key))
        return chipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

stored_data = load_data()

#=== navigation bar ===

st.title("🔒 Secure Data Encrytion system" )
menu = ["Home", "Register", "Login",  "Store Data" , "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)


if choice == "Home":
    st.subheader("Welcome to the 🔒 Secure Data Encryption System Using Streamlit")
    st.markdown("Develop a Streamlit-based secure data storage and retrieval system where : user store data with a unique passkey. ")

# === user Registeration ===
elif choice == "Register":
    st.subheader("📝Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")
    
    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("Username already exists. Please choose a different one.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": {}
                }
                save_data(stored_data)
                st.success("User registered successfully!")
        else:
            st.error("Both field are required.")

elif choice == "Login":
    st.subheader("🔑Login")
        
    if time.time() < st.session_state.lockout_time:
        remaining_time = int(st.session_state.lockout_time - time.time())
        st.error(f"Too many failed attempts. Please wait ⌛ {remaining_time} seconds")
        st.stop()

        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success(f"Welcome, {username}!")
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"⚠️Invalid credentials. {remaining} attempts left.")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error(f"🛑Too many failed attempts. Please wait ⌛ {LOCKOUT_DURATION} seconds")
                    st.stop()

# === Store Data ===

elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔒Please login first")
    else:
        st.subheader("📥Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption key (passphrase)", type="password")
    
        if st.button("Encrypt and Save"):
            if data and passkey:
                encrypted = encrypt_data(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅Data encrypted and saved successfully!")
            else:
                st.error("All fields are required.")

# === Retrieve Data ===
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔒Please login first")
    else:
        st.subheader("📤Retrieve Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("No data found")
        else:
            st.write("Encrypted Data Enteries")
            for i , item in enumerate(user_data):
                st.code(item, language="text")
            
            encrypt_input = st.text_area("Enter the Encrypted Text")
            passkey = st.text_input("Enter passkey T Decrypt", type="password")
            if st.button("Decrypt"):
                result = decrypt_text(encrypt_input, passkey)
                if result:
                    st.success(f"Decrypted  {result}")
                else: 
                    st.error("❌ incorrect passkey or corrupted data")




        

