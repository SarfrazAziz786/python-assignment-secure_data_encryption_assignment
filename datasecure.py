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

print(f"session state : {st.session_state}") # Debugging line to check session state

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
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {} # Return empty dict if file is corrupted or empty
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4) # Added indent for readability


def generate_key(passkey):
    # Use PBKDF2HMAC to derive a key from the passkey and salt
    # The key needs to be 32 bytes long and URL-safe base64 encoded for Fernet
    key = pbkdf2_hmac("sha256" , passkey.encode(), SALT, 100000, dklen=32) # Specify dklen=32
    return urlsafe_b64encode(key)

def hash_password(password):
    # Use PBKDF2HMAC for password hashing as well, consistent with key generation
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()


def encrypt_data(text, passkey): 
    derived_key = generate_key(passkey)
    cipher = Fernet(derived_key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, passkey): 
    try:
        derived_key = generate_key(passkey)
        cipher = Fernet(derived_key)
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception as e: # Catch specific exceptions if possible, e.g., InvalidToken
        # Consider logging the error e
        return None

stored_data = load_data()

#=== navigation bar ===

st.title("🔒 Secure Data Encryption System" )
menu = ["Home", "Register", "Login",  "Store Data" , "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)


if choice == "Home":
    st.subheader("Welcome to the 🔒 Secure Data Encryption System Using Streamlit")
    st.markdown("""
    This application allows you to securely store and retrieve sensitive information.
    - **Register:** Create a new user account.
    - **Login:** Access your account.
    - **Store Data:** Encrypt and save your data using a unique passkey.
    - **Retrieve Data:** Decrypt and view your stored data using the correct passkey.

    **Security Note:** Your login password and data encryption passkeys are crucial. Keep them safe!
    """)

# === user Registeration ===
elif choice == "Register":
    st.subheader("📝 Register New User")
    with st.form("register_form"):
        username = st.text_input("Choose Username")
        password = st.text_input("Choose Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        submitted = st.form_submit_button("Register")

        if submitted:
            if not username or not password or not confirm_password:
                st.error("All fields are required.")
            elif password != confirm_password:
                st.error("Passwords do not match.")
            elif username in stored_data: # Check if username already exists in dictionary
                st.warning("Username already exists. Please choose a different one.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("User registered successfully! Please proceed to Login.")
                st.balloons()


elif choice == "Login":
    st.subheader("🔑 User Login")

    # Check for lockout first
    current_time = time.time()
    if current_time < st.session_state.lockout_time:
        remaining_time = int(st.session_state.lockout_time - current_time)
        st.error(f"Too many failed attempts. Please wait ⌛ {remaining_time} seconds.")
        st.stop() # Stop execution if locked out

    # If already logged in
    if st.session_state.authenticated_user:
         st.success(f"Already logged in as {st.session_state.authenticated_user}")
         if st.button("Logout"):
             st.session_state.authenticated_user = None
             st.session_state.failed_attempts = 0 # Reset attempts on logout
             st.session_state.lockout_time = 0
             st.rerun() # Rerun to reflect logout state
    else:
        # Login form
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")

            if submitted:
                user_info = stored_data.get(username)
                # Check if user exists AND password matches
                if user_info and user_info["password"] == hash_password(password):
                    st.session_state.authenticated_user = username
                    st.session_state.failed_attempts = 0 # Reset attempts on success
                    st.session_state.lockout_time = 0 # Reset lockout time on success
                    st.success(f"Welcome, {username}!")
                    st.rerun() # Rerun to show logged-in state
                else:
                    st.session_state.failed_attempts += 1
                    attempts_left = 3 - st.session_state.failed_attempts
                    if attempts_left > 0:
                        st.error(f"⚠️ Invalid credentials. {attempts_left} attempts left.")
                    else:
                        st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                        st.error(f"🛑 Too many failed attempts. Account locked for {LOCKOUT_DURATION} seconds.")
                        # No need to st.stop() here, the check at the beginning handles it


# === Store Data ===
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login first to store data.")
    else:
        st.subheader(f"📥 Store Encrypted Data for {st.session_state.authenticated_user}")
        with st.form("store_data_form"):
            data_description = st.text_input("Data Description")
            data_to_encrypt = st.text_area("Enter data to encrypt")
            passkey = st.text_input("Encryption Passkey (choose a strong one!)", type="password")
            submitted = st.form_submit_button("Encrypt and Save")

            if submitted:
                if data_to_encrypt and passkey:
                    try:
                        encrypted_data = encrypt_data(data_to_encrypt, passkey)
                        # Store as a dictionary for potential future metadata
                        data_entry = {
                            "description": data_description if data_description else "Encrypted Data",
                            "encrypted_value": encrypted_data,
                            "timestamp": time.time() # Add a timestamp
                        }
                        # Ensure user exists in data structure (should always be true if logged in)
                        if st.session_state.authenticated_user in stored_data:
                            stored_data[st.session_state.authenticated_user]["data"].append(data_entry)
                            save_data(stored_data)
                            st.success("✅ Data encrypted and saved successfully!")
                        else:
                             st.error("Error: User data structure not found. Please re-login.")

                    except Exception as e:
                        st.error(f"An error occurred during encryption: {e}")
                else:
                    st.error("Data to encrypt and passkey are required.")

# === Retrieve Data ===
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login first to retrieve data.")
    else:
        st.subheader(f"📤 Retrieve Data for {st.session_state.authenticated_user}")
        user_data_list = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data_list:
            st.info("You haven't stored any data yet.")
        else:
            st.write("Your Stored Encrypted Data Entries:")

            # Display data entries with descriptions and allow selection
            entry_options = {f"{i+1}: {entry.get('description', 'Encrypted Data')} (Stored: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(entry.get('timestamp', 0)))})": entry.get('encrypted_value')
                             for i, entry in enumerate(user_data_list)}

            selected_entry_label = st.selectbox("Select data entry to decrypt:", options=entry_options.keys())

            if selected_entry_label:
                encrypted_text_to_decrypt = entry_options[selected_entry_label]
                st.text_area("Selected Encrypted Text:", value=encrypted_text_to_decrypt, height=100, disabled=True)

                with st.form("decrypt_data_form"):
                    passkey = st.text_input("Enter Passkey to Decrypt", type="password")
                    submitted = st.form_submit_button("Decrypt")

                    if submitted:
                        if passkey:
                            decrypted_result = decrypt_text(encrypted_text_to_decrypt, passkey)
                            if decrypted_result is not None:
                                st.success("Decryption Successful!")
                                st.text_area("Decrypted Data:", value=decrypted_result, height=150)
                            else:
                                st.error("❌ Incorrect passkey or data corruption.")
                        else:
                            st.error("Passkey is required to decrypt.")
