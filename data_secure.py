import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# Data information of the user
DATA_FILE = "secur_data.json"
SALT = b"secret_salt_value"  # Use a secure random salt in production
LOCKOUT_TIME = 60

# section login details
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

# if data is save
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    key = pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.sha256("sha256",password.encode(), SALT, 100000).hexdigest()

# cryptography fernet used
def encrpt_data(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None
    
stored_data = load_data()

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navbar
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Register":
    st.subheader("📝 Register New User")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ Username already exists. Please choose a different one.")
            else:
                stored_data[username] = {"password": hash_password(password), "data": []}
                save_data(stored_data)
                st.success("✅ Registration successful. You can now log in.")
        else:
            st.warning("⚠️ Please enter both username and password.")
    elif choice == "Login":
        st.subheader("🔑 Reauthorization Required")
        username = st.text_input("Username")
        password = st.text_input("Enter Master Password", type="password")

        if st.button("Login"):
            if username in stored_data:
                if stored_data[username]["password"] == hash_password(password):
                    st.session_state.authenticated_user = username
                    st.session_state.failed_attempts = 0
                    st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
                    st.experimental_rerun()
                else:
                    st.session_state.failed_attempts += 1
                    if st.session_state.failed_attempts >= 3:
                        st.session_state.lockout_time = time.time() + LOCKOUT_TIME
                        st.warning(f"Too many failed attempts. Lockout for 🕰️ {LOCKOUT_TIME} seconds.")
                    else:
                        st.warning("❌ Incorrect password. Please try again.")
            else:
                st.warning("⚠️ User not found. Please register first.")

elif choice == "Store Data":
    if st.session_state.authenticated_user:
        st.subheader("📂 Store Data")
        data = st.text_area("Enter data to store")
        passkey = st.text_input("Enter passkey", type="password")

        if st.button("Encrypt & Save"):
            if data and passkey:
                encrypted_data = encrpt_data(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted_data)
                save_data(stored_data)
                st.success("✅ Data stored successfully!")
            else:
                st.warning("⚠️ Please enter both data and passkey.")
    else:
        st.warning("⚠️ Please login first.")

elif choice == "Retrieve Data":
    if st.session_state.authenticated_user:
        st.subheader("🔍 Retrieve Your Data")
        passkey = st.text_input("Enter passkey to retrieve data", type="password")

        if st.button("Decrypt & Retrieve"):
            if passkey:
                user_data = stored_data[st.session_state.authenticated_user]["data"]
                if user_data:
                    decrypted_data = decrypt_data(user_data[-1], passkey)
                    if decrypted_data:
                        st.text_area("Decrypted Data", decrypted_data, height=200)
                    else:
                        st.warning("⚠️ Incorrect passkey. Please try again.")
                else:
                    st.warning("⚠️ No data found for this user.")
            else:
                st.warning("⚠️ Please enter the passkey.")
    else:
        st.warning("⚠️ Please login first.")