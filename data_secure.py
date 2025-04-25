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
    return urlsafe_b64encode(key)  # Ensure it's suitable for Fernet

def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 100000).hex()

def encrpt_data(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception:
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

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"❌ Too many failed attempts. Please wait {remaining} seconds before trying again.")
        st.stop()
    username = st.text_input("Username")
    password = st.text_input("Enter Master Password", type="password")

    if st.button("Login"):
        if username in stored_data:
            if stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")    
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.warning(f"❌ Incorrect password. {remaining} attempts left.")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_TIME
                    st.warning(f"Too many failed attempts. Lockout for 🕰️ {LOCKOUT_TIME} seconds.")
                    time.sleep(LOCKOUT_TIME)
                else:
                    st.warning("❌ Incorrect password. Please try again.")
        else:
            st.warning("⚠️ User not found. Please register first.")

elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
    else:
        st.subheader("📂 Store Encrypted Data")
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

elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("⚠️ Please login first.")
    else:
        st.subheader("🔍 Retrieve Your Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("⚠️ No data found for this user.")
        else:
            st.write("Encrypted Data Enteries:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

            encrypted_input = st.text_area("Enter Encrypted Text")
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                result = decrypt_data(encrypted_input, passkey)
                if result:
                    st.success(f"✅ Decrypted Data: {result}")
                else:
                    st.error("❌ Decryption failed. Incorrect passkey or invalid data.")
