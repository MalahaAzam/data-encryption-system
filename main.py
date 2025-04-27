import streamlit as st        # For the webpage
import hashlib                # To create secure password hashes
import json                   # To save/load data into a file
import time, os               # To handle files and delays
from cryptography.fernet import Fernet   # For encryption and decryption
from datetime import datetime, timedelta # To handle lockout times
from base64 import urlsafe_b64encode      # Not really needed here, but useful for encoding


# ------------------ Settings ------------------

DATA_FILE = "stored_data.json"  # Where user data is stored
MASTER_PASSWORD = "admin123"    # Special admin password (for later)
LOCKOUT_TIME = 60               # If you fail 3 times, lockout for 60 seconds
SECRET_KEY_FILE = "secret.key" 
PBKDF2_ITERATIONS = 100_000   # How "hard" we make password hashing (stronger security)
LOCKOUT_SECONDS = 60  # Lockout duration after 3 failed attempts (in seconds)

# ------------------ Theme Toggle ------------------

def set_theme():
    if "theme" not in st.session_state:
        st.session_state.theme = "light"

    if st.button(f"Switch to {'Dark' if st.session_state.theme == 'light' else 'Light'} Mode"):
        st.session_state.theme = "dark" if st.session_state.theme == "light" else "light"

    if st.session_state.theme == "dark":
        st.markdown("""
            <style>
                body { background-color: #1e1e1e; color: #f0f0f0; }
                .stTextInput > div > div > input,
                .stTextArea > div > textarea {
                    background-color: #333;
                    color: #f0f0f0;
                }
            </style>
        """, unsafe_allow_html=True)

# ------------------ Session State ------------------
for key in ["current_user", "failed_attempts", "lockout_until", "logged_in"]:
    if key not in st.session_state:
        st.session_state[key] = None if key != "failed_attempts" else 0

# ------------------ Encryption Setup ------------------
if not os.path.exists(SECRET_KEY_FILE):
    key = Fernet.generate_key()
    with open(SECRET_KEY_FILE, "wb") as f:
        f.write(key)
else:
    with open(SECRET_KEY_FILE, "rb") as f:
        key = f.read()

cipher = Fernet(key)

# ------------------ Utility Functions ------------------
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            data = json.load(file)
            users = data.get("users", {})
            lockout_until = data.get("lockout_until", None)
            return users, datetime.fromisoformat(lockout_until) if lockout_until else None
    return {}, None

def save_data(users, lockout_until=None):
    with open(DATA_FILE, "w") as file:
        json.dump({
            "users": users,
            "lockout_until": lockout_until.isoformat() if lockout_until else None
        }, file)

def hash_passkey(passkey, salt="static_salt"):
    return hashlib.pbkdf2_hmac("sha256", passkey.encode(), salt.encode(), PBKDF2_ITERATIONS).hex()

def encrypt(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt(token):
    return cipher.decrypt(token.encode()).decode()

def is_locked_out():
    if st.session_state.lockout_until:
        if datetime.now() < st.session_state.lockout_until:
            return True
        else:
            st.session_state.lockout_until = None
    return False

# ------------------ Pages ------------------

def home_page():
    st.title("🛡️ Secure Data Encryption System")
    st.markdown("""
    Welcome to your secure storage vault!  
    - 🔐 Register/Login to start  
    - 🔒 Encrypt and securely store multiple entries  
    - ⏳ Lockout after multiple login failures
    """)

def register_page(users):
    st.header("📝 Register")
    username = st.text_input("Choose a Username")
    password = st.text_input("Choose a Password", type="password")

    if st.button("Register"):
        if username in users:
            st.error("Username already exists.")
        elif username and password:
            users[username] = {
                "password": hash_passkey(password),
                "encrypted_data": []
            }
            save_data(users, st.session_state.lockout_until)
            st.success("Registered successfully! Please login now.")
        else:
            st.error("All fields are required.")

def login_page(users):
    st.header("🔑 Login")

    if is_locked_out():
        remaining = int((st.session_state.lockout_until - datetime.now()).total_seconds())
        st.error(f"🔒 Locked out! Try again in {remaining} seconds.")
        return

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username not in users:
            st.error("Username not found.")
            return

        if users[username]["password"] == hash_passkey(password):
            st.session_state.current_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome, {username}!")
            time.sleep(1)
            # Mark as logged in and redirect to store data page
            st.session_state.logged_in = True
            st.session_state.page = "Store Data"  # Set page to store data
            st.rerun()  # Refresh to update page
        else:
            st.session_state.failed_attempts += 1
            attempts_left = 3 - st.session_state.failed_attempts
            st.error(f"❌ Incorrect password. Attempts left: {attempts_left}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_until = datetime.now() + timedelta(seconds=LOCKOUT_SECONDS)
                save_data(users, st.session_state.lockout_until)
                st.error("🔒 Too many failed attempts. Locked temporarily.")

def store_data_page(users):
    st.header("📂 Store Encrypted Data")
    if not st.session_state.current_user:
        st.warning("⚠️ Please login first!")
        return

    user_data = st.text_area("Enter text to encrypt")

    if st.button("Encrypt & Save"):
        if user_data:
            encrypted = encrypt(user_data)
            users[st.session_state.current_user]["encrypted_data"].append(encrypted)
            save_data(users, st.session_state.lockout_until)
            st.success("✅ Data encrypted and saved!")
        else:
            st.error("⚠️ Please enter some text.")

def retrieve_data_page(users):
    st.header("🔍 Retrieve Your Data")
    if not st.session_state.current_user:
        st.warning("⚠️ Please login first!")
        return

    entries = users[st.session_state.current_user]["encrypted_data"]

    if not entries:
        st.info("ℹ️ No data found. Please store something first.")
        return

    selected = st.selectbox("Select stored data", list(range(len(entries))))

    if st.button("Decrypt"):
        encrypted_text = entries[selected]
        decrypted_text = decrypt(encrypted_text)
        st.success(f"✅ Decrypted Text: {decrypted_text}")

def logout():
    st.session_state.current_user = None
    st.session_state.logged_in = False  # Set logged in state to False
    st.success("✅ Logged out successfully.")
    time.sleep(1)
    st.session_state.page = "Home"  # Redirect to Home after logout
    st.rerun()  # Refresh the page

# ------------------ Main ------------------

set_theme()

users, saved_lockout = load_data()
if saved_lockout and not st.session_state.lockout_until:
    st.session_state.lockout_until = saved_lockout

# Handle navigation based on session state
if "logged_in" in st.session_state and st.session_state.logged_in:
    if "page" in st.session_state:
        choice = st.session_state.page
    else:
        choice = "Store Data"  # Default page after login
else:
    choice = "Login"  # If not logged in, show login page

menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(choice))

if choice == "Home":
    home_page()
elif choice == "Register":
    register_page(users)
elif choice == "Login":
    login_page(users)
elif choice == "Store Data":
    store_data_page(users)
elif choice == "Retrieve Data":
    retrieve_data_page(users)
elif choice == "Logout":
    logout()

st.markdown("---")
st.caption("🔒 Built with Fernet Encryption | PBKDF2 Hashing | Session Lockout | Streamlit UI")
