import streamlit as st
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode, urlsafe_b64decode
from hashlib import pbkdf2_hmac
import json
import os
import random

# --- Constants ---
DATA_FILE = "data_store.json"
MAX_FAILED_ATTEMPTS = 3
BACKGROUND_IMAGE = "https://plus.unsplash.com/premium_photo-1700476854144-25da28c4ee9e?q=80&w=1974&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D"
PBKDF2_ITERATIONS = 100000

# --- UI Styling ---
st.markdown(
    f"""
    <style>
    .stApp {{
        background: linear-gradient(rgba(10, 10, 10, 0.4), rgba(20, 20, 20, 0.4)), 
                    url('{BACKGROUND_IMAGE}') no-repeat center center fixed;
        background-size: cover;
        color: #ffffff;
        font-family: 'Segoe UI', sans-serif;
    }}

    .card {{
        background-color: rgba(30, 30, 30, 0.6);  /* Reduced opacity */
        border-radius: 1rem;
        padding: 1.5rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        color: rgba(255, 255, 255, 0.9);  /* Slightly lighter text */
    }}

    .dashboard-title {{
        text-align: center;
        font-size: 2.5rem;
        margin-top: 1rem;
        color: #00ffc3;
        text-shadow: 1px 1px 5px rgba(0,255,200,0.5);
    }}

    .stTextInput > div > input,
    .stTextArea textarea,
    .stButton button {{
        background-color: #1f1f1f;
        color: #fff;
        border: 1px solid #444;
        border-radius: 0.5rem;
    }}

    .stButton button:hover {{
        background-color: #333;
        border-color: #00ffc3;
        color: #00ffc3;
    }}

    .stTextInput > div > input::placeholder,
    .stTextArea textarea::placeholder {{
        color: #aaa;
    }}

    .stAlert {{
        background-color: #2a2a2a;
        border-left: 5px solid #ff4d4d;
        color: #fff;
    }}

    .stSuccess {{
        background-color: #2a2a2a;
        border-left: 5px solid #00ff88;
        color: #fff;
    }}
    </style>
    """,
    unsafe_allow_html=True,
)

# --- Security Functions ---
def generate_salt():
    return os.urandom(16)

def derive_key(password, salt, iterations=PBKDF2_ITERATIONS):
    key = pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    return urlsafe_b64encode(key).decode()

# --- Data Handling ---
def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# --- Session Management ---
if "data_store" not in st.session_state:
    st.session_state.data_store = load_data()

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "authorized" not in st.session_state:
    st.session_state.authorized = False

if "current_user" not in st.session_state:
    st.session_state.current_user = ""

# --- Dashboard Page ---
def dashboard_page():
    st.markdown('<h1 class="dashboard-title">📊 Secure Data Vault</h1>', unsafe_allow_html=True)
    entries = st.session_state.data_store[st.session_state.current_user]["entries"]
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f"""
        <div class="card" style="text-align: center;">
            <h3>🔢</h3>
            <h2>{len(entries)}</h2>
            <p>Total Secrets</p>
        </div>
        """, unsafe_allow_html=True)

# --- Login/Register Page ---
def login_page():
    st.title("🔐 Secure Login")
    with st.container():
        st.markdown('<div class="card">', unsafe_allow_html=True)
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Login / Register"):
            if not username or not password:
                st.error("Please fill all fields")
                return
                
            users = st.session_state.data_store
            if username not in users:
                password_salt = generate_salt()
                users[username] = {
                    "password_salt": urlsafe_b64encode(password_salt).decode(),
                    "password_hash": derive_key(password, password_salt),
                    "entries": []
                }
                st.success("Account created! Logged in.")
            else:
                stored_salt = urlsafe_b64decode(users[username]["password_salt"])
                attempt_hash = derive_key(password, stored_salt)
                if attempt_hash != users[username]["password_hash"]:
                    st.session_state.failed_attempts += 1
                    remaining = MAX_FAILED_ATTEMPTS - st.session_state.failed_attempts
                    st.error(f"Invalid credentials. {remaining} attempts left")
                    return
            
            st.session_state.current_user = username
            st.session_state.authorized = True
            save_data(users)
            st.rerun()
            
        st.markdown('</div>', unsafe_allow_html=True)

# --- Store Data Page ---
def store_data_page():
    st.title("🔒 Store Data")
    with st.container():
        st.markdown('<div class="card">', unsafe_allow_html=True)
        data = st.text_area("Your Data", height=150)
        passkey = st.text_input("Encryption Key", type="password")
        
        if st.button("Encrypt & Save"):
            if not data or not passkey:
                st.error("All fields required")
                return

            entry_salt = generate_salt()
            key = derive_key(passkey, entry_salt)
            cipher = Fernet(key)
            
            encrypted_data = cipher.encrypt(data.encode()).decode()
            new_entry = {
                "encrypted_data": encrypted_data,
                "entry_salt": urlsafe_b64encode(entry_salt).decode()
            }
            
            st.session_state.data_store[st.session_state.current_user]["entries"].append(new_entry)
            save_data(st.session_state.data_store)
            
            st.success("Data encrypted and saved!")
            st.code(encrypted_data)
        
        st.markdown('</div>', unsafe_allow_html=True)

# --- Retrieve Data Page ---
def retrieve_data_page():
    st.title("🔓 Retrieve Data")
    with st.container():
        st.markdown('<div class="card">', unsafe_allow_html=True)
        encrypted_input = st.text_area("Encrypted Data", height=100)
        passkey = st.text_input("Decryption Key", type="password")
        
        if st.button("Decrypt"):
            if not encrypted_input or not passkey:
                st.error("All fields required")
                return
                
            entries = st.session_state.data_store[st.session_state.current_user]["entries"]
            entry = next((e for e in entries if e["encrypted_data"] == encrypted_input), None)
            
            if not entry:
                st.error("Data not found")
                return
                
            entry_salt = urlsafe_b64decode(entry["entry_salt"])
            key = derive_key(passkey, entry_salt)
            
            try:
                cipher = Fernet(key)
                decrypted = cipher.decrypt(encrypted_input.encode()).decode()
                st.success("Decrypted successfully!")
                st.text_area("Decrypted Data", decrypted, height=150)
            except:
                st.error("Invalid passkey or corrupted data")
        
        st.markdown('</div>', unsafe_allow_html=True)

# --- App Flow ---
if st.session_state.authorized:
    st.sidebar.title(f"Welcome, {st.session_state.current_user}!")
    st.sidebar.markdown("---")
    
    pages = {
        "home": ("🏠 Dashboard", dashboard_page),
        "store": ("💾 Store Data", store_data_page),
        "retrieve": ("📂 Retrieve Data", retrieve_data_page)
    }
    
    for page_id, (page_name, _) in pages.items():
        if st.sidebar.button(page_name):
            st.session_state.page = page_id
    
    if st.sidebar.button("🚪 Logout"):
        st.session_state.authorized = False
        st.session_state.current_user = ""
        st.rerun()
    
    current_page = pages.get(st.session_state.get("page", "home"), dashboard_page)[1]
    current_page()
else:
    login_page()
