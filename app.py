import streamlit as st
from pymongo import MongoClient
import bcrypt

# ------------------- MongoDB Connection -------------------
@st.cache_resource
def get_db():
    uri = st.secrets["mongo"]["uri"]
    db_name = st.secrets["mongo"]["db_name"]
    client = MongoClient(uri)
    return client[db_name]

# ------------------- User Management -------------------
def create_user(username, password, role="user"):
    db = get_db()
    users = db["users"]
    if users.find_one({"username": username}):
        return False, "Username already exists"
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    users.insert_one({"username": username, "password": hashed, "role": role})
    return True, "User created successfully"

def authenticate_user(username, password):
    db = get_db()
    user = db["users"].find_one({"username": username})
    if user and bcrypt.checkpw(password.encode(), user["password"]):
        return True, user["role"]
    return False, None

# ------------------- Portfolio Data -------------------
def get_portfolios(username=None, is_admin=False):
    db = get_db()
    portfolios = db["portfolios"]
    if is_admin:
        return list(portfolios.find({}))
    return list(portfolios.find({"username": username}))

def add_portfolio(username, data):
    db = get_db()
    portfolios = db["portfolios"]
    portfolios.insert_one({"username": username, "data": data})

# ------------------- Admin Auto-Creation -------------------
def ensure_admin_exists():
    db = get_db()
    users = db["users"]
    admin = users.find_one({"username": "admin"})
    if not admin:
        hashed = bcrypt.hashpw("mansi1515".encode(), bcrypt.gensalt())
        users.insert_one({
            "username": "admin",
            "password": hashed,
            "role": "admin"
        })
        print("✅ Admin account created (username: admin, password: mansi1515)")

# Run admin creation once
ensure_admin_exists()

# ------------------- Streamlit App -------------------
st.set_page_config(page_title="Stock Portfolio App", layout="centered")
st.title("📈 Stock Portfolio Dashboard")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None
    st.session_state.page = "login"

# ----------- Login Page -----------
def login_page():
    st.subheader("🔐 Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        success, role = authenticate_user(username, password)
        if success:
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.role = role
            st.session_state.page = "portfolio"
            st.experimental_rerun()
        else:
            st.error("Invalid username or password")

    if st.button("Register New Account"):
        st.session_state.page = "register"
        st.experimental_rerun()

# ----------- Register Page -----------
def register_page():
    st.subheader("🧾 Register New Account")

    username = st.text_input("Create Username")
    password = st.text_input("Create Password", type="password")
    confirm = st.text_input("Confirm Password", type="password")

    if st.button("Create Account"):
        if not username or not password:
            st.error("Please enter all fields")
        elif password != confirm:
            st.error("Passwords do not match")
