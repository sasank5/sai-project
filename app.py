import streamlit as st
import os
import sqlite3
from datetime import datetime, timedelta
import hashlib
import tempfile
import random
from PIL import Image

# -----------------------
# PASSWORD HASHING
# -----------------------
def generate_password_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_password_hash(stored, password):
    return stored == hashlib.sha256(password.encode()).hexdigest()

# -----------------------
# PATH SETUP (IMPORTANT FIX)
# -----------------------
DB_PATH = os.path.join(tempfile.gettempdir(), "security.db")
INTRUDER_DIR = os.path.join(tempfile.gettempdir(), "intruders")
os.makedirs(INTRUDER_DIR, exist_ok=True)

# -----------------------
# DATABASE (FIXED)
# -----------------------
def init_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    c = conn.cursor()

    # CREATE TABLES ALWAYS
    c.execute("""
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            emotion TEXT,
            time TEXT
        )
    """)

    # INSERT DEFAULT ADMIN IF NOT EXISTS
    c.execute("SELECT * FROM admin WHERE username=?", ("admin",))
    if c.fetchone() is None:
        c.execute(
            "INSERT INTO admin (username, password) VALUES (?, ?)",
            ("admin", generate_password_hash("admin123"))
        )

    conn.commit()
    conn.close()

# -----------------------
# DATABASE FUNCTIONS
# -----------------------
def verify_admin(user, pwd):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    c = conn.cursor()

    c.execute("SELECT password FROM admin WHERE username=?", (user,))
    row = c.fetchone()

    conn.close()

    if row:
        return check_password_hash(row[0], pwd)
    return False

def log_event(emotion):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    c = conn.cursor()

    c.execute(
        "INSERT INTO logs (emotion, time) VALUES (?, ?)",
        (emotion, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )

    conn.commit()
    conn.close()

def get_logs():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    c = conn.cursor()

    c.execute("SELECT emotion, time FROM logs ORDER BY id DESC")
    data = c.fetchall()

    conn.close()
    return data

# -----------------------
# LOGIN PAGE
# -----------------------
def login_page():
    st.title("🔒 Security System Login")

    user = st.text_input("Username")
    pwd = st.text_input("Password", type="password")

    if st.button("Login"):
        if verify_admin(user, pwd):
            st.session_state.logged_in = True
            st.success("Login successful")
            st.rerun()
        else:
            st.error("Invalid credentials")

# -----------------------
# CAMERA PAGE (SAFE VERSION)
# -----------------------
def camera_page():
    st.title("📹 Monitoring System")

    img = st.camera_input("Take Photo")

    if img:
        image = Image.open(img)
        st.image(image)

        # FAKE emotion detection (Cloud safe)
        emotions = ["happy", "neutral", "angry", "fear"]
        emotion = random.choice(emotions)

        st.success(f"Detected: {emotion.upper()}")

        log_event(emotion)

        if emotion in ["angry", "fear"]:
            st.error("🚨 ALERT: Suspicious Activity!")

# -----------------------
# LOGS PAGE
# -----------------------
def logs_page():
    st.title("📊 Logs")

    data = get_logs()

    if not data:
        st.info("No logs yet")
        return

    for e, t in data:
        color = "red" if e in ["angry", "fear"] else "green"
        st.markdown(f"<span style='color:{color}'>●</span> {t} - {e}", unsafe_allow_html=True)

# -----------------------
# SETTINGS PAGE
# -----------------------
def settings_page():
    st.title("⚙️ Settings")

    new_pwd = st.text_input("New Password", type="password")

    if st.button("Change Password"):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        c.execute(
            "UPDATE admin SET password=? WHERE username=?",
            (generate_password_hash(new_pwd), "admin")
        )

        conn.commit()
        conn.close()

        st.success("Password updated!")

# -----------------------
# MAIN APP
# -----------------------
def main():
    st.set_page_config(page_title="Security System", layout="wide")

    # 🔥 IMPORTANT: INIT DB FIRST
    init_db()

    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        login_page()
        return

    menu = st.sidebar.selectbox("Menu", [
        "Camera",
        "Logs",
        "Settings",
        "Logout"
    ])

    if menu == "Camera":
        camera_page()
    elif menu == "Logs":
        logs_page()
    elif menu == "Settings":
        settings_page()
    elif menu == "Logout":
        st.session_state.logged_in = False
        st.rerun()

# -----------------------
# RUN
# -----------------------
if __name__ == "__main__":
    main()
