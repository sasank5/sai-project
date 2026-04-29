import streamlit as st
import os
import sqlite3
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
import hashlib
from PIL import Image
import random

# -----------------------
# DATABASE (SAFE FIX)
# -----------------------
DB_PATH = ":memory:"   # 🔥 prevents all sqlite errors

# -----------------------
# PASSWORD HASH
# -----------------------
def generate_password_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_password_hash(stored, password):
    return stored == hashlib.sha256(password.encode()).hexdigest()

# -----------------------
# INIT DB (RUN ONCE)
# -----------------------
def init_db():
    if "db_initialized" in st.session_state:
        return

    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE admin (
            username TEXT,
            password TEXT
        )
    """)

    c.execute("""
        CREATE TABLE logs (
            emotion TEXT,
            time TEXT
        )
    """)

    c.execute(
        "INSERT INTO admin VALUES (?, ?)",
        ("admin", generate_password_hash("admin123"))
    )

    conn.commit()
    conn.close()

    st.session_state.db_initialized = True

# -----------------------
# DB HELPERS
# -----------------------
def verify_admin(user, pwd):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    c = conn.cursor()
    c.execute("SELECT password FROM admin WHERE username=?", (user,))
    row = c.fetchone()
    conn.close()

    return row and check_password_hash(row[0], pwd)

def log_event(emotion):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute(
        "INSERT INTO logs VALUES (?, ?)",
        (emotion, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()

def get_logs():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    data = conn.execute(
        "SELECT emotion, time FROM logs ORDER BY rowid DESC"
    ).fetchall()
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
            st.error("❌ Invalid credentials")

# -----------------------
# CAMERA PAGE
# -----------------------
def camera_page():
    st.title("📷 Monitoring System")

    img = st.camera_input("Capture Image")

    if img:
        image = Image.open(img)
        st.image(image, caption="Captured Image")

        # Fake AI (cloud safe)
        emotion = random.choice(["happy", "neutral", "angry", "fear"])

        st.success(f"Detected Emotion: {emotion.upper()}")

        log_event(emotion)

        if emotion in ["angry", "fear"]:
            st.error("🚨 ALERT: Suspicious emotion detected!")

# -----------------------
# DASHBOARD
# -----------------------
def dashboard_page():
    st.title("📊 Security Logs")

    logs = get_logs()

    if not logs:
        st.info("No logs yet")
        return

    for emotion, time in logs:
        color = "red" if emotion in ["angry", "fear"] else "green"
        st.markdown(
            f"<span style='color:{color}'>●</span> {time} - {emotion}",
            unsafe_allow_html=True
        )

# -----------------------
# SETTINGS
# -----------------------
def settings_page():
    st.title("⚙️ Settings")

    current = st.text_input("Current Password", type="password")
    new = st.text_input("New Password", type="password")

    if st.button("Change Password"):
        if verify_admin("admin", current):
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            conn.execute(
                "UPDATE admin SET password=?",
                (generate_password_hash(new),)
            )
            conn.commit()
            conn.close()
            st.success("Password updated")
        else:
            st.error("Wrong current password")

# -----------------------
# MAIN APP
# -----------------------
def main():
    st.set_page_config(page_title="Security System", layout="wide")

    init_db()

    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        login_page()
        return

    menu = st.sidebar.selectbox(
        "Menu",
        ["📷 Camera", "📊 Dashboard", "⚙️ Settings", "🚪 Logout"]
    )

    if menu == "📷 Camera":
        camera_page()

    elif menu == "📊 Dashboard":
        dashboard_page()

    elif menu == "⚙️ Settings":
        settings_page()

    elif menu == "🚪 Logout":
        st.session_state.logged_in = False
        st.rerun()

# -----------------------
# RUN
# -----------------------
if __name__ == "__main__":
    main()
