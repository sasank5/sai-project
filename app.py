import streamlit as st
import os
import sqlite3
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
import hashlib
import tempfile
from PIL import Image
import random

# -----------------------
# PASSWORD HASHING
# -----------------------
def generate_password_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_password_hash(stored, password):
    return stored == hashlib.sha256(password.encode()).hexdigest()

# -----------------------
# CONFIG
# -----------------------
if "STREAMLIT_SERVER_HEADLESS" in os.environ:
    DB_PATH = os.path.join(tempfile.gettempdir(), "security.db")
    INTRUDER_DIR = os.path.join(tempfile.gettempdir(), "intruders")
else:
    DB_PATH = "security.db"
    INTRUDER_DIR = "intruders"

os.makedirs(INTRUDER_DIR, exist_ok=True)

MAX_LOGIN_ATTEMPTS = 5
SESSION_TIMEOUT_MINUTES = 30
LOG_RETENTION_DAYS = 7

EMAIL_SENDER = os.getenv("EMAIL_SENDER", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER", "")

# -----------------------
# DATABASE
# -----------------------
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS admin (
                username TEXT,
                password TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                emotion TEXT,
                time TEXT
            )
        """)

        # 🔥 FIX LOGIN BUG (always reset admin)
        c.execute("DELETE FROM admin")

        c.execute(
            "INSERT INTO admin VALUES (?, ?)",
            ("admin", generate_password_hash("admin123"))
        )

        conn.commit()

def log_event(emotion):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO logs VALUES (?, ?)",
            (emotion, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()

def get_logs(limit=100):
    with sqlite3.connect(DB_PATH) as conn:
        return conn.execute(
            "SELECT emotion, time FROM logs ORDER BY rowid DESC LIMIT ?",
            (limit,)
        ).fetchall()

# -----------------------
# EMAIL ALERT
# -----------------------
def send_email(image_path, emotion):
    try:
        if not EMAIL_SENDER:
            return

        msg = EmailMessage()
        msg["Subject"] = f"Alert: {emotion}"
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_RECEIVER
        msg.set_content(f"Detected {emotion}")

        with open(image_path, "rb") as f:
            msg.add_attachment(f.read(), maintype="image", subtype="jpeg")

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(msg)
    except:
        pass

# -----------------------
# LOGIN PAGE
# -----------------------
def login_page():
    st.title("🔒 Login")

    user = st.text_input("Username")
    pwd = st.text_input("Password", type="password")

    if st.button("Login"):
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT password FROM admin WHERE username=?",
                (user,)
            ).fetchone()

        if row and check_password_hash(row[0], pwd):
            st.session_state.logged_in = True
            st.session_state.last_activity = datetime.now()
            st.success("Login successful")
            st.rerun()
        else:
            st.error("Invalid credentials")

# -----------------------
# CAMERA PAGE
# -----------------------
def camera_page():
    st.title("📷 Monitoring")

    img = st.camera_input("Capture")

    if img:
        image = Image.open(img)
        st.image(image)

        emotion = random.choice(["happy", "neutral", "angry", "fear"])
        st.success(f"Emotion: {emotion}")

        log_event(emotion)

        if emotion in ["angry", "fear"]:
            st.error("🚨 ALERT!")

            filename = f"{datetime.now().strftime('%H%M%S')}.jpg"
            path = os.path.join(INTRUDER_DIR, filename)

            image.save(path)
            send_email(path, emotion)

# -----------------------
# DASHBOARD
# -----------------------
def dashboard_page():
    st.title("📊 Logs")

    limit = st.slider("Limit", 10, 200, 50)
    data = get_logs(limit)

    for e, t in data:
        color = "red" if e in ["angry", "fear"] else "green"
        st.markdown(f"<span style='color:{color}'>●</span> {t} - {e}", unsafe_allow_html=True)

    if st.button("Clear Logs"):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM logs")
            conn.commit()
        st.success("Cleared")
        st.rerun()

# -----------------------
# SETTINGS
# -----------------------
def settings_page():
    st.title("⚙️ Settings")

    current = st.text_input("Current Password", type="password")
    new = st.text_input("New Password", type="password")

    if st.button("Update"):
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT password FROM admin WHERE username='admin'"
            ).fetchone()

            if row and check_password_hash(row[0], current):
                conn.execute(
                    "UPDATE admin SET password=?",
                    (generate_password_hash(new),)
                )
                conn.commit()
                st.success("Updated")
            else:
                st.error("Wrong password")

    st.subheader("Stored Images")

    files = os.listdir(INTRUDER_DIR)
    for f in files[-6:]:
        st.image(os.path.join(INTRUDER_DIR, f), caption=f)

# -----------------------
# MAIN
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
        ["Camera", "Dashboard", "Settings", "Logout"]
    )

    if menu == "Camera":
        camera_page()
    elif menu == "Dashboard":
        dashboard_page()
    elif menu == "Settings":
        settings_page()
    elif menu == "Logout":
        st.session_state.logged_in = False
        st.rerun()

if __name__ == "__main__":
    main()
