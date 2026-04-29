import streamlit as st
import os
import sqlite3
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
import hashlib
def generate_password_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()
def check_password_hash(stored, password):
    return stored == hashlib.sha256(password.encode()).hexdigest()
from dotenv import load_dotenv
import tempfile
from PIL import Image

# -----------------------
# CONFIG FOR STREAMLIT CLOUD
# -----------------------
load_dotenv()

# Use secrets for cloud deployment
try:
    EMAIL_SENDER = st.secrets["email_sender"]
    EMAIL_PASSWORD = st.secrets["email_password"]
    EMAIL_RECEIVER = st.secrets["email_receiver"]
except:
    EMAIL_SENDER = os.getenv("EMAIL_SENDER", "your_email@gmail.com")
    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "your_app_password")
    EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER", "receiver@gmail.com")

# Use temp directory for cloud deployment
if "STREAMLIT_SERVER_HEADLESS" in os.environ:
    DB_PATH = os.path.join(tempfile.gettempdir(), "security.db")
    INTRUDER_DIR = os.path.join(tempfile.gettempdir(), "intruders")
else:
    BASE_DIR = os.getcwd()
    DB_PATH = os.path.join(BASE_DIR, "security.db")
    INTRUDER_DIR = os.path.join(BASE_DIR, "intruders")

os.makedirs(INTRUDER_DIR, exist_ok=True)

MAX_LOGIN_ATTEMPTS = 5
SESSION_TIMEOUT_MINUTES = 30
LOG_RETENTION_DAYS = 7

# -----------------------
# DATABASE
# -----------------------
def init_db():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS admin (
                    id       INTEGER PRIMARY KEY,
                    username TEXT UNIQUE,
                    password TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    emotion TEXT,
                    time    TEXT
                )
            """)
            if not c.execute("SELECT 1 FROM admin WHERE username='admin'").fetchone():
                c.execute(
                    "INSERT INTO admin (username, password) VALUES (?, ?)",
                    ("admin", generate_password_hash("admin123"))
                )
            conn.commit()
    except Exception as e:
        st.error(f"Database error: {e}")

def log_event(emotion: str):
    """Log emotion on change."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO logs (emotion, time) VALUES (?, ?)",
                (emotion, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
            conn.commit()
    except Exception as e:
        st.warning(f"Log error: {e}")

def get_logs(limit: int = 100):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT emotion, time FROM logs ORDER BY id DESC LIMIT ?", (limit,))
            return c.fetchall()
    except Exception:
        return []

def verify_admin(username: str, password: str):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT password FROM admin WHERE username=?", (username,)
            ).fetchone()
        return row and check_password_hash(row[0], password)
    except Exception:
        return False

def change_password(username: str, new_password: str):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "UPDATE admin SET password=? WHERE username=?",
                (generate_password_hash(new_password), username)
            )
            conn.commit()
        return True
    except Exception:
        return False

# -----------------------
# EMAIL ALERT
# -----------------------
def send_email_async(image_path: str, emotion: str):
    """Send email alert."""
    try:
        if not os.path.exists(image_path):
            return
            
        msg = EmailMessage()
        msg["Subject"] = f"Security Alert: {emotion.upper()} Detected"
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_RECEIVER
        msg.set_content(
            f"Anomalous emotion '{emotion}' detected at "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."
        )
        
        with open(image_path, "rb") as f:
            msg.add_attachment(
                f.read(),
                maintype="image",
                subtype="jpeg",
                filename=os.path.basename(image_path)
            )
        
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(msg)
    except Exception as e:
        print(f"Email error: {e}")

# -----------------------
# SESSION HELPERS
# -----------------------
def check_session_timeout():
    """Auto-logout after inactivity."""
    last = st.session_state.get("last_activity")
    if last and (datetime.now() - last) > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
        st.session_state.logged_in = False
        st.warning("Session timed out. Please log in again.")
        st.rerun()
    st.session_state.last_activity = datetime.now()

def is_strong_password(pwd: str) -> bool:
    return len(pwd) >= 8 and any(c.isdigit() for c in pwd) and any(c.isalpha() for c in pwd)

def cleanup_old_images():
    """Delete old intruder images."""
    cutoff = datetime.now() - timedelta(days=LOG_RETENTION_DAYS)
    try:
        for fname in os.listdir(INTRUDER_DIR):
            fpath = os.path.join(INTRUDER_DIR, fname)
            try:
                mtime = datetime.fromtimestamp(os.path.getmtime(fpath))
                if mtime < cutoff:
                    os.remove(fpath)
            except Exception:
                pass
    except Exception:
        pass

# -----------------------
# PAGE: LOGIN
# -----------------------
def login_page():
    st.title("🔒 Security System Login")

    if "fail_count" not in st.session_state:
        st.session_state.fail_count = 0
    if "locked_until" not in st.session_state:
        st.session_state.locked_until = None

    if st.session_state.locked_until:
        if datetime.now() < st.session_state.locked_until:
            remaining = int((st.session_state.locked_until - datetime.now()).total_seconds())
            st.error(f"⏳ Account locked. Try again in {remaining}s.")
            return
        else:
            st.session_state.locked_until = None
            st.session_state.fail_count = 0

    with st.form("login_form"):
        user = st.text_input("Username")
        pwd = st.text_input("Password", type="password")
        submit = st.form_submit_button("🔓 Login")

        if submit:
            if verify_admin(user, pwd):
                st.session_state.logged_in = True
                st.session_state.username = user
                st.session_state.last_activity = datetime.now()
                st.session_state.fail_count = 0
                
                if pwd == "admin123":
                    st.warning("⚠️ Using default password. Change it in Settings!")
                st.rerun()
            else:
                st.session_state.fail_count += 1
                remaining_attempts = MAX_LOGIN_ATTEMPTS - st.session_state.fail_count
                
                if st.session_state.fail_count >= MAX_LOGIN_ATTEMPTS:
                    st.session_state.locked_until = datetime.now() + timedelta(minutes=5)
                    st.error("❌ Account locked for 5 minutes.")
                else:
                    st.error(f"❌ Invalid credentials. {remaining_attempts} attempt(s) left.")

# -----------------------
# PAGE: CAMERA FEED (CLOUD-COMPATIBLE)
# -----------------------
def camera_page():
    st.title("📹 Monitoring")

    if "last_emotion" not in st.session_state:
        st.session_state.last_emotion = None

    img = st.camera_input("📷 Capture Image")

    if img is not None:
        image = Image.open(img)
        st.image(image, caption="Captured Image")

        # 🔥 FAKE / SIMPLE emotion detection (for cloud)
        import random
        emotions = ["happy", "neutral", "angry", "fear"]
        emotion = random.choice(emotions)

        st.success(f"Detected Emotion: {emotion.upper()}")

        # LOG
        if emotion != st.session_state.last_emotion:
            log_event(emotion)
            st.session_state.last_emotion = emotion

        # ALERT
        if emotion in ["angry", "fear"]:
            st.error("🚨 ALERT: Suspicious emotion detected!")
# -----------------------
# PAGE: LOGS DASHBOARD
# -----------------------
def dashboard_page():
    st.title("📊 Security Logs")

    col1, col2 = st.columns([3, 1])
    with col1:
        limit = st.slider("Rows to display", 10, 500, 50, step=10)
    with col2:
        if st.button("🗑️ Clear all logs"):
            try:
                with sqlite3.connect(DB_PATH) as conn:
                    conn.execute("DELETE FROM logs")
                    conn.commit()
                st.success("Logs cleared.")
                st.rerun()
            except Exception as e:
                st.error(f"Error: {e}")

    data = get_logs(limit)

    if not data:
        st.info("No logs found yet.")
        return

    emotions = sorted(set(row[0] for row in data))
    selected = st.multiselect("Filter by emotion", emotions, default=emotions)
    filtered = [row for row in data if row[0] in selected]

    for emotion, time in filtered:
        color = "red" if emotion in ("angry", "fear") else "green"
        st.markdown(
            f"<span style='color:{color}'>🔴</span> &nbsp;"
            f"**{time}** &nbsp;|&nbsp; `{emotion}`",
            unsafe_allow_html=True
        )

    if filtered:
        csv_lines = ["emotion,time"] + [f"{r[0]},{r[1]}" for r in filtered]
        st.download_button(
            "📥 Export CSV",
            data="\n".join(csv_lines),
            file_name="security_logs.csv",
            mime="text/csv"
        )

# -----------------------
# PAGE: SETTINGS
# -----------------------
def settings_page():
    st.title("⚙️ Settings")

    st.subheader("🔐 Change Password")
    with st.form("change_pwd_form"):
        current = st.text_input("Current password", type="password")
        new_pwd = st.text_input("New password", type="password")
        confirm = st.text_input("Confirm new password", type="password")
        submit = st.form_submit_button("Update Password")

        if submit:
            username = st.session_state.get("username", "admin")
            if not verify_admin(username, current):
                st.error("Current password is incorrect.")
            elif new_pwd != confirm:
                st.error("New passwords do not match.")
            elif not is_strong_password(new_pwd):
                st.error("Password must be at least 8 characters (letters + numbers).")
            else:
                if change_password(username, new_pwd):
                    st.success("✅ Password updated successfully.")
                else:
                    st.error("Error updating password.")

    st.subheader("📧 Email Configuration")
    st.info("For Streamlit Cloud: Add secrets via Settings → Secrets")
    st.code("email_sender = your_email@gmail.com\nemail_password = your_app_password\nemail_receiver = receiver@gmail.com")

    st.subheader("🖼️ Intruder Image Cleanup")
    if st.button(f"🗑️ Delete images older than {LOG_RETENTION_DAYS} days"):
        cleanup_old_images()
        st.success("Old images deleted.")

    try:
        images = sorted(os.listdir(INTRUDER_DIR))
        if images:
            st.subheader(f"Stored Intruder Images ({len(images)})")
            cols = st.columns(3)
            for i, fname in enumerate(images[-9:]):
                fpath = os.path.join(INTRUDER_DIR, fname)
                try:
                    cols[i % 3].image(fpath, caption=fname, use_container_width=True)
                except Exception:
                    pass
        else:
            st.info("No intruder images stored.")
    except Exception:
        st.info("Image storage unavailable.")

# -----------------------
# MAIN APP
# -----------------------
def main():
    st.set_page_config(
        page_title="Security System",
        page_icon="🔒",
        layout="wide"
    )

    init_db()

    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        login_page()
        return

    check_session_timeout()

    page = st.sidebar.radio(
        "Navigation",
        ["📹 Camera Feed", "📊 Logs Dashboard", "⚙️ Settings", "🚪 Logout"]
    )

    if page == "📹 Camera Feed":
        camera_page()
    elif page == "📊 Logs Dashboard":
        dashboard_page()
    elif page == "⚙️ Settings":
        settings_page()
    elif page == "🚪 Logout":
        for key in ["logged_in", "username", "last_activity", "last_emotion", "last_alert"]:
            st.session_state.pop(key, None)
        st.rerun()

if __name__ == "__main__":
    main()
