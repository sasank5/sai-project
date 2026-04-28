import streamlit as st
import cv2
import os
import sqlite3
import threading
import smtplib
import numpy as np
from deepface import DeepFace
from email.message import EmailMessage
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# -----------------------
# CONFIG
# -----------------------
load_dotenv()

EMAIL_SENDER   = os.getenv("EMAIL_SENDER", "aa@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "aa@11")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER", "chvj8121@gmail.com")

BASE_DIR      = os.getcwd()
DB_PATH       = os.path.join(BASE_DIR, "security.db")
INTRUDER_DIR  = os.path.join(BASE_DIR, "intruders")
MAX_LOGIN_ATTEMPTS = 5
SESSION_TIMEOUT_MINUTES = 30
LOG_RETENTION_DAYS = 7   # days to keep intruder images

os.makedirs(INTRUDER_DIR, exist_ok=True)

# -----------------------
# DATABASE
# -----------------------
def init_db():
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
        # Seed default admin only if not present
        if not c.execute("SELECT 1 FROM admin WHERE username='admin'").fetchone():
            c.execute(
                "INSERT INTO admin (username, password) VALUES (?, ?)",
                ("admin", generate_password_hash("admin123"))
            )
        conn.commit()


def log_event(emotion: str):
    """Insert a single log row. Called only on emotion change."""
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
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT emotion, time FROM logs ORDER BY id DESC LIMIT ?", (limit,))
        return c.fetchall()


def verify_admin(username: str, password: str):
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT password FROM admin WHERE username=?", (username,)
        ).fetchone()
    return row and check_password_hash(row[0], password)


def change_password(username: str, new_password: str):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE admin SET password=? WHERE username=?",
            (generate_password_hash(new_password), username)
        )
        conn.commit()

# -----------------------
# EMAIL (threaded)
# -----------------------
def send_email_async(image_path: str, emotion: str):
    """Fire-and-forget email in a daemon thread to avoid blocking the camera loop."""
    def _send():
        try:
            msg = EmailMessage()
            msg["Subject"] = f"Security Alert: {emotion.upper()} Detected"
            msg["From"]    = EMAIL_SENDER
            msg["To"]      = EMAIL_RECEIVER
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
            # Logged to console; st.error can't be called from a background thread
            print(f"[Email error] {e}")

    threading.Thread(target=_send, daemon=True).start()

# -----------------------
# IMAGE RETENTION CLEANUP
# -----------------------
def cleanup_old_images():
    """Delete intruder images older than LOG_RETENTION_DAYS."""
    cutoff = datetime.now() - timedelta(days=LOG_RETENTION_DAYS)
    for fname in os.listdir(INTRUDER_DIR):
        fpath = os.path.join(INTRUDER_DIR, fname)
        try:
            mtime = datetime.fromtimestamp(os.path.getmtime(fpath))
            if mtime < cutoff:
                os.remove(fpath)
        except Exception:
            pass

# -----------------------
# SESSION HELPERS
# -----------------------
def check_session_timeout():
    """Auto-logout after SESSION_TIMEOUT_MINUTES of inactivity."""
    last = st.session_state.get("last_activity")
    if last and (datetime.now() - last) > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
        st.session_state.logged_in = False
        st.warning("Session timed out. Please log in again.")
        st.rerun()
    st.session_state.last_activity = datetime.now()


def is_strong_password(pwd: str) -> bool:
    return len(pwd) >= 8 and any(c.isdigit() for c in pwd) and any(c.isalpha() for c in pwd)

# -----------------------
# PAGE: LOGIN
# -----------------------
def login_page():
    st.title("Security System Login")

    # Initialise attempt counter
    if "fail_count" not in st.session_state:
        st.session_state.fail_count = 0
    if "locked_until" not in st.session_state:
        st.session_state.locked_until = None

    # Lockout check
    if st.session_state.locked_until:
        remaining = (st.session_state.locked_until - datetime.now()).seconds
        if datetime.now() < st.session_state.locked_until:
            st.error(f"Too many failed attempts. Try again in {remaining}s.")
            return
        else:
            st.session_state.locked_until = None
            st.session_state.fail_count = 0

    with st.form("login_form"):
        user   = st.text_input("Username")
        pwd    = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")   # FIXED: correct method name

        if submit:
            if verify_admin(user, pwd):
                st.session_state.logged_in     = True
                st.session_state.username      = user
                st.session_state.last_activity = datetime.now()
                st.session_state.fail_count    = 0
                # Warn if still using default password
                if pwd == "admin123":
                    st.warning(
                        "You are using the default password. "
                        "Please change it in Settings."
                    )
                st.rerun()
            else:
                st.session_state.fail_count += 1
                remaining_attempts = MAX_LOGIN_ATTEMPTS - st.session_state.fail_count
                if st.session_state.fail_count >= MAX_LOGIN_ATTEMPTS:
                    st.session_state.locked_until = datetime.now() + timedelta(minutes=5)
                    st.error("Account locked for 5 minutes due to too many failed attempts.")
                else:
                    st.error(f"Invalid credentials. {remaining_attempts} attempt(s) remaining.")

# -----------------------
# PAGE: CAMERA FEED
# -----------------------
def camera_page():
    st.title("Real-time Monitoring")

    uploaded = st.file_uploader("Upload a video or image", type=["mp4", "avi", "jpg", "jpeg", "png"])
    if not uploaded:
        return

    # Save to temp file
    import tempfile
    suffix = os.path.splitext(uploaded.name)[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(uploaded.read())
        tmp_path = tmp.name

    # Image
    if suffix.lower() in (".jpg", ".jpeg", ".png"):
        frame = cv2.imdecode(np.frombuffer(open(tmp_path, "rb").read(), np.uint8), cv2.IMREAD_COLOR)
        _analyze_and_display(frame)

    # Video
    else:
        cap = cv2.VideoCapture(tmp_path)
        stframe = st.image([])
        while cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break
            _analyze_and_display(frame, stframe)
        cap.release()

def _analyze_and_display(frame, placeholder=None):
    try:
        results = DeepFace.analyze(frame, actions=["emotion"], enforce_detection=False, silent=True)
        emotion = results[0]["dominant_emotion"]
        color = (0, 0, 255) if emotion in ("angry", "fear") else (0, 255, 0)
        cv2.putText(frame, f"{emotion.upper()}", (30, 50), cv2.FONT_HERSHEY_SIMPLEX, 1, color, 2)
        log_event(emotion)
        if emotion in ("angry", "fear"):
            path = os.path.join(INTRUDER_DIR, f"alert_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg")
            cv2.imwrite(path, frame)
            send_email_async(path, emotion)
            st.error(f"Alert: {emotion} detected!")
    except Exception as e:
        st.warning(f"Detection error: {e}")

    if placeholder:
        placeholder.image(frame, channels="BGR")
    else:
        st.image(frame, channels="BGR")
# -----------------------
# PAGE: LOGS DASHBOARD
# -----------------------
def dashboard_page():
    st.title("Security Logs")

    col1, col2 = st.columns([3, 1])
    with col1:
        limit = st.slider("Rows to display", 10, 500, 50, step=10)
    with col2:
        if st.button("Clear all logs"):
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("DELETE FROM logs")
                conn.commit()
            st.success("Logs cleared.")
            st.rerun()

    data = get_logs(limit)

    if not data:
        st.info("No logs found yet.")
        return

    # Emotion filter
    emotions = sorted(set(row[0] for row in data))
    selected = st.multiselect("Filter by emotion", emotions, default=emotions)
    filtered = [row for row in data if row[0] in selected]

    # Colour-code rows
    for emotion, time in filtered:
        color = "red" if emotion in ("angry", "fear") else "green"
        st.markdown(
            f"<span style='color:{color}'>⬤</span> &nbsp;"
            f"**{time}** &nbsp;|&nbsp; `{emotion}`",
            unsafe_allow_html=True
        )

    # CSV export
    if filtered:
        csv_lines = ["emotion,time"] + [f"{r[0]},{r[1]}" for r in filtered]
        st.download_button(
            "Export CSV",
            data="\n".join(csv_lines),
            file_name="security_logs.csv",
            mime="text/csv"
        )

# -----------------------
# PAGE: SETTINGS
# -----------------------
def settings_page():
    st.title("Settings")

    st.subheader("Change Password")
    with st.form("change_pwd_form"):
        current = st.text_input("Current password", type="password")
        new_pwd = st.text_input("New password", type="password")
        confirm = st.text_input("Confirm new password", type="password")
        submit  = st.form_submit_button("Update Password")

        if submit:
            username = st.session_state.get("username", "admin")
            if not verify_admin(username, current):
                st.error("Current password is incorrect.")
            elif new_pwd != confirm:
                st.error("New passwords do not match.")
            elif not is_strong_password(new_pwd):
                st.error("Password must be at least 8 characters and contain letters and numbers.")
            else:
                change_password(username, new_pwd)
                st.success("Password updated successfully.")

    st.subheader("Email Configuration")
    st.info(
        "Set EMAIL_SENDER, EMAIL_PASSWORD, and EMAIL_RECEIVER "
        "in a `.env` file in the project root. Restart the app after changes."
    )
    st.code(
        "EMAIL_SENDER=your_email@gmail.com\n"
        "EMAIL_PASSWORD=your_app_password\n"
        "EMAIL_RECEIVER=receiver@gmail.com",
        language="ini"
    )

    st.subheader("Intruder Image Cleanup")
    if st.button(f"Delete images older than {LOG_RETENTION_DAYS} days"):
        cleanup_old_images()
        st.success("Old intruder images deleted.")

    # Show stored images
    images = sorted(os.listdir(INTRUDER_DIR))
    if images:
        st.subheader(f"Stored Intruder Images ({len(images)})")
        cols = st.columns(3)
        for i, fname in enumerate(images[-9:]):   # show last 9
            fpath = os.path.join(INTRUDER_DIR, fname)
            cols[i % 3].image(fpath, caption=fname, use_container_width=True)
    else:
        st.info("No intruder images stored.")

# -----------------------
# MAIN
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

    # Session timeout check on every interaction
    check_session_timeout()

    page = st.sidebar.radio(
        "Navigation",
        ["Camera Feed", "Logs Dashboard", "Settings", "Logout"]
    )

    if page == "Camera Feed":
        camera_page()
    elif page == "Logs Dashboard":
        dashboard_page()
    elif page == "Settings":
        settings_page()
    elif page == "Logout":
        for key in ["logged_in", "username", "last_activity", "last_emotion", "last_alert"]:
            st.session_state.pop(key, None)
        st.rerun()


if __name__ == "__main__":
    main()
