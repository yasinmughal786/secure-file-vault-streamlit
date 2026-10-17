import base64
import hashlib
import hmac
import io
import os
import secrets
import time
from datetime import datetime

import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---------------------------------------------------------
# Secure File Vault — single-file Streamlit application
# ---------------------------------------------------------
APP_NAME = "Secure File Vault"
FORMAT_MAGIC = b"SFV1"
PBKDF2_ITERATIONS = 600_000
MAX_FILE_SIZE_MB = 200

st.set_page_config(
    page_title=APP_NAME,
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Read credentials from Streamlit secrets. Create .streamlit/secrets.toml locally,
# and configure the same values in Streamlit Cloud -> App settings -> Secrets.
def get_login_credentials():
    try:
        username = str(st.secrets["auth"]["username"])
        password = str(st.secrets["auth"]["password"])
        return username, password
    except Exception:
        return None, None


def verify_login(username, password):
    configured_username, configured_password = get_login_credentials()
    if not configured_username or not configured_password:
        return False, "Login is not configured yet. Create .streamlit/secrets.toml (instructions below)."
    username_ok = hmac.compare_digest(username.encode(), configured_username.encode())
    password_ok = hmac.compare_digest(password.encode(), configured_password.encode())
    return username_ok and password_ok, "Incorrect username or password."


def derive_fernet_key(password: str, salt: bytes) -> bytes:
    """Derive an encryption key from a user-supplied password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_bytes(data: bytes, password: str):
    salt = secrets.token_bytes(16)
    key = derive_fernet_key(password, salt)
    token = Fernet(key).encrypt(data)
    # Format: magic (4 bytes) + salt (16 bytes) + Fernet token
    return FORMAT_MAGIC + salt + token, hashlib.sha256(data).hexdigest()


def decrypt_bytes(payload: bytes, password: str):
    if len(payload) < 20 or payload[:4] != FORMAT_MAGIC:
        raise ValueError("This file is not a Secure File Vault .sfv file, or it is damaged.")
    salt = payload[4:20]
    token = payload[20:]
    key = derive_fernet_key(password, salt)
    data = Fernet(key).decrypt(token)
    return data, hashlib.sha256(data).hexdigest()


def format_size(size):
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.2f} MB"


def add_activity(action, filename, status, detail=""):
    st.session_state.activity.insert(
        0,
        {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "file": filename,
            "status": status,
            "detail": detail,
        },
    )
    st.session_state.activity = st.session_state.activity[:100]


for key, default in {
    "authenticated": False,
    "activity": [],
    "operations": 0,
    "files_secured": 0,
    "last_result": None,
}.items():
    if key not in st.session_state:
        st.session_state[key] = default

# Professional dark UI styling
st.markdown(
    """
    <style>
    .stApp { background: radial-gradient(circle at top right, #10234b 0, #081225 38%, #050b17 100%); color: #eef4ff; }
    [data-testid="stSidebar"] { background: #071326; border-right: 1px solid #18335b; }
    [data-testid="stHeader"] { background: rgba(0,0,0,0); }
    .hero { padding: 1.1rem 1.4rem; border: 1px solid #1a3a67; border-radius: 20px;
            background: linear-gradient(120deg, rgba(16,54,112,.72), rgba(8,18,39,.85)); margin-bottom: 1rem; }
    .hero h1 { margin: 0; font-size: 2.25rem; color: #f4f8ff; }
    .hero p { margin: .4rem 0 0 0; color: #b9d2ff; }
    div[data-testid="stMetric"] { background: rgba(13,30,60,.78); border: 1px solid #1a3b69; padding: 1rem; border-radius: 15px; }
    div.stButton > button, div.stDownloadButton > button { border-radius: 10px; font-weight: 650; border: 1px solid #2b74ed; }
    .note { color: #adc2e6; font-size: .9rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

# Login screen
if not st.session_state.authenticated:
    st.markdown(
        '<div class="hero"><h1>🔐 Secure File Vault</h1>'
        '<p>Private file encryption, decryption and integrity verification.</p></div>',
        unsafe_allow_html=True,
    )
    left, center, right = st.columns([1, 1.15, 1])
    with center:
        st.subheader("Sign in")
        st.caption("Sign in with the credentials configured by the app owner.")
        with st.form("login_form"):
            username_input = st.text_input("Username")
            password_input = st.text_input("Password", type="password")
            submit = st.form_submit_button("Sign in", use_container_width=True)
        if submit:
            ok, message = verify_login(username_input, password_input)
            if ok:
                st.session_state.authenticated = True
                st.session_state.login_name = username_input
                st.rerun()
            else:
                st.error(message)
        st.info("Owner setup: create `.streamlit/secrets.toml` locally and add the same values in Streamlit Cloud → App settings → Secrets.")
    st.stop()

# Sidebar
with st.sidebar:
    st.markdown("## 🛡️ Secure File Vault")
    st.caption("ENCRYPT • PROTECT • VERIFY")
    page = st.radio(
        "Navigation",
        ["Dashboard", "Encrypt File", "Decrypt File", "Activity Log", "About"],
        label_visibility="collapsed",
    )
    st.divider()
    st.success("Session authenticated")
    st.caption("Your files are processed in app memory; this demo does not intentionally save uploaded files to disk.")
    if st.button("Log out", use_container_width=True):
        st.session_state.authenticated = False
        st.session_state.pop("login_name", None)
        st.rerun()

st.markdown(
    f'<div class="hero"><h1>🔐 Secure File Vault</h1>'
    f'<p>Professional file encryption & decryption · Signed in as {st.session_state.get("login_name", "user")}</p></div>',
    unsafe_allow_html=True,
)

if page == "Dashboard":
    c1, c2, c3 = st.columns(3)
    c1.metric("Session operations", st.session_state.operations)
    c2.metric("Files secured", st.session_state.files_secured)
    c3.metric("Recent activity entries", len(st.session_state.activity))
    st.subheader("Vault controls")
    a, b = st.columns(2)
    with a:
        st.markdown("### 🔒 Encrypt a file")
        st.write("Encrypt a document, photo, or other file with a password.")
        if st.button("Open Encrypt File", use_container_width=True):
            st.session_state["navigation_target"] = "Encrypt File"
            st.info("Choose **Encrypt File** from the sidebar.")
    with b:
        st.markdown("### 🔓 Decrypt a file")
        st.write("Restore a file using the same password used during encryption.")
        if st.button("Open Decrypt File", use_container_width=True):
            st.info("Choose **Decrypt File** from the sidebar.")
    st.warning("Important: if you lose the encryption password, the encrypted file cannot be recovered. Use a strong, unique password and keep it safe.")
    st.subheader("Recent activity")
    if st.session_state.activity:
        st.dataframe(st.session_state.activity[:5], use_container_width=True, hide_index=True)
    else:
        st.caption("No operations in this session yet.")

elif page == "Encrypt File":
    st.subheader("🔒 Encrypt your file")
    st.write("Choose a file, set a strong encryption password, and download the encrypted `.sfv` file.")
    uploaded = st.file_uploader("Choose a photo or document", key="encrypt_upload")
    password = st.text_input("Create encryption password", type="password", key="encrypt_password")
    confirm = st.text_input("Confirm encryption password", type="password", key="encrypt_confirm")
    st.caption("Use a strong password. It is not stored by this app.")
    if uploaded is not None:
        st.caption(f"Selected: **{uploaded.name}** · {format_size(uploaded.size)}")
        if uploaded.size > MAX_FILE_SIZE_MB * 1024 * 1024:
            st.error(f"Maximum file size is {MAX_FILE_SIZE_MB} MB.")
        elif st.button("Encrypt File", type="primary", use_container_width=True):
            if not password:
                st.error("Please enter an encryption password.")
            elif len(password) < 12:
                st.error("Use at least 12 characters for the encryption password.")
            elif password != confirm:
                st.error("Passwords do not match.")
            else:
                try:
                    encrypted, original_hash = encrypt_bytes(uploaded.getvalue(), password)
                    output_name = uploaded.name + ".sfv"
                    encrypted_hash = hashlib.sha256(encrypted).hexdigest()
                    st.session_state.operations += 1
                    st.session_state.files_secured += 1
                    st.session_state.last_result = {
                        "name": output_name,
                        "original_hash": original_hash,
                        "encrypted_hash": encrypted_hash,
                    }
                    add_activity("Encrypt", uploaded.name, "Success", f"Original SHA-256: {original_hash}")
                    st.success("File encrypted successfully!")
                    st.write("**Encrypted output:**", output_name)
                    st.write("**Original file SHA-256:**")
                    st.code(original_hash)
                    st.write("**Encrypted file SHA-256:**")
                    st.code(encrypted_hash)
                    st.download_button(
                        "⬇️ Download Encrypted File",
                        data=encrypted,
                        file_name=output_name,
                        mime="application/octet-stream",
                        use_container_width=True,
                    )
                except Exception as exc:
                    add_activity("Encrypt", uploaded.name, "Failed", str(exc))
                    st.error(f"Encryption failed: {exc}")

elif page == "Decrypt File":
    st.subheader("🔓 Decrypt your file")
    st.write("Upload a `.sfv` file and enter the same password used to encrypt it.")
    encrypted_upload = st.file_uploader(
        "Upload encrypted .sfv file",
        key="decrypt_upload",
    )
    decrypt_password = st.text_input(
        "Encryption password",
        type="password",
        key="decrypt_password",
    )
    if encrypted_upload is not None:
        st.caption(f"Selected: **{encrypted_upload.name}** · {format_size(encrypted_upload.size)}")
        if encrypted_upload.size > MAX_FILE_SIZE_MB * 1024 * 1024:
            st.error(f"Maximum file size is {MAX_FILE_SIZE_MB} MB.")
        elif st.button("Decrypt File", type="primary", use_container_width=True):
            try:
                restored, restored_hash = decrypt_bytes(encrypted_upload.getvalue(), decrypt_password)
                output_name = encrypted_upload.name[:-4] if encrypted_upload.name.endswith(".sfv") else "decrypted_file"
                st.session_state.operations += 1
                add_activity("Decrypt", encrypted_upload.name, "Success", f"Restored SHA-256: {restored_hash}")
                st.success("Decryption successful! The original file has been restored.")
                st.write("**Restored file:**", output_name)
                st.write("**Restored file SHA-256:**")
                st.code(restored_hash)
                st.download_button(
                    "⬇️ Download Decrypted File",
                    data=restored,
                    file_name=output_name,
                    mime="application/octet-stream",
                    use_container_width=True,
                )
                st.info("Integrity note: this hash identifies the restored file. Compare it with the original-file hash shown during encryption to verify the bytes match.")
            except (InvalidToken, ValueError):
                add_activity("Decrypt", encrypted_upload.name, "Failed", "Wrong password or invalid/damaged file")
                st.error("Decryption failed. Check that you selected the matching .sfv file and entered the exact same password.")
            except Exception:
                add_activity("Decrypt", encrypted_upload.name, "Failed", "Unexpected error")
                st.error("Decryption failed because of an unexpected error. Check the app logs if you own this deployment.")

elif page == "Activity Log":
    st.subheader("📋 Activity Log")
    st.caption("This log is session-only and may reset when the app restarts or the session ends.")
    if st.session_state.activity:
        st.dataframe(st.session_state.activity, use_container_width=True, hide_index=True)
        csv_data = io.StringIO()
        import csv
        writer = csv.DictWriter(csv_data, fieldnames=["time", "action", "file", "status", "detail"])
        writer.writeheader()
        writer.writerows(st.session_state.activity)
        st.download_button("Download activity log (CSV)", csv_data.getvalue(), "vault_activity.csv", "text/csv")
    else:
        st.info("No activity recorded yet. Encrypt or decrypt a file to create an entry.")

elif page == "About":
    st.subheader("About Secure File Vault")
    st.write(
        "Secure File Vault is a learning/demo application for password-derived file encryption, "
        "downloadable encrypted files, SHA-256 integrity fingerprints, and session activity tracking."
    )
    st.markdown(
        """
        **Security notes**
        - File encryption uses Fernet authenticated encryption.
        - A key is derived from the encryption password using PBKDF2-HMAC-SHA256 and a random salt stored in the encrypted file.
        - The app does not store the encryption password.
        - Login credentials should be configured through Streamlit secrets, never hardcoded in public source code.
        - Activity history and metrics are held in the current Streamlit session, not a permanent audit database.
        - This is a portfolio/demo project, not a formally audited enterprise vault.
        """
    )
