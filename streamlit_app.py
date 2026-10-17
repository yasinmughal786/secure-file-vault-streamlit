
import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
from pathlib import Path

st.set_page_config(page_title="Secure File Vault", page_icon="🔐")

st.title("🔐 Secure File Vault")
st.write("Encrypt and decrypt your files securely.")

encrypt_tab, decrypt_tab = st.tabs(["Encrypt File", "Decrypt File"])

with encrypt_tab:
    st.subheader("Encrypt your file")
    file = st.file_uploader("Choose a photo or document", key="encrypt")

    if st.button("Encrypt File"):
        if file is None:
            st.warning("Please select a file first.")
        else:
            key = Fernet.generate_key()
            cipher = Fernet(key)
            encrypted_data = cipher.encrypt(file.getvalue())

            st.session_state["encrypted_data"] = encrypted_data
            st.session_state["key"] = key
            st.session_state["filename"] = file.name + ".encrypted"

            st.success("Encryption successful!")

    if "encrypted_data" in st.session_state:
        st.download_button(
            "Download Encrypted File",
            st.session_state["encrypted_data"],
            file_name=st.session_state["filename"],
        )
        st.download_button(
            "Download Secret Key",
            st.session_state["key"],
            file_name="secret_key.key",
        )
        st.warning("Keep your secret key safe!")

with decrypt_tab:
    st.subheader("Decrypt your file")
    encrypted_file = st.file_uploader(
        "Upload encrypted file", key="decrypt"
    )
    key_file = st.file_uploader(
        "Upload matching secret key", key="key"
    )

    if st.button("Decrypt File"):
        if encrypted_file is None or key_file is None:
            st.warning("Upload both files.")
        else:
            try:
                cipher = Fernet(key_file.getvalue())
                decrypted_data = cipher.decrypt(encrypted_file.getvalue())

                name = Path(encrypted_file.name).name
                if name.endswith(".encrypted"):
                    name = name[:-10]
                else:
                    name = "decrypted_" + name

                st.session_state["decrypted_data"] = decrypted_data
                st.session_state["decrypted_name"] = name
                st.success("Decryption successful!")

            except (InvalidToken, ValueError, TypeError):
                st.error("Wrong key or invalid encrypted file.")

    if "decrypted_data" in st.session_state:
        st.download_button(
            "Download Decrypted File",
            st.session_state["decrypted_data"],
            file_name=st.session_state["decrypted_name"],
        )
