import sys
import os
import base64
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QTextEdit, QPushButton, QComboBox,
    QVBoxLayout, QHBoxLayout, QMessageBox, QFileDialog, QCheckBox
)
from PyQt5.QtGui import QFont
from Crypto.Cipher import DES, AES, PKCS1_OAEP, ARC4
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class CryptoApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Encryption & Decryption App")
        self.setGeometry(100, 100, 600, 500)

        self.algorithm_label = QLabel("Select Algorithm:")
        self.algorithm_combo = QComboBox() 
        self.algorithm_combo.addItems(["DES", "AES", "RSA", "RC4"])
        self.algorithm_combo.currentIndexChanged.connect(self.update_key_field)

        self.key_label = QLabel("Enter Key (leave blank to auto-generate where allowed):")
        self.key_input = QLineEdit()

        self.text_label = QLabel("Enter Text:")
        self.text_edit = QTextEdit()

        self.result_label = QLabel("Result:")
        self.result_edit = QTextEdit()
        self.result_edit.setReadOnly(True)

        self.encrypt_button = QPushButton("Encrypt Text")
        self.decrypt_button = QPushButton("Decrypt Text")
        self.file_encrypt_button = QPushButton("Encrypt File")
        self.file_decrypt_button = QPushButton("Decrypt File")

        self.show_key_checkbox = QCheckBox("Show Generated Key/IV")

        self.encrypt_button.clicked.connect(self.encrypt_text)
        self.decrypt_button.clicked.connect(self.decrypt_text)
        self.file_encrypt_button.clicked.connect(self.encrypt_file)
        self.file_decrypt_button.clicked.connect(self.decrypt_file)

        layout = QVBoxLayout()
        layout.addWidget(self.algorithm_label)
        layout.addWidget(self.algorithm_combo)
        layout.addWidget(self.key_label)
        layout.addWidget(self.key_input)
        layout.addWidget(self.text_label)
        layout.addWidget(self.text_edit)
        layout.addWidget(self.result_label)
        layout.addWidget(self.result_edit)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)
        layout.addLayout(button_layout)

        file_layout = QHBoxLayout()
        file_layout.addWidget(self.file_encrypt_button)
        file_layout.addWidget(self.file_decrypt_button)
        layout.addLayout(file_layout)

        layout.addWidget(self.show_key_checkbox)

        self.setLayout(layout)

        self.rsa_key_path = "rsa_private.pem"
        self.rsa_public_key_path = "rsa_public.pem"

        if not os.path.exists(self.rsa_key_path):
            self.generate_rsa_keys()

        self.update_key_field()  # Initialize key field based on default selection

    def update_key_field(self):
        algorithm = self.algorithm_combo.currentText()

        if algorithm == "DES":
            self.key_input.setPlaceholderText("8 bytes key required")
            self.key_input.setMaxLength(8)
            self.key_input.setEnabled(True)
        elif algorithm == "AES":
            self.key_input.setPlaceholderText("16, 24, or 32 bytes key recommended")
            self.key_input.setMaxLength(32)
            self.key_input.setEnabled(True)
        elif algorithm == "RC4":
            self.key_input.setPlaceholderText("16 bytes key recommended")
            self.key_input.setMaxLength(16)
            self.key_input.setEnabled(True)
        elif algorithm == "RSA":
            self.key_input.setPlaceholderText("RSA keys auto-generated")
            self.key_input.clear()
            self.key_input.setEnabled(False)

    def generate_rsa_keys(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        with open(self.rsa_key_path, "wb") as f:
            f.write(private_key)
        with open(self.rsa_public_key_path, "wb") as f:
            f.write(public_key)

    def get_rsa_keys(self):
        with open(self.rsa_key_path, "rb") as f:
            private_key = RSA.import_key(f.read())
        with open(self.rsa_public_key_path, "rb") as f:
            public_key = RSA.import_key(f.read())
        return private_key, public_key

    def encrypt_text(self):
        algorithm = self.algorithm_combo.currentText()
        text = self.text_edit.toPlainText().encode()
        key_input = self.key_input.text().encode()

        try:
            if algorithm == "DES":
                if key_input and len(key_input) != 8:
                    raise ValueError("DES key must be exactly 8 bytes.")
                key = key_input if key_input else get_random_bytes(8)
                iv = get_random_bytes(8)
                cipher = DES.new(key, DES.MODE_CBC, iv)
                encrypted = iv + cipher.encrypt(pad(text, 8))
            elif algorithm == "AES":
                if key_input and len(key_input) not in (16, 24, 32):
                    raise ValueError("AES key must be 16, 24, or 32 bytes.")
                key = key_input if key_input else get_random_bytes(16)
                iv = get_random_bytes(16)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted = iv + cipher.encrypt(pad(text, 16))
            elif algorithm == "RSA":
                _, public_key = self.get_rsa_keys()
                cipher = PKCS1_OAEP.new(public_key)
                encrypted = cipher.encrypt(text)
            elif algorithm == "RC4":
                if key_input and len(key_input) != 16:
                    raise ValueError("RC4 key must be exactly 16 bytes.")
                key = key_input if key_input else get_random_bytes(16)
                cipher = ARC4.new(key)
                encrypted = cipher.encrypt(text)
            else:
                encrypted = b""

            encoded = base64.b64encode(encrypted).decode()
            self.result_edit.setPlainText(encoded)

            if self.show_key_checkbox.isChecked() and algorithm != "RSA":
                QMessageBox.information(self, "Key Info", f"Key: {key.hex()}\n(IV shown within ciphertext for DES/AES)")

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def decrypt_text(self):
        algorithm = self.algorithm_combo.currentText()
        encoded_text = self.result_edit.toPlainText()
        key_input = self.key_input.text().encode()

        try:
            encrypted = base64.b64decode(encoded_text)

            if algorithm == "DES":
                if len(key_input) != 8:
                    raise ValueError("DES key must be exactly 8 bytes.")
                iv = encrypted[:8]
                cipher = DES.new(key_input, DES.MODE_CBC, iv)
                decrypted = unpad(cipher.decrypt(encrypted[8:]), 8)
            elif algorithm == "AES":
                if len(key_input) not in (16, 24, 32):
                    raise ValueError("AES key must be 16, 24, or 32 bytes.")
                iv = encrypted[:16]
                cipher = AES.new(key_input, AES.MODE_CBC, iv)
                decrypted = unpad(cipher.decrypt(encrypted[16:]), 16)
            elif algorithm == "RSA":
                private_key, _ = self.get_rsa_keys()
                cipher = PKCS1_OAEP.new(private_key)
                decrypted = cipher.decrypt(encrypted)
            elif algorithm == "RC4":
                if len(key_input) != 16:
                    raise ValueError("RC4 key must be exactly 16 bytes.")
                cipher = ARC4.new(key_input)
                decrypted = cipher.decrypt(encrypted)
            else:
                decrypted = b""

            self.text_edit.setPlainText(decrypted.decode())

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def encrypt_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if not path:
            return

        with open(path, "rb") as f:
            data = f.read()

        self.text_edit.setPlainText(data.decode(errors='ignore'))
        self.encrypt_text()

        encrypted_data = base64.b64decode(self.result_edit.toPlainText())

        save_path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted File")
        if save_path:
            with open(save_path, "wb") as f:
                f.write(encrypted_data)
            QMessageBox.information(self, "Success", "File encrypted successfully.")

    def decrypt_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt")
        if not path:
            return

        with open(path, "rb") as f:
            encrypted_data = f.read()

        encoded_text = base64.b64encode(encrypted_data).decode()
        self.result_edit.setPlainText(encoded_text)
        self.decrypt_text()

        save_path, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File")
        if save_path:
            with open(save_path, "wb") as f:
                f.write(self.text_edit.toPlainText().encode())
            QMessageBox.information(self, "Success", "File decrypted successfully.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CryptoApp()
    window.show()
    sys.exit(app.exec_())
