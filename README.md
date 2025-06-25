# 🔐 Secure Encryption & Decryption Application

![22](https://github.com/user-attachments/assets/70b1ec54-4221-4973-8aa3-a407444f34a9)



A user-friendly **PyQt5 GUI application** for encrypting and decrypting text or files using popular cryptographic algorithms. Perfect for learning, experimenting, or securing basic data.

---

## 🖥️ Features

✅ Simple, intuitive graphical interface
✅ Supports **DES**, **AES**, **RSA**, and **RC4** algorithms
✅ Text and file encryption/decryption
✅ Automatic key generation (where applicable)
✅ Option to view generated keys or IVs
✅ Base64 encoding for safe display and storage
✅ RSA key pairs are auto-generated and saved for persistent use

---


## 🔑 Supported Algorithms & Explanations

### 1. **DES (Data Encryption Standard)**

* Symmetric block cipher
* Operates on 64-bit blocks with a **fixed 8-byte (64-bit) key**
* Suitable for simple encryption tasks
* **Note:** DES is considered outdated for serious security but still useful for learning

### 2. **AES (Advanced Encryption Standard)**

* Modern symmetric block cipher
* Supports **16, 24, or 32-byte keys** (128, 192, or 256 bits)
* Highly secure and efficient
* Used in many industry-standard systems (e.g., HTTPS, VPNs)

### 3. **RSA (Rivest–Shamir–Adleman)**

* Asymmetric encryption (public/private key pair)
* Automatically generates **2048-bit RSA key pairs**
* Public key for encryption, private key for decryption
* Commonly used for secure key exchange or small data encryption

### 4. **RC4 (Rivest Cipher 4)**

* Symmetric stream cipher
* Requires a **16-byte key**
* Lightweight and fast, but generally considered weak for modern security needs
* Still useful for basic understanding or non-critical applications

---

## 📂 File Encryption/Decryption

* Select a file, encrypt its contents, and save the encrypted version
* Decrypt previously encrypted files with the correct key

---

## 💡 Notes

* **RSA keys are stored in the same folder** as the app (`rsa_private.pem`, `rsa_public.pem`)
* For **DES**, **AES**, and **RC4**, you can enter your own key or leave it blank to auto-generate
* The generated key and IV (for DES/AES) can be shown with the "Show Generated Key/IV" option
* All encrypted outputs are Base64 encoded for easy display and copying

---

## 🛡️ Disclaimer

This application is for educational purposes. While it demonstrates real cryptography, do **not** use it for protecting highly sensitive information in production environments.
