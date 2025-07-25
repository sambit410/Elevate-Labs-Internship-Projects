# Secure Vault - File Encryption Tool

## Description
A simple GUI application for encrypting and decrypting files using AES-256 encryption. Protect your sensitive files with password-based security.

## Requirements
- Python 3.7+
- Tkinter (usually included with Python)

1. Install required packages:
   ```bash
   pip install cryptography
   ```

## How to Use
1. Run the application:
   ```bash
   python secure_vault.py
   ```

2. In the GUI:
   - Enter a password and click "Generate Key"
   - Click "Encrypt File" to protect a file
   - Click "Decrypt Selected" to recover a file

## Features
- Encrypt/decrypt any file type
- Password-based key generation
- File integrity verification
- Simple graphical interface

## Security Note
- Files cannot be recovered if you lose the password
- Always keep backups of important files
