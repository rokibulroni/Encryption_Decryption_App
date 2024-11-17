
# Encryption/Decryption App

This GUI-based application supports AES and RSA encryption and decryption. It is built using Python's `tkinter` for GUI and `pycryptodome` for cryptographic operations.

## Features
- **AES Encryption and Decryption**: Requires a 16-byte key.
- **RSA Encryption and Decryption**: Generate keys or use pre-existing ones.

## Requirements
- Python 3.7 or later
- Install required libraries: `pip install pycryptodome`

## How to Run
1. Clone this repository.
2. Install the dependencies.
3. Run `main.py`.

## How to Use
1. Choose the encryption method (AES or RSA).
2. For AES, provide a 16-byte key.
3. For RSA, provide the public/private keys as needed.
4. Input the message, then click Encrypt or Decrypt.

## Notes
- Ensure RSA keys are in PEM format.
- AES keys must be exactly 16 bytes.

## License
MIT License
