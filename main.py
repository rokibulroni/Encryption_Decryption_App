
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import base64
import os

# AES Encryption
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

# AES Decryption
def aes_decrypt(data, key):
    raw = base64.b64decode(data)
    nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# RSA Key Generation
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# RSA Encryption
def rsa_encrypt(data, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return base64.b64encode(cipher.encrypt(data.encode())).decode()

# RSA Decryption
def rsa_decrypt(data, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(base64.b64decode(data)).decode()

# GUI
def main():
    def encrypt_message():
        method = method_var.get()
        message = input_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "No message to encrypt!")
            return
        
        if method == "AES":
            key = key_entry.get().encode()
            if len(key) != 16:
                messagebox.showerror("Error", "AES key must be 16 bytes!")
                return
            encrypted = aes_encrypt(message, key)
        elif method == "RSA":
            public_key = public_key_entry.get("1.0", tk.END).strip()
            if not public_key:
                messagebox.showerror("Error", "Provide a valid RSA public key!")
                return
            encrypted = rsa_encrypt(message, public_key)
        else:
            messagebox.showerror("Error", "Unknown encryption method!")
            return
        
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, encrypted)

    def decrypt_message():
        method = method_var.get()
        message = input_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "No message to decrypt!")
            return
        
        if method == "AES":
            key = key_entry.get().encode()
            if len(key) != 16:
                messagebox.showerror("Error", "AES key must be 16 bytes!")
                return
            decrypted = aes_decrypt(message, key)
        elif method == "RSA":
            private_key = private_key_entry.get("1.0", tk.END).strip()
            if not private_key:
                messagebox.showerror("Error", "Provide a valid RSA private key!")
                return
            decrypted = rsa_decrypt(message, private_key)
        else:
            messagebox.showerror("Error", "Unknown decryption method!")
            return
        
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted)

    app = tk.Tk()
    app.title("Encryption/Decryption App")

    tk.Label(app, text="Select Method:").pack()
    method_var = tk.StringVar(value="AES")
    tk.Radiobutton(app, text="AES", variable=method_var, value="AES").pack(anchor="w")
    tk.Radiobutton(app, text="RSA", variable=method_var, value="RSA").pack(anchor="w")

    tk.Label(app, text="Input Message:").pack()
    input_text = tk.Text(app, height=5, width=50)
    input_text.pack()

    tk.Label(app, text="AES Key (16 bytes) or RSA Keys:").pack()
    key_entry = tk.Entry(app, show="*")
    key_entry.pack()

    tk.Label(app, text="Public Key (RSA Only):").pack()
    public_key_entry = tk.Text(app, height=5, width=50)
    public_key_entry.pack()

    tk.Label(app, text="Private Key (RSA Only):").pack()
    private_key_entry = tk.Text(app, height=5, width=50)
    private_key_entry.pack()

    tk.Button(app, text="Encrypt", command=encrypt_message).pack()
    tk.Button(app, text="Decrypt", command=decrypt_message).pack()

    tk.Label(app, text="Output:").pack()
    output_text = tk.Text(app, height=5, width=50)
    output_text.pack()

    app.mainloop()

if __name__ == "__main__":
    main()
