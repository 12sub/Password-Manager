#!/bin/python3
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox
import pickle


def generate_key():
    key = Fernet.generate_key()
    return key
def encrypt_password(key, password):
    k = Fernet(key)
    encrypted = k.encrypt(password.encode())
    return encrypted

def decrypt_password(key, encrypt_password):
    k = Fernet(key)
    passwd = str(encrypt_password())
    decrypted = k.decrypt(passwd)
    return decrypted

passwords = {}
key = generate_key()

def validate_pass():
     # service = entry.get()
    uid = uid_entry.get()
    userid = username_entry.get()
    password = password_entry.get()

    # You can add your own validation logic here
    if uid == uid and userid == userid and password == password:
        encrypt_file = encrypt_password(key, password)
        with open('pass-file.json', 'wb') as file:
            pass_append = []
            passwords[uid] = {"Username": userid, "Password": encrypt_file}
            pass_append.append(passwords[uid])
            file.write(pickle.dumps(pass_append), file)
        messagebox.showinfo("Login Successful Welcome ", (uid))
    else:
        messagebox.showerror("Login Failed", "Invalid username or password")

def get_details():
    uid = uid_entry.get()

    if uid in passwords:
       userid = passwords[uid]['Username']
       encrypted = passwords[uid]['Password']
       decrypted = decrypt_password(key, encrypted)
       with open('pass-file.txt', 'rb') as file:
        file.read(pickle.loads(decrypted))
       messagebox.showinfo("Retrevial Successful, " , (uid, decrypted))
    else:
        messagebox.showerror("Retrvial Failed", "Passwords not found")

window = tk.Tk()
window.title("Password Manager Form")

# Create and place the username label and entry
username_label = tk.Label(window, text="Userid:")
username_label.pack()

username_entry = tk.Entry(window)
username_entry.pack()

# Create and place the password label and entry
password_label = tk.Label(window, text="Password:")
password_label.pack()

password_entry = tk.Entry(window, show="*")  # Show asterisks for password
password_entry.pack()

# Create and place the password label and entry
uid_label = tk.Label(window, text="Account:")
uid_label.pack()

uid_entry = tk.Entry(window)  # Show asterisks for password
uid_entry.pack()

# Create and place the password texts
login_button = tk.Button(window, text="Add password", command=validate_pass)
login_button.pack()

# Find the password texts
login_button = tk.Button(window, text="Retrive Password", command=get_details)
login_button.pack()

# Start the Tkinter event loop
window.mainloop()

