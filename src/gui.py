"""
Description: 
    Creates a GUI for the cipher functions defined in cipher.py.
    This GUI allows users to generate keys, encrypt plaintext, and decrypt ciphertext. 
"""
from tkinter import *
import tkinter as tk
import cipher as cipher 

#-----------------Cipher Functions----------------

def generate_key():
    return cipher.generate_key() 

def encrypt(key, plaintext):
    if not key:
        return "ERROR: Please enter a key"
    if not plaintext:
        return "ERROR: Please enter text to encrypt"
    return cipher.encrypt(key, plaintext)

def decrypt(key, ciphertext):
    if not key:
        return "ERROR: Please enter a key"
    if not ciphertext:
        return "ERROR: Please enter text to decrypt"
    return cipher.decrypt(key, ciphertext)


window = tk.Tk() 
window.title("Cipher GUI")


#-----------------Key List Section----------------
# Section Label
keyListLabel = tk.Label(text="Keys", font=("Arial", 14, "bold"))
keyListLabel.pack()

keyListInstructions = tk.Label(text="Generated keys will appear in this box")
keyListInstructions.pack()

keyList = Text(window, height=10)
keyList.pack()

generateKeyButton = tk.Button(text="Generate Key", command=lambda: keyList.insert(tk.END, generate_key() + "\n\n"))
generateKeyButton.pack()

#-----------------Encryption Section---------------- 
# Section Label
encryptLabel = tk.Label(text="Encryption", font=("Arial", 14, "bold"))
encryptLabel.pack()

# Key input 
encryptKeyLabel = tk.Label(text="Enter your encryption key here")
encryptKeyLabel.pack()
encryptKey = Text(window, height=2)
encryptKey.pack()

# Plaintext input 
encryptInputLabel = tk.Label(text="Enter Text to Encrypt")
encryptInputLabel.pack()
encryptInput = Text(window, height=5)
encryptInput.pack()

# Ciphertext output 
encryptOutputLabel = tk.Label(text="Encryption Output")
encryptOutputLabel.pack()
encryptOutput = Text(window, height=5)
encryptOutput.pack()

# Encrypt button
encryptButton = tk.Button(text="Encrypt", command=lambda: encryptOutput.insert(tk.END, encrypt(encryptKey.get("1.0", tk.END).strip(), encryptInput.get("1.0", tk.END).strip()) + "\n"))
encryptButton.pack()

#-----------------Decryption Section---------------- 
# Section Label
decryptLabel = tk.Label(text="Decryption", font=("Arial", 14, "bold"))
decryptLabel.pack()

# Key input 
decryptKeyLabel = tk.Label(text="Enter your decryption key here")
decryptKeyLabel.pack()
decryptKey = Text(window, height=2)
decryptKey.pack()

# Ciphertext input 
decryptInputLabel = tk.Label(text="Enter Text to Decrypt")
decryptInputLabel.pack()
decryptInput = Text(window, height=5)
decryptInput.pack()

# Plaintext output 
decryptOutputLabel = tk.Label(text="Decryption output")
decryptOutputLabel.pack()
decryptOutput = Text(window, height=5)
decryptOutput.pack()

# Decrypt button
decryptButton = tk.Button(text="Decrypt", command=lambda: decryptOutput.insert(tk.END, decrypt(decryptKey.get("1.0", tk.END).strip(), decryptInput.get("1.0", tk.END).strip()) + "\n"))
decryptButton.pack()

window.mainloop()