import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
import numpy as np
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets

class App:

    def __init__(self, master):
        # Building the GUI for the app
        self.master = master
        self.master.title("Stegappnography")
        self.label = tk.Label(master, text="Input text:")
        self.label.pack()
        self.text_entry = tk.Text(master, height=5, width=40)
        self.text_entry.pack()
        self.encrypt_var = tk.BooleanVar()
        self.encrypt_checkbox = tk.Checkbutton(master, text="Encrypt?", variable=self.encrypt_var)
        self.encrypt_checkbox.pack()
        self.choose_image_button = tk.Button(master, text="Select picture", command=self.select_image)
        self.choose_image_button.pack()
        self.hide_button = tk.Button(master, text="Embeed text", command=self.embeed_text)
        self.hide_button.pack()
        self.extract_button = tk.Button(master, text="Extract text", command=self.extract_text)
        self.extract_button.pack()
        self.result_label = tk.Label(master, text="")
        self.result_label.pack()
        self.image_path = None

    def select_image(self):
        self.image_path = filedialog.askopenfilename()
        if self.image_path:
            self.result_label.config(text="Selected image: " + self.image_path)

    def embeed_text(self):

        text_to_hide = self.text_entry.get("1.0", tk.END).strip()
        if not self.image_path:
            messagebox.showerror("Error", "Image not selected")
            return

        key = "0123456789abcdef"
        iv = secrets.token_bytes(16)
        if self.encrypt_var.get():
            encrypted_text, iv = self.encrypt_text(text_to_hide, key)
            text_to_hide = encrypted_text.hex()

        image = Image.open(self.image_path)
        image_array = np.array(image)
        hashed_text = hashlib.sha256(text_to_hide.encode()).hexdigest()
        binary_text = ''.join(format(ord(char), '08b') for char in hashed_text + text_to_hide)
        binary_text += '1' * (len(image_array.flatten()) - len(binary_text))

        image_array.flags.writeable = True
        for i, bit in enumerate(binary_text):
            image_array.flat[i] = (image_array.flat[i] & ~1) | int(bit)

        stego_image = Image.fromarray(image_array)
        stego_image.save('stego_image.png')
        messagebox.showinfo("Success", "The text has been successfully embeeded into the image")


    def extract_text(self):

        if not self.image_path:
            messagebox.showerror("Error", "Image not selected")
            return

        key = "0123456789abcdef"

        extracted_text = self.extract_text_from_image(self.image_path, key)
        self.text_entry.delete("1.0", tk.END)
        self.text_entry.insert(tk.END, extracted_text)

    def encrypt_text(self, text, key):
        cipher = AES.new(key.encode(), AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
        iv = cipher.iv
        return ct_bytes, iv

    def decrypt_text(self, ct_bytes, iv, key):

        cipher = AES.new(key.encode(), AES.MODE_CBC, iv=iv)
        pt = cipher.decrypt(ct_bytes)
        str = unpad(pt, AES.block_size).decode()
        return str

    def extract_text_from_image(self, image_path, key):

        image = Image.open(image_path)
        image_array = np.array(image)

        extracted_bits = ''
        for bit in image_array.flatten():
            extracted_bits += str(bit & 1)

        end_index = extracted_bits.find('11111111')
        binary_text = extracted_bits[:end_index]

        hash_text = binary_text[:256]
        text_to_extract = binary_text[256:end_index]

        if key:
            decrypted_text = self.decrypt_text(bytes.fromhex(text_to_extract), bytes.fromhex(hash_text), key)
            return decrypted_text
        else:
            return bytes.fromhex(text_to_extract).decode()

def main():
    root = tk.Tk()
    app = App(root)
    root.mainloop()

if __name__ == "__main__":
    main()