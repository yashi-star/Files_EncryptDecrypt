import os
import base64
import tkinter as tk
from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
import cv2
from PIL import Image, ImageTk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import secrets

# Create window for video player
root = tk.Tk()
root.resizable(True, True)
root.title("Video Player")
root.configure(bg="#0c111b")
video = cv2.VideoCapture('animation.mp4')
width = int(video.get(cv2.CAP_PROP_FRAME_WIDTH))
height = int(video.get(cv2.CAP_PROP_FRAME_HEIGHT))
canvas = tk.Canvas(root, width=width, height=height)
canvas.pack()

def play_video():
    ret, frame = video.read()
    if ret:
        frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        image = Image.fromarray(frame_rgb)
        photo = ImageTk.PhotoImage(image)
        canvas.create_image(0, 0, anchor=tk.NW, image=photo)
        canvas.image = photo
        root.after(30, play_video)
    else:
        video.release()

play_video()
animation_duration = 4000
root.after(animation_duration, root.destroy)
root.mainloop()


# Function to generate a random 256-bit key
def generate_key():
    return secrets.token_bytes(32)  # Generate a random 256-bit key

# Function to encrypt audio data
def encrypt_aes(key, data):
    # Pad the data
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    # Create a new AES cipher
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = iv + encryptor.update(padded_data) + encryptor.finalize()
    return encrypted

# Function to decrypt audio data
def decrypt_aes(key, encrypted_data):
    # Ensure the key size is appropriate for AES (16, 24, or 32 bytes)
    if len(key) not in {16, 24, 32}:
        raise ValueError("Invalid key size. Key must be 16, 24, or 32 bytes long.")
    
    # Extract the IV from the beginning of the encrypted data (first 16 bytes)
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    
    # Create a Cipher object with the same key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the data
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Unpad the decrypted data using PKCS7 padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
    except ValueError as e:
        print("Error during unpadding. Possible data corruption or wrong key.")
        raise e
    return decrypted_data

# Function to encrypt audio file
def encrypt_audio():
    key = generate_key()
    file_path = filedialog.askopenfilename(filetypes=[("Audio Files", "*.wav")])
    
    if file_path:  # Ensure the user didn't cancel the file dialog
        with open(file_path, 'rb') as file:
            original_file = file.read()   
        encrypted = encrypt_aes(key, original_file)
        
        # Save the encryption key to a file for later use
        with open("encryption_key.key", 'wb') as key_file:
            key_file.write(key)
        
        save_path = filedialog.asksaveasfilename(filetypes=[("Encrypted Audio Files", "*.wav")])
        
        if save_path:  # Ensure the user didn't cancel the save dialog
            with open(save_path, 'wb') as file:
                file.write(encrypted)
                print("Audio encryption completed.")

# Function to decrypt audio file
def decrypt_audio():
    try:
        # Load the encryption key from the file
        with open("encryption_key.key", 'rb') as key_file:
            key = key_file.read()
    except FileNotFoundError:
        print("Encryption key file not found.")
        return

    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Audio Files", "*.wav")])
    
    if file_path:  # Ensure the user didn't cancel the file dialog
        with open(file_path, 'rb') as file:
            encrypted_file = file.read()
        
        try:
            decrypted = decrypt_aes(key, encrypted_file)
            save_path = filedialog.asksaveasfilename(filetypes=[("Audio Files", "*.wav")])
            
            if save_path:  # Ensure the user didn't cancel the save dialog
                with open(save_path, 'wb') as file:
                    file.write(decrypted)
                    print("Audio decryption completed.")
        except ValueError:
            print("Error during decryption. Possible data corruption or wrong key.")



def encrypt_image():
    key = generate_key()
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.jpeg;*.jpg;*.png")])
    
    if file_path:
        with open(file_path, 'rb') as file:
            original_file = file.read()
        
        encrypted = encrypt_aes(key, original_file)
        
        with open("image_encryption_key.key", 'wb') as key_file:
            key_file.write(key)        
        save_path = filedialog.asksaveasfilename(filetypes=[("Encrypted Image Files", "*.jpeg;*.jpg;*.png")])        
        if save_path:
            with open(save_path, 'wb') as file:
                file.write(encrypted)
                print("Image encryption completed.")


# Function to decrypt image file
def decrypt_image():
    try:
        with open("image_encryption_key.key", 'rb') as key_file:
            key = key_file.read()
    except FileNotFoundError:
        print("Image encryption key file not found.")
        return
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Image Files", "*.jpeg;*.jpg;*.png")])    
    if file_path:
        with open(file_path, 'rb') as file:
            encrypted_file = file.read()       
        try:
            decrypted = decrypt_aes(key, encrypted_file)
            save_path = filedialog.asksaveasfilename(filetypes=[("Image Files", "*.jpeg;*.jpg;*.png")])
            
            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(decrypted)
                    print("Image decryption completed.")
        except ValueError:
            print("Error during decryption. Possible data corruption or wrong key.")


# Function to encrypt PDF file
def encrypt_pdf():
    key = generate_key()
    file_path = filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])
    
    if file_path:
        with open(file_path, 'rb') as file:
            original_file = file.read()
        
        encrypted = encrypt_aes(key, original_file)
        
        with open("pdf_encryption_key.key", 'wb') as key_file:
            key_file.write(key)
        
        save_path = filedialog.asksaveasfilename(filetypes=[("Encrypted PDF Files", "*.pdf")])
        
        if save_path:
            with open(save_path, 'wb') as file:
                file.write(encrypted)
                print("PDF encryption completed.")

# Function to decrypt PDF file
def decrypt_pdf():
    try:
        with open("pdf_encryption_key.key", 'rb') as key_file:
            key = key_file.read()
    except FileNotFoundError:
        print("PDF encryption key file not found.")
        return

    file_path = filedialog.askopenfilename(filetypes=[("Encrypted PDF Files", "*.pdf")])
    
    if file_path:
        with open(file_path, 'rb') as file:
            encrypted_file = file.read()
        
        try:
            decrypted = decrypt_aes(key, encrypted_file)
            save_path = filedialog.asksaveasfilename(filetypes=[("PDF Files", "*.pdf")])
            
            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(decrypted)
                    print("PDF decryption completed.")
        except ValueError:
            print("Error during decryption. Possible data corruption or wrong key.")

# Function to encrypt video file
def encrypt_video():
    key = generate_key()
    file_path = filedialog.askopenfilename(filetypes=[("Video Files", "*.mp4;*.avi;*.mkv")])
    
    if file_path:
        with open(file_path, 'rb') as file:
            original_file = file.read()
        
        encrypted = encrypt_aes(key, original_file)
        
        with open("video_encryption_key.key", 'wb') as key_file:
            key_file.write(key)
        
        save_path = filedialog.asksaveasfilename(filetypes=[("Encrypted Video Files", "*.mp4;*.avi;*.mkv")])
        
        if save_path:
            with open(save_path, 'wb') as file:
                file.write(encrypted)
                print("Video encryption completed.")

# Function to decrypt video file
def decrypt_video():
    try:
        with open("video_encryption_key.key", 'rb') as key_file:
            key = key_file.read()
    except FileNotFoundError:
        print("Video encryption key file not found.")
        return

    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Video Files", "*.mp4;*.avi;*.mkv")])
    
    if file_path:
        with open(file_path, 'rb') as file:
            encrypted_file = file.read()
        
        try:
            decrypted = decrypt_aes(key, encrypted_file)
            save_path = filedialog.asksaveasfilename(filetypes=[("Video Files", "*.mp4;*.avi;*.mkv")])
            
            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(decrypted)
                    print("Video decryption completed.")
        except ValueError:
            print("Error during decryption. Possible data corruption or wrong key.")

# Function to save the key to a file
def save_key(key):
    with open('key.key', 'wb') as key_file:
        key_file.write(key.encode('utf-8'))

# Function to load the key from a file
def load_key():
    with open('key.key', 'rb') as key_file:
        return key_file.read().decode('utf-8')


def encrypt_text():
    key = code.get()
    if key:
        # Ensure the key length is appropriate for AES (16, 24, or 32 bytes)
        key = key.ljust(32)[:32]  # Pad or truncate the key to 32 bytes
        message = text1.get(1.0, END).strip()
        if message:  # Check if there is a message to encrypt
            # Convert the message to bytes
            message_bytes = message.encode('utf-8')
            
            # Encrypt the message
            encrypted_message = encrypt_aes(key.encode('utf-8'), message_bytes)
            
            # Display the encrypted message as bytes in hex format for readability
            root1 = Toplevel(root)
            root1.title("Encryption")
            root1.geometry("400x200")
            root1.configure(bg="#0c111b")
            Label(root1, text="ENCRYPT", font="arial", fg="white", bg="#0c111b").place(x=10, y=0)
            text2 = Text(root1, font="Rpbote 10", bg="white", relief=SUNKEN)
            text2.place(x=10, y=40, width=380, height=150)
            text2.insert(END, encrypted_message.hex())  # Display encrypted message as hex
            print("Text encryption completed.")
            code.set("")  # Reset the key input field after encryption
        else:
            messagebox.showerror("Encryption", "Input text to encrypt")
    else:
        messagebox.showerror("Encryption", "Input secret key")

def decrypt_text():
    key = code.get()
    if key:
        # Ensure the key length is appropriate for AES (16, 24, or 32 bytes)
        key = key.ljust(32)[:32]  # Pad or truncate the key to 32 bytes
        
        message = text1.get(0.0, END).strip()
        if message:  # Check if there is a message to decrypt
            try:
                # Convert the hex string back to bytes
                encrypted_message = bytes.fromhex(message)
                
                # Decrypt the message
                decrypted_message = decrypt_aes(key.encode('utf-8'), encrypted_message)
                
                root2 = Toplevel(root)
                root2.title("Decryption")
                root2.geometry("400x200")
                root2.configure(bg="#0c111b")
                Label(root2, text="DECRYPT", font="arial", fg="white", bg="#0c111b").place(x=10, y=0)
                text2 = Text(root2, font="Rpbote 10", bg="white", relief=SUNKEN)
                text2.place(x=10, y=40, width=380, height=150)
                text2.insert(END, decrypted_message.decode('utf-8'))  # Show decrypted message
                print("Text decryption completed.")
            except Exception as e:
                messagebox.showerror("Decryption Error", "Failed to decrypt the message.")
        else:
            messagebox.showerror("Decryption", "Input text to decrypt")
    else:
        messagebox.showerror("Decryption Error", "Input secret key")



        
    
def show_about():
    messagebox.showinfo("About", "This is a sample application.\n\nVersion: 1.0\n By-Yashi Pant")

def reset():
    code.set("")
    text1.delete(1.0, END)

def create_gui():
    global root
    global text1
    global code
    root = Tk()
    root.title("Data Security")
    root.geometry("700x900")
    root.resizable(False, True)
    root.configure(bg="#0c111b")
    menu = Menu(root)
    root.config(menu=menu)
    filemenu = Menu(menu)
    menu.add_cascade(label='File', menu=filemenu)
    filemenu.add_command(label='New')
    filemenu.add_command(label='Open...')
    filemenu.add_command(label='Exit', command=root.quit)
    optionmenu = Menu(menu)
    menu.add_cascade(label='Option', menu=optionmenu)
    optionmenu.add_command(label="cut")
    optionmenu.add_command(label="copy")
    optionmenu.add_command(label="paste")
    moremenu = Menu(menu)
    menu.add_cascade(label='More', menu=moremenu)
    moremenu.add_command(label="Undo")
    moremenu.add_command(label="Redo")
    windowmenu = Menu(menu)
    menu.add_cascade(label='window', menu=windowmenu)
    windowmenu.add_command(label="gui.py-C:/users/desktop/miniproject/gui.py")
    helpmenu = Menu(menu)
    menu.add_cascade(label="Help", menu=helpmenu)
    helpmenu.add_command(label="About", command=show_about)

    Label(root, text="' Securing Your Files '", bg="#0c111b", fg="white", font="algerian 30 bold").place(x=100, y=20)

    frame1 = Frame(root, bd=3, bg="black", width=340, height=280, relief=SUNKEN)
    frame1.place(x=10, y=80)
    lb1 = Label(frame1, bg="black")
    lb1.place(x=40, y=10)
    Button(frame1, text="Encrypt", width=10, height=2, fg="white", bg="green", command=encrypt_text).place(x=130, y=26)
    Button(frame1, text="Decrypt", width=10, height=2, fg="white", bg="green", command=decrypt_text).place(x=130, y=76)
    Button(frame1, text="Reset", width=10, height=2, fg="white", bg="red", command=reset).place(x=130, y=130)
    Label(text=" enter secret key ", fg="white", bg="black", font=("calibri", 13)).place(x=130, y=250)
    code = StringVar()
    Entry(textvariable=code, width=10, bd=0, font=("arial", 20), show="*").place(x=110, y=280)

    frame2 = Frame(root, bd=3, width=340, height=280, bg="white", relief=SUNKEN )
    frame2.place(x=350, y=80)
    text1 = Text(frame2, font="Robote 20", bg="black", fg="green", relief=RAISED)
    text1.place(x=0, y=0, width=320, height=295)
    scrollbar1 = Scrollbar(frame2)
    scrollbar1.place(x=320, y=0, height=300)
    scrollbar1.configure(command=text1.yview)
    text1.configure(yscrollcommand=scrollbar1.set)

    frame3 = Frame(root, bd=3, bg="#aaa", width=330, height=150, relief=SUNKEN)
    frame3.place(x=10, y=370)
    Button(frame3, text="Audio", width=10, height=2, command=encrypt_audio, fg="white", bg="#dc143c").place(x=30, y=26)
    Button(frame3, text="Image", width=10, height=2, command=encrypt_image, fg="white", bg="#dc143c").place(x=180, y=26)
    Button(frame3, text="PDF", width=10, height=2, command=encrypt_pdf, fg="white", bg="#dc143c").place(x=30, y=76)
    Button(frame3, text="Video", width=10, height=2, command=encrypt_video, fg="white", bg="#dc143c").place(x=180, y=76)
    Label(frame3, text="Encrypting- video, Image, audio,pdf", bg="#aaa", fg="black").place(x=20, y=5)

    frame4 = Frame(root, bd=3, bg="#aaa", width=330, height=150, relief=SUNKEN)
    frame4.place(x=360, y=370)
    Button(frame4, text="Audio", width=10, height=2, command=decrypt_audio, fg="white", bg="#dc143c").place(x=30, y=26)
    Button(frame4, text="Image", width=10, height=2, command=decrypt_image, fg="white", bg="#dc143c").place(x=180, y=26)
    Button(frame4, text="PDF", width=10, height=2, command=decrypt_pdf, fg="white", bg="#dc143c").place(x=30, y=76)
    Button(frame4, text="Video", width=10, height=2, command=decrypt_video, fg="white", bg="#dc143c").place(x=180, y=76)
    Label(frame4, text="Decrypting- video, Image, audio,pdf", bg="#aaa", fg="black").place(x=20, y=5)
    root.mainloop()

create_gui()