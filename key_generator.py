import tkinter as tk
from tkinter import messagebox
import secrets
import uuid
import base64
import os
import sys

# Function to get correct path for PyInstaller-extracted files
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and PyInstaller """
    try:
        base_path = sys._MEIPASS  # Temporary folder used by PyInstaller
    except AttributeError:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

# Function to generate keys
def generate_key(preset, length):
    if preset == "alphanumeric":
        return ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(length))
    elif preset == "hex":
        return secrets.token_hex(length // 2)
    elif preset == "uuid":
        return str(uuid.uuid4())
    elif preset == "base64":
        return base64.urlsafe_b64encode(secrets.token_bytes(length)).decode('utf-8')[:length]
    elif preset == "binary":
        return ''.join(secrets.choice('01') for _ in range(length))
    elif preset == "numeric":
        return ''.join(secrets.choice('0123456789') for _ in range(length))
    else:
        return "Invalid preset selected"

def on_generate():
    preset = preset_var.get()
    try:
        length = int(length_var.get())
        if length <= 0:
            raise ValueError
        key = generate_key(preset, length)
        result_var.set(key)
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid positive integer for the key length")

def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(result_var.get())
    messagebox.showinfo("Copied", "Key copied to clipboard")

# Set up root window
root = tk.Tk()
root.title("Secure Key Generator")

# Set application icon
icon_path = resource_path("icon.ico")
root.iconbitmap(icon_path)

# Explicit window size
root.geometry("500x550")

# Set up styling
root.configure(bg='#2c3e50')
style = {
    'fg': 'white', 'font': ('Arial', 12),
    'padx': 5, 'pady': 5, 'bg': '#34495e'
}
button_style = {
    'bg': '#16a085', 'fg': 'white', 'activebackground': '#1abc9c', 'font': ('Arial', 12, 'bold'),
    'padx': 5, 'pady': 5
}
highlight_style = {
    'highlightbackground': '#ecf0f1', 'highlightcolor': '#1abc9c', 'highlightthickness': 2, 'bd': 0
}

# GUI elements
preset_var = tk.StringVar(value="alphanumeric")
length_var = tk.StringVar(value="32")
result_var = tk.StringVar()

tk.Label(root, text="Select Key Type:", **style).pack(pady=5)
tk.Radiobutton(root, text="Alphanumeric", variable=preset_var, value="alphanumeric", **style, selectcolor='#1abc9c').pack(anchor='w', padx=15)
tk.Radiobutton(root, text="Hexadecimal", variable=preset_var, value="hex", **style, selectcolor='#1abc9c').pack(anchor='w', padx=15)
tk.Radiobutton(root, text="UUID (Version 4)", variable=preset_var, value="uuid", **style, selectcolor='#1abc9c').pack(anchor='w', padx=15)
tk.Radiobutton(root, text="Base64", variable=preset_var, value="base64", **style, selectcolor='#1abc9c').pack(anchor='w', padx=15)
tk.Radiobutton(root, text="Binary", variable=preset_var, value="binary", **style, selectcolor='#1abc9c').pack(anchor='w', padx=15)
tk.Radiobutton(root, text="Numeric", variable=preset_var, value="numeric", **style, selectcolor='#1abc9c').pack(anchor='w', padx=15)

tk.Label(root, text="Key Length (for applicable types):", **style).pack(pady=5)
tk.Entry(root, textvariable=length_var, width=10, **highlight_style).pack(pady=5)

tk.Button(root, text="Generate Key", command=on_generate, **button_style).pack(pady=10)

tk.Label(root, text="Generated Key:", **style).pack(pady=5)
tk.Entry(root, textvariable=result_var, width=40, **highlight_style).pack(pady=5)

tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard, **button_style).pack(pady=10)

# Start the GUI
root.mainloop()
