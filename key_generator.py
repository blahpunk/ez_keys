import tkinter as tk
from tkinter import messagebox
import secrets
import uuid
import base64

def generate_key(preset, length):
    if preset == "alphanumeric":
        return ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(length))
    elif preset == "hex":
        return secrets.token_hex(length // 2)  # hex returns 2 characters for each byte
    elif preset == "uuid":
        return str(uuid.uuid4())
    elif preset == "base64":
        return base64.urlsafe_b64encode(secrets.token_bytes(length)).decode('utf-8')[:length]
    elif preset == "binary":
        return ''.join(secrets.choice('01') for _ in range(length))
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

root = tk.Tk()
root.title("Secure Key Generator")

# Create GUI elements
preset_var = tk.StringVar(value="alphanumeric")
length_var = tk.StringVar(value="32")
result_var = tk.StringVar()

tk.Label(root, text="Select Key Type:").pack(pady=5)
tk.Radiobutton(root, text="Alphanumeric", variable=preset_var, value="alphanumeric").pack(anchor='w')
tk.Radiobutton(root, text="Hexadecimal", variable=preset_var, value="hex").pack(anchor='w')
tk.Radiobutton(root, text="UUID (Version 4)", variable=preset_var, value="uuid").pack(anchor='w')
tk.Radiobutton(root, text="Base64", variable=preset_var, value="base64").pack(anchor='w')
tk.Radiobutton(root, text="Binary", variable=preset_var, value="binary").pack(anchor='w')

tk.Label(root, text="Key Length (for applicable types):").pack(pady=5)
tk.Entry(root, textvariable=length_var, width=10).pack()

tk.Button(root, text="Generate Key", command=on_generate).pack(pady=10)

tk.Label(root, text="Generated Key:").pack(pady=5)
tk.Entry(root, textvariable=result_var, width=40).pack()

tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard).pack(pady=10)

# Start the GUI
root.mainloop()
