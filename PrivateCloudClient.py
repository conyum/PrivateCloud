import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.fernet import Fernet
import requests
import customtkinter as ctk
import zipfile
import hashlib
import time
import re
import pyperclip

class FileEncryptorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.user = None
        self.file_paths = []
        self.key = None
        self.api_url = "http://51.195.253.123:8000"
        self.version = "0.3.1"
        self.title("PrivateCloud")
        self.geometry("600x400")
        self.check_for_updates()
        self.login_screen()
    
    def check_for_updates(self):
        try:
            response = requests.get(f"{self.api_url}/version")
            if response.status_code == 200:
                latest_version = response.json().get("version")
                if self.is_newer_version(latest_version, self.version):
                    messagebox.showinfo("There is a new version!", "There is a new version! \n\nVisit https://nordicz.info/download/latest\nTo download!")
                else:
                    print("No update available.")
            else:
                messagebox.showerror("Error", "Failed to check for updates.")
        except Exception as e:
            messagebox.showerror("Error", f"Update check failed: {e}")

    def is_newer_version(self, latest_version, current_version):
        latest_parts = [int(part) for part in latest_version.split('.')]
        current_parts = [int(part) for part in current_version.split('.')]
        return latest_parts > current_parts

    def clear_screen(self):
        for widget in self.winfo_children():
            widget.destroy()

    def login_screen(self):
        self.clear_screen()
        ctk.CTkLabel(self, text="Login or Register", font=("Arial", 18)).pack(pady=10)
        username = ctk.StringVar()
        password = ctk.StringVar()
        username_entry = ctk.CTkEntry(self, textvariable=username, placeholder_text="Username")
        password_entry = ctk.CTkEntry(self, textvariable=password, placeholder_text="Password", show="*")
        username_entry.pack(pady=5)
        password_entry.pack(pady=5)
        login_button = ctk.CTkButton(self, text="Login", command=lambda: self.login(username.get(), password.get()))
        login_button.pack(pady=5)
        register_button = ctk.CTkButton(self, text="Register", command=lambda: self.register(username.get(), password.get()))
        register_button.pack(pady=5)
        self.bind('<Return>', lambda event: login_button.invoke())

    def login(self, username, password):
        try:
            response = requests.post(f"{self.api_url}/login", json={"username": username, "password": password})
            if response.status_code == 200:
                self.user = {"username": username, "password": password}
                self.configure_ui("Dark")
            else:
                messagebox.showerror("Error", f"Login failed: {response.json().get('error')}")
        except Exception as e:
            messagebox.showerror("Error", f"Login request failed: {e}")

    def register(self, username, password):
        try:
            response = requests.post(f"{self.api_url}/register", json={"username": username, "password": password})
            if response.status_code == 201:
                messagebox.showinfo("Success", "Registration successful! Please log in.")
            else:
                messagebox.showerror("Error", f"Registration failed: {response.json().get('error')}")
        except Exception as e:
            messagebox.showerror("Error", f"Registration request failed: {e}")

    def configure_ui(self, theme):
        self.clear_screen()
        self.title(f"PrivateCloud v{self.version} - Welcome, {self.user['username']}")
        ctk.set_appearance_mode(theme)
        self.geometry("600x500")
        ctk.CTkButton(self, text="Logout", command=self.logout, fg_color="red").pack(pady=10)
        ctk.CTkButton(self, text="Generate Key", command=self.generate_key, fg_color="green").pack(pady=10)
        ctk.CTkButton(self, text="Select Files (Max 100mb)", command=self.select_files, fg_color="blue").pack(pady=10)
        ctk.CTkButton(self, text="Encrypt Files", command=self.encrypt_files, fg_color="orange").pack(pady=10)
        ctk.CTkButton(self, text="Decrypt Files", command=self.decrypt_files, fg_color="orange").pack(pady=10)
        ctk.CTkButton(self, text="Upload to Cloud", command=self.upload_to_api, fg_color="purple").pack(pady=10)
        ctk.CTkButton(self, text="Download from Cloud", command=self.download_from_api, fg_color="purple").pack(pady=10)
        self.list_button = ctk.CTkButton(self, text="List Cloud Files", command=self.list_uploaded_files)
        self.list_button.pack()

    def logout(self):
        self.user = None
        self.file_paths = []
        self.key = None
        self.clear_screen()
        self.login_screen()

    def generate_key(self):
        if os.path.exists(f"{self.user['username']}.key"):
            i = 1
            while os.path.exists(f"{self.user['username']}.key.yummii-{i}"):
                i += 1
            os.rename(f"{self.user['username']}.key", f"{self.user['username']}.key.yummii-{i}")
            messagebox.showinfo("Backup Created", f"Existing key backed up as '{self.user['username']}.key.yummii-{i}'.")

        self.key = Fernet.generate_key()
        with open(f"{self.user['username']}.key", "wb") as key_file:
            key_file.write(self.key)
        messagebox.showinfo("Success", f"New encryption key generated and saved as '{self.user['username']}.key'.")

    @staticmethod
    def get_total_file_size(file_paths):
        return sum(os.path.getsize(file_path) for file_path in file_paths)

    def select_files(self):
        max_total_size = 100 * 1024 * 1024
        selected_files = filedialog.askopenfilenames(title="Select Files")
    
        if not selected_files:
            messagebox.showerror("Error", "No files selected.")
            return
    
        total_size = self.get_total_file_size(selected_files)
        if total_size > max_total_size:
            messagebox.showerror("Error", f"Total file size exceeds 100 MB. Selected size: {total_size / (1024 * 1024):.2f} MB.")
            return
    
        self.file_paths = selected_files
        messagebox.showinfo("Files Selected", f"{len(self.file_paths)} file(s) selected. Total size: {total_size / (1024 * 1024):.2f} MB.")
    
    def encrypt_files(self):
        if not self.file_paths:
            messagebox.showerror("Error", "No files selected.")
            return

        if os.path.isfile(self.user['username']+'.key'):
            with open(f"{self.user['username']}.key", "rb") as key_file:
                    self.key = key_file.read()
        else:
            messagebox.showerror("Error", "Generate an encryption key first.")
            return

        cipher = Fernet(self.key)
        for file_path in self.file_paths:
            try:
                with open(file_path, "rb") as f:
                    data = f.read()
                encrypted_data = cipher.encrypt(data)
                with open(file_path + ".yummii", "wb") as enc_file:
                    enc_file.write(encrypted_data)
                os.remove(file_path)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to encrypt {file_path}: {e}")
                return
        messagebox.showinfo("Success", "Files encrypted successfully.")

    def decrypt_files(self):
        if not self.file_paths:
            messagebox.showerror("Error", "No files selected.")
            return

        if not self.key:
            try:
                with open(f"{self.user['username']}.key", "rb") as key_file:
                    self.key = key_file.read()
            except FileNotFoundError:
                messagebox.showerror("Error", "Encryption key not found. Generate or load a key first.")
                return

        cipher = Fernet(self.key)
        for file_path in self.file_paths:
            if not file_path.endswith(".yummii"):
                continue
            try:
                with open(file_path, "rb") as f:
                    encrypted_data = f.read()
                decrypted_data = cipher.decrypt(encrypted_data)
                original_path = file_path.rstrip(".yummii")
                with open(original_path, "wb") as dec_file:
                    dec_file.write(decrypted_data)
                os.remove(file_path)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to decrypt {file_path}: {e}")
                return
        messagebox.showinfo("Success", "Files decrypted successfully.")

    @staticmethod
    def generate_file_hash(file_path):
        hasher = hashlib.sha256()
        salt = os.urandom(16)  
        hasher.update(salt)
        timestamp = str(time.time()).encode('utf-8')  
        hasher.update(timestamp)
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

    def upload_to_api(self):
        max_total_size = 100 * 1024 * 1024
    
        if not self.file_paths:
            messagebox.showerror("Error", "No files selected to upload.")
            return

        total_size = self.get_total_file_size(self.file_paths)
        if total_size > max_total_size:
            messagebox.showerror("Error", f"Total file size exceeds 100 MB. Selected size: {total_size / (1024 * 1024):.2f} MB.")
            return

        if not self.user:
            messagebox.showerror("Error", "User not logged in.")
            return

        if not os.path.exists(f"{self.user['username']}.key"):
            messagebox.showerror("Error", "Encryption key not found. Ensure the key exists before uploading.")
            return

        with open(f"{self.user['username']}.key", "rb") as key_file:
            encryption_key_data = key_file.read()

        for file_path in self.file_paths:
            try:
                file_hash = self.generate_file_hash(file_path)
                if file_path.endswith(".yummii"):
                    archive_name = os.path.splitext(file_path)[0] + ".zip"
                    with zipfile.ZipFile(archive_name, 'w', zipfile.ZIP_DEFLATED) as archive:
                        archive.write(file_path, os.path.basename(file_path))
                        renamed_key_filename = os.path.basename(file_path).replace(".yummii", ".key")
                        with open(renamed_key_filename, "wb") as temp_key_file:
                            temp_key_file.write(encryption_key_data)
                        archive.write(renamed_key_filename, renamed_key_filename)
                        os.remove(renamed_key_filename)

                    with open(archive_name, 'rb') as f:
                        files = {'file': f}
                        data = {'username': self.user['username'], 'password': self.user['password'], 'file_hash': file_hash, 'version': self.version}
                        response = requests.post(f"{self.api_url}/upload", files=files, data=data)
                        if response.status_code == 200:
                            self.show_hash_copyable(file_hash)
                        else:
                            messagebox.showinfo("Error", f"Failed to upload archive {archive_name}: {response.text}")
                    os.remove(archive_name)
                else:
                    with open(file_path, 'rb') as f:
                        files = {'file': f}
                        data = {'username': self.user['username'], 'password': self.user['password'], 'file_hash': file_hash, 'version': self.version}
                        response = requests.post(f"{self.api_url}/upload", files=files, data=data)
                        if response.status_code == 200:
                            self.show_hash_copyable(file_hash)
                        else:
                            messagebox.showinfo("Error", f"Failed to upload {file_path}: {response.text}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to upload {file_path}: {e}")

    def show_hash_copyable(self, file_hash):
        copy_window = ctk.CTkToplevel(self)
        copy_window.title("File Hash")
        copy_window.geometry("400x200")
        copy_window.attributes("-topmost", True)
        ctk.CTkLabel(copy_window, text="File Hash:").pack(pady=10)
        hash_entry = ctk.CTkEntry(copy_window, state="normal", width=300, justify="center")
        hash_entry.insert(0, file_hash)
        hash_entry.pack(pady=10)
        hash_entry.select_range(0, len(file_hash))  
        hash_entry.focus()  
        def copy_to_clipboard():
            pyperclip.copy(file_hash)
            messagebox.showinfo("Copied", "Hash copied to clipboard!")
        copy_button = ctk.CTkButton(copy_window, text="Copy Hash", command=copy_to_clipboard)
        copy_button.pack(padx=10, pady=(10, 5))

        close_button = ctk.CTkButton(copy_window, text="Close", command=copy_window.destroy)
        close_button.pack(padx=25, pady=(5, 10))

    def download_from_api(self):
        file_hash = simpledialog.askstring("Download", "Enter the file hash:")
        if not file_hash:
            return
        try:
            response = requests.get(
                f"{self.api_url}/download/{file_hash}",
                stream=True
            )
            if response.status_code == 200:
                
                content_disposition = response.headers.get('Content-Disposition')
                if content_disposition:
                    
                    filename_match = re.findall('filename="(.+)"', content_disposition)
                    if filename_match:
                        filename = filename_match[0]
                    else:
                        filename = "downloaded_file"
                else:
                    filename = "downloaded_file"
                
                save_path = filedialog.asksaveasfilename(title="Save File As", initialfile=filename)
                if not save_path:
                    return

                with open(save_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                messagebox.showinfo("Success", f"File downloaded to {save_path}.")
            else:
                messagebox.showerror("Error", f"File not found for hash: {file_hash}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to download file: {e}")

    def list_uploaded_files(self):
        try:
            self.geometry("600x600")
            response = requests.get(
                f"{self.api_url}/files",
                params={"username": self.user['username'], "password": self.user['password'], 'version': self.version}
            )

            if response.status_code == 200:
                data = response.json()

                if not hasattr(self, "files_frame"):
                    self.files_frame = ctk.CTkScrollableFrame(self, width=500, height=200)
                    self.files_frame.pack(pady=10, fill="x", expand=False)
                else:
                    for widget in self.files_frame.winfo_children():
                        widget.destroy()

                if 'files' in data and data['files']:
                    for file in data['files']:
                        file_name = file["filename"]
                        file_hash = file["file_hash"]

                        def on_enter(event, button):
                            button.configure(text_color="yellow")  

                        def on_leave(event, button):
                            button.configure(text_color="lightblue")  

                        file_button = ctk.CTkButton(
                            self.files_frame,
                            text=file_name,
                            command=lambda fname=file_name, fhash=file_hash: self.download_file_prompt(fname, fhash),
                            fg_color="transparent",
                            text_color="lightblue",
                            hover_color="grey",
                        )

                        file_button.bind("<Enter>", lambda event, button=file_button: on_enter(event, button))
                        file_button.bind("<Leave>", lambda event, button=file_button: on_leave(event, button))
                        file_button.pack(fill="x", pady=2)
                else:
                    no_files_label = ctk.CTkLabel(
                        self.files_frame,
                        text="No files found.",
                        font=("Arial", 14),
                        text_color="gray"
                    )
                    no_files_label.pack(pady=20)
            else:
                if response.status_code == 404 and "no files found" in response.text.lower():
                    if not hasattr(self, "files_frame"):
                        self.files_frame = ctk.CTkScrollableFrame(self, width=500, height=200)
                        self.files_frame.pack(pady=10, fill="x", expand=False)
                    else:
                        for widget in self.files_frame.winfo_children():
                            widget.destroy()

                    no_files_label = ctk.CTkLabel(
                        self.files_frame,
                        text="No files found.",
                        font=("Arial", 14),
                        text_color="lightgray"
                    )
                    no_files_label.pack(pady=20)
                else:
                    messagebox.showerror("Error", f"Failed to fetch uploaded files: {response.text}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch uploaded files: {e}")

    def download_file_prompt(self, file_name, fhash):
        save_path = filedialog.asksaveasfilename(
            title=f"Save {file_name} As",
            initialfile=file_name
        )
        if save_path:
            self.download_file(save_path, fhash)

    def download_file(self, save_path, fhash):
        try:
            response = requests.get(
                f"{self.api_url}/download/{fhash}",
                stream=True
            )
            if response.status_code == 200:
                with open(save_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                messagebox.showinfo("Success", f"File downloaded to {save_path}.")
            else:
                messagebox.showerror("Error", f"Failed to download file: {response.text}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to download file: {e}")

if __name__ == "__main__":
    app = FileEncryptorApp()
    app.mainloop()
