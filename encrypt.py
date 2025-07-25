import os
import base64
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.font import Font


class FileVault:
    """Secure file encryption/decryption system that requires key for each operation"""

    def __init__(self, storage_dir="secure_vault"):
        self.storage_dir = storage_dir
        self.metadata_file = os.path.join(storage_dir, "vault_metadata.json")

        # Initialize storage directory
        os.makedirs(storage_dir, exist_ok=True)

        # Initialize metadata file
        if not os.path.exists(self.metadata_file):
            with open(self.metadata_file, 'w') as f:
                json.dump({}, f)

    def create_key_from_password(self, password, salt=None):
        """Generate encryption key from password (does not store it)"""
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=400000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode())), salt

    def encrypt_file(self, key, file_path):
        """Encrypt a file using the provided key"""
        try:
            fernet = Fernet(key)
        except:
            raise ValueError("Invalid encryption key format")

        # Read original file
        with open(file_path, 'rb') as f:
            original_data = f.read()

        # Generate hashes
        file_hash = hashlib.sha256(original_data).hexdigest()
        encrypted_data = fernet.encrypt(original_data)
        encrypted_hash = hashlib.sha256(encrypted_data).hexdigest()

        # Prepare encrypted filename
        original_name = os.path.basename(file_path)
        encrypted_name = f"{original_name}.enc"
        encrypted_path = os.path.join(self.storage_dir, encrypted_name)

        # Save encrypted file
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)

        # Update metadata
        metadata = self._load_metadata()
        metadata[encrypted_name] = {
            'original_name': original_name,
            'encrypted_at': datetime.now().isoformat(),
            'original_hash': file_hash,
            'encrypted_hash': encrypted_hash
        }
        self._save_metadata(metadata)

        return encrypted_name

    def decrypt_file(self, key, encrypted_name, output_dir=None):
        """Decrypt a file using the provided key"""
        try:
            fernet = Fernet(key)
        except:
            raise ValueError("Invalid encryption key format")

        encrypted_path = os.path.join(self.storage_dir, encrypted_name)

        # Verify file exists in metadata
        metadata = self._load_metadata()
        if encrypted_name not in metadata:
            raise ValueError("File not found in metadata")

        file_meta = metadata[encrypted_name]

        # Read encrypted file
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()

        # Verify encrypted file integrity
        current_encrypted_hash = hashlib.sha256(encrypted_data).hexdigest()
        if current_encrypted_hash != file_meta['encrypted_hash']:
            raise ValueError("Encrypted file has been modified")

        # Decrypt data
        try:
            decrypted_data = fernet.decrypt(encrypted_data)
        except:
            raise ValueError("Decryption failed - wrong key or corrupted file")

        # Verify original content integrity
        current_file_hash = hashlib.sha256(decrypted_data).hexdigest()
        if current_file_hash != file_meta['original_hash']:
            raise ValueError("Decrypted content doesn't match original")

        # Save decrypted file
        output_path = os.path.join(
            output_dir if output_dir else self.storage_dir,
            file_meta['original_name']
        )

        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        return output_path

    def get_file_list(self):
        """Get list of encrypted files with metadata"""
        return self._load_metadata()

    def _load_metadata(self):
        """Load metadata from file"""
        with open(self.metadata_file, 'r') as f:
            return json.load(f)

    def _save_metadata(self, metadata):
        """Save metadata to file"""
        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)


class SecureVaultApp:
    """GUI for the secure file vault system"""

    def __init__(self, root):
        self.root = root
        self.root.title("Secure Vault - AES File Encryption")
        self.root.geometry("1000x700")
        self.root.minsize(900, 650)

        # Initialize file vault system
        self.vault = FileVault()

        # Setup fonts and styles
        self.title_font = Font(family="Helvetica", size=12, weight="bold")
        self.button_font = Font(family="Segoe UI", size=10)
        self.status_font = Font(family="Consolas", size=9)
        self.configure_styles()

        # Build the interface
        self.setup_interface()

        # Load existing files
        self.refresh_file_list()

    def configure_styles(self):
        """Configure custom widget styles"""
        style = ttk.Style()
        style.configure('Main.TFrame', background='#f0f0f0')
        style.configure('Section.TLabelframe', background='#f0f0f0', borderwidth=2, relief=tk.RAISED, labelmargins=5)
        style.configure('Section.TLabelframe.Label', background='#f0f0f0', font=self.title_font)
        style.configure('Action.TButton', font=self.button_font, padding=5)
        style.map('Action.TButton',
                  foreground=[('active', 'black'), ('!active', 'black')],
                  background=[('active', '#e1e1e1'), ('!active', '#f0f0f0')])
        style.configure('File.Treeview', rowheight=25, font=('Segoe UI', 10))
        style.configure('File.Treeview.Heading', font=('Segoe UI', 10, 'bold'))
        style.configure('Status.TLabel', font=self.status_font, background='#e0e0e0', relief=tk.SUNKEN, padding=3)

    def setup_interface(self):
        """Build the application interface"""
        # Main container
        main_frame = ttk.Frame(self.root, style='Main.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(2, weight=1)

        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        ttk.Label(header_frame, text="Secure Vault", font=('Helvetica', 16, 'bold'), background='#f0f0f0').pack(
            side=tk.LEFT)

        # Key management section
        key_frame = ttk.LabelFrame(main_frame, text=" Encryption Key ", style='Section.TLabelframe')
        key_frame.grid(row=1, column=0, sticky='ew', padx=10, pady=5)
        self.setup_key_section(key_frame)

        # File operations section
        ops_frame = ttk.LabelFrame(main_frame, text=" File Operations ", style='Section.TLabelframe')
        ops_frame.grid(row=2, column=0, sticky='nsew', padx=10, pady=5)
        self.setup_file_operations(ops_frame)

        # Status bar
        self.status = ttk.Label(main_frame, text=" Ready ", style='Status.TLabel')
        self.status.grid(row=3, column=0, sticky='ew', padx=10, pady=(5, 0))

    def setup_key_section(self, parent):
        """Configure the key management section"""
        # Password section
        pass_frame = ttk.Frame(parent)
        pass_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(pass_frame, text="Password:", width=10, anchor=tk.W).pack(side=tk.LEFT, padx=(0, 5))
        self.pass_entry = ttk.Entry(pass_frame, show="•", width=40, font=self.button_font)
        self.pass_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(pass_frame, text="Generate Key", style='Action.TButton', command=self.generate_key).pack(
            side=tk.LEFT, padx=5)

        # Key entry section
        key_entry_frame = ttk.Frame(parent)
        key_entry_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(key_entry_frame, text="Encryption Key:", width=10, anchor=tk.W).pack(side=tk.LEFT, padx=(0, 5))
        self.key_entry = ttk.Entry(key_entry_frame, width=60, font=self.button_font)
        self.key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(key_entry_frame, text="Set Key", style='Action.TButton', command=self.set_key).pack(side=tk.LEFT,
                                                                                                       padx=5)

    def setup_file_operations(self, parent):
        """Configure the file operations section"""
        # Button toolbar
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill=tk.X, padx=5, pady=(0, 5))

        ttk.Button(toolbar, text="Encrypt File", style='Action.TButton', command=self.encrypt_file).pack(side=tk.LEFT,
                                                                                                         padx=2)
        ttk.Button(toolbar, text="Decrypt Selected", style='Action.TButton', command=self.decrypt_file).pack(
            side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Refresh List", style='Action.TButton', command=self.refresh_file_list).pack(
            side=tk.RIGHT, padx=2)

        # File list with scrollbars
        list_container = ttk.Frame(parent)
        list_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))

        # Create the treeview
        self.file_tree = ttk.Treeview(list_container, style='File.Treeview',
                                      columns=('original', 'date', 'hash'),
                                      selectmode='browse')

        # Configure columns
        self.file_tree.heading('#0', text='Encrypted Name', anchor=tk.W)
        self.file_tree.heading('original', text='Original Name', anchor=tk.W)
        self.file_tree.heading('date', text='Encrypted Date', anchor=tk.W)
        self.file_tree.heading('hash', text='File Hash', anchor=tk.W)

        self.file_tree.column('#0', width=200, stretch=tk.YES)
        self.file_tree.column('original', width=150, stretch=tk.YES)
        self.file_tree.column('date', width=150, stretch=tk.YES)
        self.file_tree.column('hash', width=100, stretch=tk.YES)

        # Add scrollbars
        y_scroll = ttk.Scrollbar(list_container, orient=tk.VERTICAL, command=self.file_tree.yview)
        x_scroll = ttk.Scrollbar(list_container, orient=tk.HORIZONTAL, command=self.file_tree.xview)
        self.file_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        # Layout components
        self.file_tree.grid(row=0, column=0, sticky='nsew')
        y_scroll.grid(row=0, column=1, sticky='ns')
        x_scroll.grid(row=1, column=0, sticky='ew')

        # Configure resizing
        list_container.grid_rowconfigure(0, weight=1)
        list_container.grid_columnconfigure(0, weight=1)

    def generate_key(self):
        """Generate encryption key from password"""
        password = self.pass_entry.get()
        if not password:
            self.update_status("Please enter a password first")
            messagebox.showwarning("Missing Password", "You must enter a password to generate a key")
            return

        try:
            key, _ = self.vault.create_key_from_password(password)
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, key.decode())
            self.update_status("Generated new encryption key from password")
        except Exception as e:
            self.update_status(f"Key generation failed: {str(e)}")
            messagebox.showerror("Key Generation Error", f"Failed to generate key:\n{str(e)}")

    def set_key(self):
        """Validate and use the entered key"""
        key = self.key_entry.get()
        if not key:
            self.update_status("No key provided")
            messagebox.showwarning("Missing Key", "Please enter an encryption key")
            return

        # Test if the key is valid by trying to create a Fernet instance
        try:
            Fernet(key.encode())
            self.update_status("Encryption key is valid")
        except Exception as e:
            self.update_status(f"Invalid key: {str(e)}")
            messagebox.showerror("Key Error", f"Invalid encryption key:\n{str(e)}")

    def encrypt_file(self):
        """Handle file encryption"""
        key = self.key_entry.get()
        if not key:
            self.update_status("Cannot encrypt - no key provided")
            messagebox.showwarning("Key Required", "Please enter an encryption key first")
            return

        file_path = filedialog.askopenfilename(title="Select file to encrypt")
        if not file_path:
            return

        try:
            encrypted_name = self.vault.encrypt_file(key.encode(), file_path)
            self.refresh_file_list()
            self.update_status(f"File encrypted as: {encrypted_name}")
            messagebox.showinfo("Success", f"File encrypted successfully as:\n{encrypted_name}")
        except Exception as e:
            self.update_status(f"Encryption failed: {str(e)}")
            messagebox.showerror("Encryption Error", f"Failed to encrypt file:\n{str(e)}")

    def decrypt_file(self):
        """Handle file decryption"""
        key = self.key_entry.get()
        if not key:
            self.update_status("Cannot decrypt - no key provided")
            messagebox.showwarning("Key Required", "Please enter an encryption key first")
            return

        selected = self.file_tree.selection()
        if not selected:
            self.update_status("No file selected for decryption")
            messagebox.showwarning("No Selection", "Please select a file to decrypt")
            return

        encrypted_name = self.file_tree.item(selected[0])['text']
        output_dir = filedialog.askdirectory(title="Select output directory")

        if not output_dir:
            return

        try:
            output_path = self.vault.decrypt_file(key.encode(), encrypted_name, output_dir)
            self.update_status(f"File decrypted to: {output_path}")
            messagebox.showinfo("Success", f"File successfully decrypted to:\n{output_path}")
        except Exception as e:
            self.update_status(f"Decryption failed: {str(e)}")
            messagebox.showerror("Decryption Error", f"Failed to decrypt file:\n{str(e)}")

    def refresh_file_list(self):
        """Update the file list display"""
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)

        files = self.vault.get_file_list()
        for enc_name, meta in files.items():
            self.file_tree.insert('', 'end',
                                  text=enc_name,
                                  values=(
                                      meta['original_name'],
                                      meta['encrypted_at'][:19],
                                      meta['original_hash'][:8] + "..."
                                  ))

        self.update_status(f"Showing {len(files)} encrypted files")

    def update_status(self, message):
        """Update the status bar"""
        self.status.config(text=f" {message} ")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureVaultApp(root)
    root.mainloop()