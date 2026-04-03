# ═══════════════════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════════════════

import sqlite3
import bcrypt
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet
import base64


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: CONSTANTS & FILE PATHS
# ═══════════════════════════════════════════════════════════════════════════

DATA_DIR = Path(__file__).parent / "data"
DB_PATH = DATA_DIR / "declaratieapp.db"
AES_KEY_PATH = DATA_DIR / "aes_key.bin"
FERNET_KEY_PATH = DATA_DIR / "fernet_key.bin"

# Hard-coded Super Administrator credentials (assignment requirement)
SUPER_ADMIN_USERNAME = "super_admin"
SUPER_ADMIN_PASSWORD = "Admin_123?"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: ENCRYPTION KEY MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════


def load_or_create_aes_key():
    """
    Load or create AES-256 key for deterministic username encryption.
    Uses ECB mode so usernames can be searched in WHERE clauses.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if AES_KEY_PATH.exists():
        with open(AES_KEY_PATH, "rb") as key_file:
            key = key_file.read()
        print(f"✓ AES key loaded from {AES_KEY_PATH}")
    else:
        key = get_random_bytes(32)
        with open(AES_KEY_PATH, "wb") as key_file:
            key_file.write(key)
        print(f"✓ New AES key created at {AES_KEY_PATH}")
    return key


aes_key = load_or_create_aes_key()


def encrypt_username(username):
    """Encrypt username using deterministic AES-256 ECB (searchable)."""
    if username is None or username == "":
        return ""
    cipher = AES.new(aes_key, AES.MODE_ECB)
    padded = pad(username.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode()


def decrypt_username(encrypted_username):
    """Decrypt AES-encrypted username back to plain text."""
    if encrypted_username is None or encrypted_username == "":
        return ""
    cipher = AES.new(aes_key, AES.MODE_ECB)
    encrypted = base64.b64decode(encrypted_username)
    decrypted = cipher.decrypt(encrypted)
    return unpad(decrypted, AES.block_size).decode()


def load_or_create_fernet_key():
    """Load or create Fernet key for non-deterministic encryption of sensitive data."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if FERNET_KEY_PATH.exists():
        with open(FERNET_KEY_PATH, "rb") as key_file:
            key = key_file.read()
        print(f"✓ Fernet key loaded from {FERNET_KEY_PATH}")
    else:
        key = Fernet.generate_key()
        with open(FERNET_KEY_PATH, "wb") as key_file:
            key_file.write(key)
        print(f"✓ New Fernet key created at {FERNET_KEY_PATH}")
    return Fernet(key)


fernet_cipher = load_or_create_fernet_key()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: SENSITIVE DATA ENCRYPTION (Fernet - non-deterministic)
# ═══════════════════════════════════════════════════════════════════════════


def encrypt_field(plaintext):
    """Encrypt field using Fernet (non-deterministic). For data that doesn't need searching."""
    if plaintext is None or plaintext == "":
        return ""
    encrypted_bytes = fernet_cipher.encrypt(str(plaintext).encode())
    return encrypted_bytes.decode()


def decrypt_field(encrypted_text):
    """Decrypt Fernet-encrypted field back to plain text."""
    if encrypted_text is None or encrypted_text == "":
        return ""
    decrypted_bytes = fernet_cipher.decrypt(encrypted_text.encode())
    return decrypted_bytes.decode()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: PASSWORD HASHING (bcrypt)
# ═══════════════════════════════════════════════════════════════════════════


def hash_password(password, username=None):
    """Hash password using bcrypt with automatic salt generation."""
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def verify_password(password, username, stored_hash):
    """Verify password against bcrypt hash."""
    password_bytes = password.encode('utf-8')
    stored_hash_bytes = stored_hash.encode('utf-8')
    return bcrypt.checkpw(password_bytes, stored_hash_bytes)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5: DATABASE CONNECTION
# ═══════════════════════════════════════════════════════════════════════════


def get_connection():
    """Create and return a database connection with foreign keys enabled."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6: TABLE CREATION
# ═══════════════════════════════════════════════════════════════════════════


def create_tables():
    """
    Create database schema: users, employees, and claims tables.
    All sensitive fields are encrypted, passwords are hashed.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Users: Super Admin, Managers, Employees (login accounts)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('super_admin', 'manager', 'employee')),
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            employee_id INTEGER,
            must_change_password INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE SET NULL
        )
    """
    )

    # Employees: personal data of CoreStaff Solutions employees
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            birthday TEXT NOT NULL,
            gender TEXT NOT NULL,
            street_name TEXT NOT NULL,
            house_number TEXT NOT NULL,
            zip_code TEXT NOT NULL,
            city TEXT NOT NULL,
            email TEXT NOT NULL,
            mobile_phone TEXT NOT NULL,
            identity_doc_type TEXT NOT NULL,
            identity_doc_number TEXT NOT NULL,
            bsn TEXT NOT NULL,
            registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """
    )

    # Claims: travel and home office expense claims
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS claims (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            claim_date TEXT NOT NULL,
            project_number TEXT NOT NULL,
            employee_id INTEGER NOT NULL,
            claim_type TEXT NOT NULL,
            travel_distance TEXT,
            from_zip_code TEXT,
            from_house_number TEXT,
            to_zip_code TEXT,
            to_house_number TEXT,
            approved TEXT NOT NULL DEFAULT '',
            approved_by TEXT,
            salary_batch TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
        )
    """
    )

    conn.commit()
    conn.close()
    print("✓ Database tables created successfully")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7: SYSTEM INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════


def init_super_admin():
    """Create default super admin account if it doesn't exist."""
    conn = get_connection()
    cursor = conn.cursor()

    encrypted_username = encrypt_username(SUPER_ADMIN_USERNAME)
    cursor.execute("SELECT id FROM users WHERE username = ?", (encrypted_username,))

    if cursor.fetchone() is None:
        password_hash = hash_password(SUPER_ADMIN_PASSWORD, SUPER_ADMIN_USERNAME)
        cursor.execute(
            """
            INSERT INTO users (username, password_hash, role, first_name, last_name)
            VALUES (?, ?, ?, ?, ?)
        """,
            (encrypted_username, password_hash, "super_admin", "Super", "Administrator"),
        )
        conn.commit()
        print(f"✓ Super Admin account created")
        print(f"  Username: {SUPER_ADMIN_USERNAME}")
        print(f"  Password: {SUPER_ADMIN_PASSWORD}")
    else:
        print(f"✓ Super Admin account already exists")

    conn.close()


def init_database():
    """Initialize the complete database system."""
    print("=" * 60)
    print("DECLARATIEAPP BACKEND SYSTEM - DATABASE INITIALIZATION")
    print("=" * 60)
    create_tables()
    init_super_admin()
    print("=" * 60)
    print("✓ Database initialization complete!")
    print(f"✓ Database location: {DB_PATH}")
    print(f"✓ AES key: {AES_KEY_PATH}")
    print(f"✓ Fernet key: {FERNET_KEY_PATH}")
    print("=" * 60)
