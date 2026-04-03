# ═══════════════════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Database and cryptography libraries for secure data management
#
# External libraries:
# - sqlite3: Database operations
# - hashlib: Password hashing (SHA-256)
# - Crypto: AES-256 encryption for usernames
# - cryptography.fernet: Non-deterministic encryption for sensitive data
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
# Description: Configuration paths and default credentials
#
# Key components:
# - DATA_DIR: Directory for database and encryption keys
# - DB_PATH: SQLite database file location
# - AES_KEY_PATH: AES-256 key for username encryption (deterministic)
# - FERNET_KEY_PATH: Fernet key for sensitive data encryption (non-deterministic)
# - SUPER_ADMIN credentials: Default admin account
# ═══════════════════════════════════════════════════════════════════════════

# File paths
DATA_DIR = Path(__file__).parent / "data"
DB_PATH = DATA_DIR / "urban_mobility.db"
AES_KEY_PATH = DATA_DIR / "aes_key.bin"
FERNET_KEY_PATH = DATA_DIR / "fernet_key.bin"

# Default super admin credentials
SUPER_ADMIN_USERNAME = "super_admin"
SUPER_ADMIN_PASSWORD = "Admin_123?"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: ENCRYPTION KEY MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════
# Description: Load or create encryption keys and username encryption/decryption
#
# Key components:
# - load_or_create_aes_key(): AES-256 key for deterministic username encryption
# - encrypt_username(): Encrypt username using AES-256 ECB (deterministic)
# - decrypt_username(): Decrypt username back to plain text
# - load_or_create_fernet_key(): Fernet key for non-deterministic data encryption
#
# Note: Keys are persisted to disk for consistency across application restarts
# ═══════════════════════════════════════════════════════════════════════════


def load_or_create_aes_key():
    """
    Load or create AES-256 key for username encryption.

    Uses ECB mode because usernames need to be searchable in the database
    (same username must produce same encrypted value for WHERE queries).

    Returns:
        bytes: 32-byte AES encryption key
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
    """
    Encrypt username using deterministic AES-256 ECB.

    Must be deterministic to allow database lookups (WHERE username = ?).

    Args:
        username (str): Plain text username

    Returns:
        str: Base64-encoded encrypted username
    """
    if username is None or username == "":
        return ""

    cipher = AES.new(aes_key, AES.MODE_ECB)
    padded = pad(username.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode()


def decrypt_username(encrypted_username):
    """
    Decrypt AES-encrypted username back to plain text.

    Args:
        encrypted_username (str): Base64-encoded encrypted username

    Returns:
        str: Plain text username
    """
    if encrypted_username is None or encrypted_username == "":
        return ""

    cipher = AES.new(aes_key, AES.MODE_ECB)
    encrypted = base64.b64decode(encrypted_username)
    decrypted = cipher.decrypt(encrypted)
    return unpad(decrypted, AES.block_size).decode()


def load_or_create_fernet_key():
    """
    Load or create Fernet key for encrypting sensitive data that doesn't need to be searched.

    Uses non-deterministic encryption (different output each time) for better security.
    Used for: emails, phones, driving licenses, serial numbers.

    Returns:
        Fernet: Encryption cipher object
    """
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
# SECTION 3: SENSITIVE DATA ENCRYPTION
# ═══════════════════════════════════════════════════════════════════════════
# Description: Encrypt and decrypt sensitive data (non-searchable fields)
#
# Key components:
# - encrypt_field(): Non-deterministic Fernet encryption for sensitive data
# - decrypt_field(): Decrypt Fernet-encrypted data back to plain text
#
# Encryption strategy:
# - Used for data that doesn't need to be searched: emails, phones, licenses, serial numbers
# - Non-deterministic (different output each time) for better security
# - Cannot be used in WHERE clauses (use username encryption for searchable fields)
# ═══════════════════════════════════════════════════════════════════════════


def encrypt_field(plaintext):
    """
    Encrypt field using Fernet (non-deterministic, more secure).

    Use for data that doesn't need to be searched: emails, phones, licenses, serial numbers.

    Args:
        plaintext (str): Plain text value

    Returns:
        str: Encrypted text
    """
    if plaintext is None or plaintext == "":
        return ""
    encrypted_bytes = fernet_cipher.encrypt(plaintext.encode())
    return encrypted_bytes.decode()


def decrypt_field(encrypted_text):
    """
    Decrypt Fernet-encrypted field back to plain text.

    Args:
        encrypted_text (str): Encrypted text

    Returns:
        str: Plain text value
    """
    if encrypted_text is None or encrypted_text == "":
        return ""
    decrypted_bytes = fernet_cipher.decrypt(encrypted_text.encode())
    return decrypted_bytes.decode()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: PASSWORD HASHING
# ═══════════════════════════════════════════════════════════════════════════
# Description: Secure password hashing with bcrypt
#
# Key components:
# - hash_password(): Hash password using bcrypt with automatic salt generation
# - verify_password(): Verify password against bcrypt hash
#
# Note: bcrypt includes random salt in the hash and uses adaptive cost factor
#       to remain resistant to brute-force attacks as hardware improves
# ═══════════════════════════════════════════════════════════════════════════


def hash_password(password, username=None):
    """
    Hash password using bcrypt with automatic salt generation.

    bcrypt is designed for password hashing with:
    - Automatic random salt generation
    - Adaptive cost factor
    - Industry-standard security

    Args:
        password (str): Plain text password
        username (str): Unused, kept for API compatibility with existing code

    Returns:
        str: Bcrypt hash string
    """
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=12)  # Cost factor: 12
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def verify_password(password, username, stored_hash):
    """
    Verify password against bcrypt hash.

    bcrypt automatically extracts the salt from the stored hash.

    Args:
        password (str): Plain text password to verify
        username (str): Unused, kept for API compatibility with existing code
        stored_hash (str): Bcrypt hash from database

    Returns:
        bool: True if password is correct
    """
    password_bytes = password.encode('utf-8')
    stored_hash_bytes = stored_hash.encode('utf-8')
    return bcrypt.checkpw(password_bytes, stored_hash_bytes)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5: DATABASE CONNECTION
# ═══════════════════════════════════════════════════════════════════════════
# Description: SQLite database connection management
#
# Key components:
# - get_connection(): Create SQLite connection with foreign keys enabled
#
# Note: Foreign keys are enabled for referential integrity
# ═══════════════════════════════════════════════════════════════════════════


def get_connection():
    """
    Create and return a database connection with foreign keys enabled.

    Returns:
        sqlite3.Connection: Database connection
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6: TABLE CREATION
# ═══════════════════════════════════════════════════════════════════════════
# Description: Database schema definition and table creation
#
# Key components:
# - create_tables(): Create all database tables (users, travelers, scooters)
#
# Tables:
# - users: System users (Super Admin, System Admin, Service Engineer)
# - travelers: Customers with encrypted personal information
# - scooters: Fleet inventory with encrypted serial numbers
# ═══════════════════════════════════════════════════════════════════════════


def create_tables():
    """
    Create database schema: users, travelers, and scooters tables.

    All sensitive fields are encrypted, passwords are hashed.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Users: system administrators and service engineers
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('super_admin', 'system_admin', 'service_engineer')),
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            must_change_password INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """
    )

    # Travelers: customers with encrypted personal information
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS travelers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id TEXT NOT NULL UNIQUE,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            birthday TEXT NOT NULL,
            gender TEXT NOT NULL CHECK(gender IN ('Male', 'Female')),
            street_name TEXT NOT NULL,
            house_number TEXT NOT NULL,
            zip_code TEXT NOT NULL,
            city TEXT NOT NULL,
            email TEXT NOT NULL,
            mobile_phone TEXT NOT NULL,
            driving_license TEXT NOT NULL,
            registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """
    )

    # Scooters: fleet inventory with encrypted serial numbers
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scooters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            serial_number TEXT NOT NULL UNIQUE,
            brand TEXT NOT NULL,
            model TEXT NOT NULL,
            top_speed REAL NOT NULL,
            battery_capacity INTEGER NOT NULL,
            state_of_charge INTEGER NOT NULL CHECK(state_of_charge >= 0 AND state_of_charge <= 100),
            target_range_soc_min INTEGER NOT NULL CHECK(target_range_soc_min >= 0 AND target_range_soc_min <= 100),
            target_range_soc_max INTEGER NOT NULL CHECK(target_range_soc_max >= 0 AND target_range_soc_max <= 100),
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            out_of_service_status INTEGER NOT NULL DEFAULT 0,
            mileage REAL NOT NULL DEFAULT 0,
            last_maintenance_date TEXT,
            in_service_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """
    )

    conn.commit()
    conn.close()

    print("✓ Database tables created successfully")


def init_super_admin():
    """
    Create default super admin account if it doesn't exist.

    Credentials: super_admin / Admin_123?
    Has full access to all system features.
    """
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
            (
                encrypted_username,
                password_hash,
                "super_admin",
                "Super",
                "Administrator",
            ),
        )

        conn.commit()
        print(f"✓ Super Admin account created")
        print(f"  Username: {SUPER_ADMIN_USERNAME}")
        print(f"  Password: {SUPER_ADMIN_PASSWORD}")
    else:
        print(f"✓ Super Admin account already exists")

    conn.close()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7: SYSTEM INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════
# Description: Initialize database system and default accounts
#
# Key components:
# - init_super_admin(): Create default Super Admin account
# - init_database(): Main initialization function (tables + super admin)
#
# Note: Called on application startup to ensure system is ready
# ═══════════════════════════════════════════════════════════════════════════


def init_database():
    """
    Initialize the complete database system: keys, tables, and super admin.

    Called on application startup.
    """
    print("=" * 60)
    print("URBAN MOBILITY BACKEND SYSTEM - DATABASE INITIALIZATION")
    print("=" * 60)

    create_tables()
    init_super_admin()

    print("=" * 60)
    print("✓ Database initialization complete!")
    print(f"✓ Database location: {DB_PATH}")
    print(f"✓ AES key: {AES_KEY_PATH}")
    print(f"✓ Fernet key: {FERNET_KEY_PATH}")
    print("=" * 60)
