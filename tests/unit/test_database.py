"""
Unit tests for database.py module.

Tests encryption, password hashing, database initialization,
and connection management functions.
"""

import pytest
from unittest.mock import Mock, patch
import sqlite3
from database import (
    encrypt_username,
    decrypt_username,
    encrypt_field,
    decrypt_field,
    hash_password,
    verify_password,
    get_connection,
    create_tables,
    init_super_admin,
    init_database,
)


# ============================================================================
# Key Loading Tests
# ============================================================================


@pytest.mark.unit
class TestKeyLoading:
    """Test loading existing encryption keys from files"""

    @patch("database.AES_KEY_PATH")
    @patch("database.DATA_DIR")
    def test_load_or_create_aes_key_loads_existing_key(
        self, mock_data_dir, mock_aes_key_path
    ):
        """Test that load_or_create_aes_key loads existing key from file"""
        from database import load_or_create_aes_key
        from unittest.mock import MagicMock, mock_open

        # Simulate existing key file
        mock_aes_key_path.exists.return_value = True
        test_key = b"0" * 32  # 32-byte test key

        # Mock the file opening
        m = mock_open(read_data=test_key)
        with patch("builtins.open", m):
            key = load_or_create_aes_key()

            # Verify key was loaded from file
            assert key == test_key
            m.assert_called_once_with(mock_aes_key_path, "rb")

    @patch("database.FERNET_KEY_PATH")
    @patch("database.DATA_DIR")
    def test_load_or_create_fernet_key_loads_existing_key(
        self, mock_data_dir, mock_fernet_key_path
    ):
        """Test that load_or_create_fernet_key loads existing key from file"""
        from database import load_or_create_fernet_key
        from cryptography.fernet import Fernet
        from unittest.mock import mock_open

        # Simulate existing key file
        mock_fernet_key_path.exists.return_value = True
        test_key = Fernet.generate_key()

        # Mock the file opening
        m = mock_open(read_data=test_key)
        with patch("builtins.open", m):
            cipher = load_or_create_fernet_key()

            # Verify key was loaded from file
            m.assert_called_once_with(mock_fernet_key_path, "rb")
            assert cipher is not None


# ============================================================================
# Encryption Tests - Username (AES)
# ============================================================================


@pytest.mark.unit
class TestUsernameEncryption:
    """Test AES encryption for usernames"""

    def test_encrypt_username_success(self):
        """Test encrypting a username"""
        username = "testuser"
        encrypted = encrypt_username(username)

        assert encrypted is not None
        assert encrypted != username
        assert isinstance(encrypted, str)

    def test_decrypt_username_success(self):
        """Test decrypting an encrypted username"""
        username = "testuser"
        encrypted = encrypt_username(username)
        decrypted = decrypt_username(encrypted)

        assert decrypted == username

    def test_encrypt_username_deterministic(self):
        """Test that same username always produces same encrypted value"""
        username = "testuser"
        encrypted1 = encrypt_username(username)
        encrypted2 = encrypt_username(username)

        assert encrypted1 == encrypted2

    def test_encrypt_empty_username(self):
        """Test encrypting empty username"""
        encrypted = encrypt_username("")
        assert encrypted == ""

    def test_decrypt_empty_username(self):
        """Test decrypting empty username"""
        decrypted = decrypt_username("")
        assert decrypted == ""

    def test_encrypt_username_none(self):
        """Test encrypting None username"""
        encrypted = encrypt_username(None)
        assert encrypted == ""


# ============================================================================
# Encryption Tests - Fields (Fernet)
# ============================================================================


@pytest.mark.unit
class TestFieldEncryption:
    """Test Fernet encryption for sensitive fields"""

    def test_encrypt_field_success(self):
        """Test encrypting a field"""
        plaintext = "sensitive_data"
        encrypted = encrypt_field(plaintext)

        assert encrypted is not None
        assert encrypted != plaintext
        assert isinstance(encrypted, str)

    def test_decrypt_field_success(self):
        """Test decrypting an encrypted field"""
        plaintext = "sensitive_data"
        encrypted = encrypt_field(plaintext)
        decrypted = decrypt_field(encrypted)

        assert decrypted == plaintext

    def test_encrypt_field_non_deterministic(self):
        """Test that same field produces different encrypted values (Fernet)"""
        plaintext = "test@example.com"
        encrypted1 = encrypt_field(plaintext)
        encrypted2 = encrypt_field(plaintext)

        # Fernet is non-deterministic, so same input produces different output
        assert encrypted1 != encrypted2

    def test_encrypt_empty_field(self):
        """Test encrypting empty field"""
        encrypted = encrypt_field("")
        assert encrypted == ""

    def test_decrypt_empty_field(self):
        """Test decrypting empty field"""
        decrypted = decrypt_field("")
        assert decrypted == ""

    def test_encrypt_field_none(self):
        """Test encrypting None field"""
        encrypted = encrypt_field(None)
        assert encrypted == ""

    def test_encrypt_decrypt_email(self):
        """Test encrypting and decrypting email"""
        email = "user@example.com"
        encrypted = encrypt_field(email)
        decrypted = decrypt_field(encrypted)

        assert decrypted == email

    def test_encrypt_decrypt_phone(self):
        """Test encrypting and decrypting phone number"""
        phone = "12345678"
        encrypted = encrypt_field(phone)
        decrypted = decrypt_field(encrypted)

        assert decrypted == phone


# ============================================================================
# Password Hashing Tests
# ============================================================================


@pytest.mark.unit
class TestPasswordHashing:
    """Test password hashing and verification"""

    def test_hash_password_success(self):
        """Test hashing a password"""
        password = "TestPass123!"
        username = "testuser"
        hashed = hash_password(password, username)

        assert hashed is not None
        assert hashed != password
        assert isinstance(hashed, str)
        assert hashed.startswith('$2b$')  # bcrypt hash format
        assert len(hashed) == 60  # bcrypt produces 60-char string

    def test_verify_password_correct(self):
        """Test verifying correct password"""
        password = "TestPass123!"
        username = "testuser"
        hashed = hash_password(password, username)

        assert verify_password(password, username, hashed) is True

    def test_verify_password_incorrect(self):
        """Test verifying incorrect password"""
        password = "TestPass123!"
        wrong_password = "WrongPass456!"
        username = "testuser"
        hashed = hash_password(password, username)

        assert verify_password(wrong_password, username, hashed) is False

    def test_hash_password_non_deterministic(self):
        """Test that bcrypt produces different hashes each time (random salt)"""
        password = "TestPass123!"
        username = "testuser"

        hash1 = hash_password(password, username)
        hash2 = hash_password(password, username)

        # bcrypt is non-deterministic (different random salt each time)
        assert hash1 != hash2
        # But both should verify correctly
        assert verify_password(password, username, hash1) is True
        assert verify_password(password, username, hash2) is True

    def test_verify_password_case_sensitive(self):
        """Test that password verification is case-sensitive"""
        password = "TestPass123!"
        wrong_case = "testpass123!"
        username = "testuser"
        hashed = hash_password(password, username)

        assert verify_password(wrong_case, username, hashed) is False


# ============================================================================
# Database Connection Tests
# ============================================================================


@pytest.mark.unit
class TestDatabaseConnection:
    """Test database connection management"""

    @patch("database.DB_PATH")
    @patch("database.DATA_DIR")
    def test_get_connection_creates_directory(self, mock_data_dir, mock_db_path):
        """Test that get_connection creates data directory"""
        mock_data_dir.mkdir = Mock()

        # Use in-memory database for testing
        with patch("database.sqlite3.connect") as mock_connect:
            mock_connect.return_value = Mock(spec=sqlite3.Connection)

            conn = get_connection()

            mock_data_dir.mkdir.assert_called_once_with(parents=True, exist_ok=True)

    def test_get_connection_enables_foreign_keys(self):
        """Test that foreign keys are enabled"""
        with patch("database.sqlite3.connect") as mock_connect:
            mock_conn = Mock(spec=sqlite3.Connection)
            mock_connect.return_value = mock_conn

            conn = get_connection()

            mock_conn.execute.assert_called_once_with("PRAGMA foreign_keys = ON")

    def test_get_connection_returns_connection(self):
        """Test that get_connection returns a connection object"""
        with patch("database.sqlite3.connect") as mock_connect:
            mock_conn = Mock(spec=sqlite3.Connection)
            mock_connect.return_value = mock_conn

            conn = get_connection()

            assert conn is mock_conn


# ============================================================================
# Table Creation Tests
# ============================================================================


@pytest.mark.unit
class TestTableCreation:
    """Test database table creation"""

    @patch("database.get_connection")
    def test_create_tables_success(self, mock_get_conn):
        """Test creating database tables"""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        create_tables()

        # Should execute CREATE TABLE for users, travelers, and scooters
        assert mock_cursor.execute.call_count == 3
        mock_conn.commit.assert_called_once()
        mock_conn.close.assert_called_once()

    @patch("database.get_connection")
    def test_create_tables_users_table(self, mock_get_conn):
        """Test that users table is created with correct schema"""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        create_tables()

        # Check first call (users table)
        users_call = mock_cursor.execute.call_args_list[0]
        users_sql = users_call[0][0]

        assert "CREATE TABLE IF NOT EXISTS users" in users_sql
        assert "username TEXT NOT NULL UNIQUE" in users_sql
        assert "password_hash TEXT NOT NULL" in users_sql
        assert "role TEXT NOT NULL" in users_sql

    @patch("database.get_connection")
    def test_create_tables_travelers_table(self, mock_get_conn):
        """Test that travelers table is created with correct schema"""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        create_tables()

        # Check second call (travelers table)
        travelers_call = mock_cursor.execute.call_args_list[1]
        travelers_sql = travelers_call[0][0]

        assert "CREATE TABLE IF NOT EXISTS travelers" in travelers_sql
        assert "customer_id TEXT NOT NULL UNIQUE" in travelers_sql
        assert "email TEXT NOT NULL" in travelers_sql

    @patch("database.get_connection")
    def test_create_tables_scooters_table(self, mock_get_conn):
        """Test that scooters table is created with correct schema"""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        create_tables()

        # Check third call (scooters table)
        scooters_call = mock_cursor.execute.call_args_list[2]
        scooters_sql = scooters_call[0][0]

        assert "CREATE TABLE IF NOT EXISTS scooters" in scooters_sql
        assert "serial_number TEXT NOT NULL UNIQUE" in scooters_sql
        assert "brand TEXT NOT NULL" in scooters_sql
        assert "model TEXT NOT NULL" in scooters_sql
        assert "battery_capacity INTEGER NOT NULL" in scooters_sql
        assert "state_of_charge INTEGER NOT NULL" in scooters_sql
        assert "latitude REAL NOT NULL" in scooters_sql
        assert "longitude REAL NOT NULL" in scooters_sql


# ============================================================================
# Super Admin Initialization Tests
# ============================================================================


@pytest.mark.unit
class TestSuperAdminInit:
    """Test super admin account initialization"""

    @patch("database.get_connection")
    @patch("database.hash_password")
    @patch("database.encrypt_username")
    def test_init_super_admin_creates_account(
        self, mock_encrypt, mock_hash, mock_get_conn
    ):
        """Test that super admin account is created if it doesn't exist"""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None  # User doesn't exist
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        mock_encrypt.return_value = "encrypted_super_admin"
        mock_hash.return_value = "hashed_password"

        init_super_admin()

        # Should check if user exists
        mock_cursor.execute.assert_any_call(
            "SELECT id FROM users WHERE username = ?", ("encrypted_super_admin",)
        )

        # Should insert new super admin
        insert_call = [
            call for call in mock_cursor.execute.call_args_list if "INSERT" in str(call)
        ]
        assert len(insert_call) == 1

        mock_conn.commit.assert_called_once()

    @patch("database.get_connection")
    @patch("database.encrypt_username")
    def test_init_super_admin_already_exists(self, mock_encrypt, mock_get_conn):
        """Test that super admin is not created if already exists"""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1,)  # User exists
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        mock_encrypt.return_value = "encrypted_super_admin"

        init_super_admin()

        # Should only execute SELECT, not INSERT
        assert mock_cursor.execute.call_count == 1
        mock_conn.commit.assert_not_called()


# ============================================================================
# Database Initialization Tests
# ============================================================================


@pytest.mark.unit
class TestDatabaseInit:
    """Test complete database initialization"""

    @patch("database.init_super_admin")
    @patch("database.create_tables")
    def test_init_database_success(self, mock_create_tables, mock_init_super):
        """Test that init_database calls all necessary functions"""
        init_database()

        mock_create_tables.assert_called_once()
        mock_init_super.assert_called_once()


# ============================================================================
# Integration Tests
# ============================================================================


@pytest.mark.unit
class TestDatabaseIntegration:
    """Integration tests for database operations"""

    def test_encrypt_decrypt_roundtrip_username(self):
        """Test full roundtrip encryption/decryption for username"""
        original = "test_user_123"
        encrypted = encrypt_username(original)
        decrypted = decrypt_username(encrypted)

        assert decrypted == original
        assert encrypted != original

    def test_encrypt_decrypt_roundtrip_field(self):
        """Test full roundtrip encryption/decryption for field"""
        original = "test@example.com"
        encrypted = encrypt_field(original)
        decrypted = decrypt_field(encrypted)

        assert decrypted == original
        assert encrypted != original

    def test_password_hash_verify_roundtrip(self):
        """Test full roundtrip password hashing and verification"""
        password = "SecurePass123!@#"
        username = "testuser"

        hashed = hash_password(password, username)
        is_valid = verify_password(password, username, hashed)

        assert is_valid is True
        assert hashed != password
