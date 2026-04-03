"""
Unit tests for backup.py module.

Tests backup and restore functionality including ZIP operations,
restore code management, and role-based access control.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, mock_open
from pathlib import Path
from datetime import datetime
from backup import (
    create_backup,
    list_backups,
    restore_backup,
    generate_restore_code,
    revoke_restore_code,
    list_restore_codes,
    _validate_restore_code,
    _mark_code_as_used,
)


# ============================================================================
# Create Backup Tests
# ============================================================================


@pytest.mark.unit
class TestCreateBackup:
    """Test backup creation functionality"""

    @patch("backup.log_activity")
    @patch("backup.get_current_user")
    @patch("backup.check_permission")
    def test_create_backup_no_permission(
        self, mock_check_perm, mock_get_user, mock_log
    ):
        """Test creating backup without permission"""
        mock_check_perm.return_value = False

        success, msg, filename = create_backup()

        assert success is False
        assert "access denied" in msg.lower()
        assert filename is None

    @patch("backup.log_activity")
    @patch("backup.BACKUP_DIR")
    @patch("backup.DATA_DIR")
    @patch("backup.zipfile.ZipFile")
    @patch("backup.get_current_user")
    @patch("backup.check_permission")
    def test_create_backup_success(
        self,
        mock_check_perm,
        mock_get_user,
        mock_zipfile,
        mock_data_dir,
        mock_backup_dir,
        mock_log,
    ):
        """Test successfully creating backup"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "super_admin"}
        mock_backup_dir.mkdir = Mock()

        # Mock file paths
        db_path = Mock()
        db_path.exists.return_value = True
        aes_path = Mock()
        aes_path.exists.return_value = True
        fernet_path = Mock()
        fernet_path.exists.return_value = True
        log_path = Mock()
        log_path.exists.return_value = True

        with patch.object(
            Path, "__truediv__", side_effect=[db_path, aes_path, fernet_path, log_path]
        ):
            mock_zip_context = MagicMock()
            mock_zipfile.return_value.__enter__.return_value = mock_zip_context

            success, msg, filename = create_backup()

        assert success is True
        assert "created successfully" in msg.lower()
        assert filename is not None
        assert filename.startswith("backup_")
        assert filename.endswith(".zip")
        mock_backup_dir.mkdir.assert_called_once_with(parents=True, exist_ok=True)

    @patch("backup.log_activity")
    @patch("backup.BACKUP_DIR")
    @patch("backup.zipfile.ZipFile")
    @patch("backup.get_current_user")
    @patch("backup.check_permission")
    def test_create_backup_error_handling(
        self, mock_check_perm, mock_get_user, mock_zipfile, mock_backup_dir, mock_log
    ):
        """Test error handling during backup creation"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin"}
        mock_zipfile.side_effect = Exception("Disk full")

        success, msg, filename = create_backup()

        assert success is False
        assert "error" in msg.lower()
        assert filename is None


# ============================================================================
# List Backups Tests
# ============================================================================


@pytest.mark.unit
class TestListBackups:
    """Test listing available backups"""

    @patch("backup.BACKUP_DIR")
    def test_list_backups_directory_not_exists(self, mock_backup_dir):
        """Test listing backups when directory doesn't exist"""
        mock_backup_dir.exists.return_value = False

        backups = list_backups()

        assert backups == []

    @patch("backup.BACKUP_DIR")
    def test_list_backups_success(self, mock_backup_dir):
        """Test successfully listing backups"""
        mock_backup_dir.exists.return_value = True

        # Mock backup files
        mock_file1 = Mock()
        mock_file1.name = "backup_20250101_100000.zip"
        mock_stat1 = Mock()
        mock_stat1.st_size = 1024
        mock_stat1.st_mtime = 1704106800.0  # 2024-01-01 10:00:00
        mock_file1.stat.return_value = mock_stat1

        mock_file2 = Mock()
        mock_file2.name = "backup_20250102_150000.zip"
        mock_stat2 = Mock()
        mock_stat2.st_size = 2048
        mock_stat2.st_mtime = 1704204000.0  # 2024-01-02 15:00:00
        mock_file2.stat.return_value = mock_stat2

        mock_backup_dir.glob.return_value = [mock_file1, mock_file2]

        backups = list_backups()

        assert len(backups) == 2
        # Should be sorted by creation time (newest first)
        assert backups[0]["filename"] == "backup_20250102_150000.zip"
        assert backups[0]["size"] == 2048
        assert backups[1]["filename"] == "backup_20250101_100000.zip"
        assert backups[1]["size"] == 1024

    @patch("backup.BACKUP_DIR")
    def test_list_backups_empty(self, mock_backup_dir):
        """Test listing backups when none exist"""
        mock_backup_dir.exists.return_value = True
        mock_backup_dir.glob.return_value = []

        backups = list_backups()

        assert backups == []


# ============================================================================
# Restore Backup Tests
# ============================================================================


@pytest.mark.unit
class TestRestoreBackup:
    """Test backup restoration functionality"""

    @patch("backup.get_current_user")
    def test_restore_backup_not_logged_in(self, mock_get_user):
        """Test restoring backup when not logged in"""
        mock_get_user.return_value = None

        success, msg = restore_backup("backup_test.zip")

        assert success is False
        assert "logged in" in msg.lower()

    @patch("backup.check_permission")
    @patch("backup.get_current_user")
    def test_restore_backup_no_permission(self, mock_get_user, mock_check_perm):
        """Test restoring backup without permission"""
        mock_get_user.return_value = {
            "username": "engineer",
            "role": "service_engineer",
        }
        mock_check_perm.return_value = False

        success, msg = restore_backup("backup_test.zip")

        assert success is False
        assert "access denied" in msg.lower()

    @patch("backup.check_permission")
    @patch("backup.get_current_user")
    def test_restore_backup_system_admin_no_code(self, mock_get_user, mock_check_perm):
        """Test system admin trying to restore without code"""
        mock_get_user.return_value = {"username": "admin", "role": "system_admin"}
        mock_check_perm.side_effect = lambda x: x == "restore_backup"

        success, msg = restore_backup("backup_test.zip", restore_code=None)

        assert success is False
        assert "restore code" in msg.lower()

    @patch("backup.log_activity")
    @patch("backup.BACKUP_DIR")
    @patch("backup.DATA_DIR")
    @patch("backup.zipfile.ZipFile")
    @patch("backup.check_permission")
    @patch("backup.get_current_user")
    def test_restore_backup_super_admin_success(
        self,
        mock_get_user,
        mock_check_perm,
        mock_zipfile,
        mock_data_dir,
        mock_backup_dir,
        mock_log,
    ):
        """Test super admin successfully restoring backup without code"""
        mock_get_user.return_value = {"username": "super_admin", "role": "super_admin"}
        mock_check_perm.side_effect = lambda x: x == "manage_restore_codes"

        # Mock backup file exists
        backup_path = Mock()
        backup_path.exists.return_value = True
        with patch.object(Path, "__truediv__", return_value=backup_path):
            mock_zip_context = MagicMock()
            mock_zip_context.namelist.return_value = [
                "urban_mobility.db",
                "aes_key.bin",
                "fernet_key.bin",
                "system.log",
            ]
            mock_zipfile.return_value.__enter__.return_value = mock_zip_context

            success, msg = restore_backup("backup_test.zip")

        assert success is True
        assert "restored successfully" in msg.lower()
        mock_log.assert_called_once()

    @patch("backup._validate_restore_code")
    @patch("backup._mark_code_as_used")
    @patch("backup.log_activity")
    @patch("backup.BACKUP_DIR")
    @patch("backup.DATA_DIR")
    @patch("backup.zipfile.ZipFile")
    @patch("backup.check_permission")
    @patch("backup.get_current_user")
    def test_restore_backup_system_admin_valid_code(
        self,
        mock_get_user,
        mock_check_perm,
        mock_zipfile,
        mock_data_dir,
        mock_backup_dir,
        mock_log,
        mock_mark_used,
        mock_validate,
    ):
        """Test system admin restoring with valid code"""
        mock_get_user.return_value = {"username": "admin", "role": "system_admin"}
        mock_check_perm.side_effect = lambda x: x == "restore_backup"
        mock_validate.return_value = (True, "backup_test.zip")

        backup_path = Mock()
        backup_path.exists.return_value = True
        with patch.object(Path, "__truediv__", return_value=backup_path):
            mock_zip_context = MagicMock()
            mock_zip_context.namelist.return_value = ["urban_mobility.db"]
            mock_zipfile.return_value.__enter__.return_value = mock_zip_context

            success, msg = restore_backup("backup_test.zip", restore_code="ABC123")

        assert success is True
        assert "restored successfully" in msg.lower()
        mock_validate.assert_called_once_with("ABC123")
        mock_mark_used.assert_called_once_with("ABC123")

    @patch("backup.log_activity")
    @patch("backup._validate_restore_code")
    @patch("backup.check_permission")
    @patch("backup.get_current_user")
    def test_restore_backup_system_admin_invalid_code(
        self, mock_get_user, mock_check_perm, mock_validate, mock_log
    ):
        """Test system admin with invalid restore code"""
        mock_get_user.return_value = {"username": "admin", "role": "system_admin"}
        mock_check_perm.side_effect = lambda x: x == "restore_backup"
        mock_validate.return_value = (False, None)

        success, msg = restore_backup("backup_test.zip", restore_code="INVALID")

        assert success is False
        assert "invalid" in msg.lower()
        mock_log.assert_called_once()
        # Check suspicious flag
        assert mock_log.call_args[1]["suspicious"] is True

    @patch("backup._validate_restore_code")
    @patch("backup.check_permission")
    @patch("backup.get_current_user")
    def test_restore_backup_wrong_backup_for_code(
        self, mock_get_user, mock_check_perm, mock_validate
    ):
        """Test system admin using code for different backup"""
        mock_get_user.return_value = {"username": "admin", "role": "system_admin"}
        mock_check_perm.side_effect = lambda x: x == "restore_backup"
        mock_validate.return_value = (True, "backup_other.zip")

        success, msg = restore_backup("backup_test.zip", restore_code="ABC123")

        assert success is False
        assert "valid for" in msg.lower()

    @patch("backup.check_permission")
    @patch("backup.get_current_user")
    def test_restore_backup_file_not_found(self, mock_get_user, mock_check_perm):
        """Test restoring non-existent backup"""
        mock_get_user.return_value = {"username": "super_admin", "role": "super_admin"}
        mock_check_perm.side_effect = lambda x: x == "manage_restore_codes"

        # Mock the backup path to not exist
        with patch("backup.BACKUP_DIR") as mock_backup_dir:
            backup_path = Mock()
            backup_path.exists.return_value = False
            mock_backup_dir.__truediv__ = Mock(return_value=backup_path)

            success, msg = restore_backup("nonexistent.zip")

        assert success is False
        assert "not found" in msg.lower() or "error" in msg.lower()


# ============================================================================
# Generate Restore Code Tests
# ============================================================================


@pytest.mark.unit
class TestGenerateRestoreCode:
    """Test restore code generation"""

    @patch("backup.check_permission")
    def test_generate_restore_code_no_permission(self, mock_check_perm):
        """Test generating code without permission"""
        mock_check_perm.return_value = False

        success, msg, code = generate_restore_code("backup_test.zip", "admin_001")

        assert success is False
        assert "access denied" in msg.lower()
        assert code is None

    @patch("backup.check_permission")
    def test_generate_restore_code_backup_not_found(self, mock_check_perm):
        """Test generating code for non-existent backup"""
        mock_check_perm.return_value = True

        # Mock the backup directory and path
        with patch("backup.BACKUP_DIR") as mock_backup_dir:
            backup_path = Mock()
            backup_path.exists.return_value = False
            mock_backup_dir.__truediv__ = Mock(return_value=backup_path)

            success, msg, code = generate_restore_code("nonexistent.zip", "admin_001")

        assert success is False
        assert "not found" in msg.lower()
        assert code is None

    @patch("backup.log_activity")
    @patch("backup.get_current_user")
    @patch("backup.get_connection")
    @patch("backup.encrypt_field")
    @patch("backup.BACKUP_DIR")
    @patch("backup.check_permission")
    def test_generate_restore_code_success(
        self,
        mock_check_perm,
        mock_backup_dir,
        mock_encrypt,
        mock_conn,
        mock_get_user,
        mock_log,
    ):
        """Test successfully generating restore code"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "super_admin"}
        mock_encrypt.side_effect = [
            "encrypted_code",
            "encrypted_backup",
            "encrypted_target",
        ]

        backup_path = Mock()
        backup_path.exists.return_value = True
        with patch.object(Path, "__truediv__", return_value=backup_path):
            mock_cursor = Mock()
            mock_conn.return_value.cursor.return_value = mock_cursor

            success, msg, code = generate_restore_code("backup_test.zip", "admin_001")

        assert success is True
        assert "generated successfully" in msg.lower()
        assert code is not None
        assert len(code) == 12
        assert code.isalnum()  # Should be alphanumeric
        # Check table creation and insert
        assert mock_cursor.execute.call_count == 2
        mock_conn.return_value.commit.assert_called_once()


# ============================================================================
# Revoke Restore Code Tests
# ============================================================================


@pytest.mark.unit
class TestRevokeRestoreCode:
    """Test restore code revocation"""

    @patch("backup.check_permission")
    def test_revoke_restore_code_no_permission(self, mock_check_perm):
        """Test revoking code without permission"""
        mock_check_perm.return_value = False

        success, msg = revoke_restore_code("ABC123")

        assert success is False
        assert "access denied" in msg.lower()

    @patch("backup.get_connection")
    @patch("backup.check_permission")
    def test_revoke_restore_code_table_not_exists(self, mock_check_perm, mock_conn):
        """Test revoking code when table doesn't exist"""
        mock_check_perm.return_value = True

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None  # Table doesn't exist
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = revoke_restore_code("ABC123")

        assert success is False
        assert "no restore codes" in msg.lower()

    @patch("backup.get_connection")
    @patch("backup.check_permission")
    def test_revoke_restore_code_no_active_codes(self, mock_check_perm, mock_conn):
        """Test revoking code when no active codes exist"""
        mock_check_perm.return_value = True

        mock_cursor = Mock()
        mock_cursor.fetchone.side_effect = [
            ("restore_codes",),  # Table exists
        ]
        mock_cursor.fetchall.return_value = []  # No active codes
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = revoke_restore_code("ABC123")

        assert success is False
        assert "no active" in msg.lower()

    @patch("backup.log_activity")
    @patch("backup.get_current_user")
    @patch("backup.decrypt_field")
    @patch("backup.get_connection")
    @patch("backup.check_permission")
    def test_revoke_restore_code_success(
        self, mock_check_perm, mock_conn, mock_decrypt, mock_get_user, mock_log
    ):
        """Test successfully revoking restore code"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "super_admin"}

        mock_cursor = Mock()
        mock_cursor.fetchone.side_effect = [
            ("restore_codes",),  # Table exists
        ]
        mock_cursor.fetchall.return_value = [
            (1, "encrypted_code", "encrypted_backup", "encrypted_target"),
        ]
        mock_decrypt.side_effect = [
            "ABC123",  # Matches the code we're looking for
            "backup_test.zip",
            "admin_001",
        ]
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = revoke_restore_code("ABC123")

        assert success is True
        assert "revoked successfully" in msg.lower()
        # Check DELETE was called
        delete_call = [
            call for call in mock_cursor.execute.call_args_list if "DELETE" in str(call)
        ]
        assert len(delete_call) == 1

    @patch("backup.decrypt_field")
    @patch("backup.get_connection")
    @patch("backup.check_permission")
    def test_revoke_restore_code_not_found(
        self, mock_check_perm, mock_conn, mock_decrypt
    ):
        """Test revoking non-existent code"""
        mock_check_perm.return_value = True

        mock_cursor = Mock()
        mock_cursor.fetchone.side_effect = [
            ("restore_codes",),  # Table exists
        ]
        mock_cursor.fetchall.return_value = [
            (1, "encrypted_code", "encrypted_backup", "encrypted_target"),
        ]
        mock_decrypt.return_value = "DIFFERENT_CODE"  # Doesn't match
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = revoke_restore_code("ABC123")

        assert success is False
        assert "not found" in msg.lower()


# ============================================================================
# List Restore Codes Tests
# ============================================================================


@pytest.mark.unit
class TestListRestoreCodes:
    """Test listing active restore codes"""

    @patch("backup.check_permission")
    def test_list_restore_codes_no_permission(self, mock_check_perm):
        """Test listing codes without permission"""
        mock_check_perm.return_value = False

        codes = list_restore_codes()

        assert codes == []

    @patch("backup.get_connection")
    @patch("backup.check_permission")
    def test_list_restore_codes_table_not_exists(self, mock_check_perm, mock_conn):
        """Test listing codes when table doesn't exist"""
        mock_check_perm.return_value = True

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None  # Table doesn't exist
        mock_conn.return_value.cursor.return_value = mock_cursor

        codes = list_restore_codes()

        assert codes == []

    @patch("backup.decrypt_field")
    @patch("backup.get_connection")
    @patch("backup.check_permission")
    def test_list_restore_codes_success(self, mock_check_perm, mock_conn, mock_decrypt):
        """Test successfully listing restore codes"""
        mock_check_perm.return_value = True

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = ("restore_codes",)  # Table exists
        mock_cursor.fetchall.return_value = [
            (
                "encrypted_code1",
                "encrypted_backup1",
                "encrypted_user1",
                "2025-01-01 10:00:00",
            ),
            (
                "encrypted_code2",
                "encrypted_backup2",
                "encrypted_user2",
                "2025-01-02 11:00:00",
            ),
        ]
        mock_decrypt.side_effect = [
            "ABC123",
            "backup1.zip",
            "admin_001",
            "DEF456",
            "backup2.zip",
            "admin_002",
        ]
        mock_conn.return_value.cursor.return_value = mock_cursor

        codes = list_restore_codes()

        assert len(codes) == 2
        assert codes[0]["code"] == "ABC123"
        assert codes[0]["backup_filename"] == "backup1.zip"
        assert codes[0]["target_username"] == "admin_001"
        assert codes[1]["code"] == "DEF456"


# ============================================================================
# Internal Helper Tests
# ============================================================================


@pytest.mark.unit
class TestValidateRestoreCode:
    """Test internal restore code validation"""

    @patch("backup.get_connection")
    def test_validate_restore_code_table_not_exists(self, mock_conn):
        """Test validating code when table doesn't exist"""
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None  # Table doesn't exist
        mock_conn.return_value.cursor.return_value = mock_cursor

        is_valid, backup_name = _validate_restore_code("ABC123")

        assert is_valid is False
        assert backup_name is None

    @patch("backup.decrypt_field")
    @patch("backup.get_connection")
    def test_validate_restore_code_success(self, mock_conn, mock_decrypt):
        """Test successfully validating restore code"""
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = ("restore_codes",)  # Table exists
        mock_cursor.fetchall.return_value = [
            ("encrypted_backup1", 0, "encrypted_code1"),
            ("encrypted_backup2", 0, "encrypted_code2"),
        ]
        mock_decrypt.side_effect = [
            "WRONG_CODE",  # First code doesn't match
            "ABC123",  # Second code matches
            "backup_test.zip",  # Return backup filename
        ]
        mock_conn.return_value.cursor.return_value = mock_cursor

        is_valid, backup_name = _validate_restore_code("ABC123")

        assert is_valid is True
        assert backup_name == "backup_test.zip"

    @patch("backup.decrypt_field")
    @patch("backup.get_connection")
    def test_validate_restore_code_not_found(self, mock_conn, mock_decrypt):
        """Test validating non-existent code"""
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = ("restore_codes",)
        mock_cursor.fetchall.return_value = [
            ("encrypted_backup", 0, "encrypted_code"),
        ]
        mock_decrypt.return_value = "DIFFERENT_CODE"
        mock_conn.return_value.cursor.return_value = mock_cursor

        is_valid, backup_name = _validate_restore_code("ABC123")

        assert is_valid is False
        assert backup_name is None


@pytest.mark.unit
class TestMarkCodeAsUsed:
    """Test marking restore code as used"""

    @patch("backup.decrypt_field")
    @patch("backup.encrypt_field")
    @patch("backup.get_connection")
    def test_mark_code_as_used_success(self, mock_conn, mock_encrypt, mock_decrypt):
        """Test successfully marking code as used"""
        mock_encrypt.return_value = "encrypted_code"
        mock_decrypt.return_value = "ABC123"
        mock_cursor = Mock()
        mock_cursor.fetchall.return_value = [(1, "encrypted_code")]
        mock_conn.return_value.cursor.return_value = mock_cursor

        _mark_code_as_used("ABC123")

        # Check UPDATE was called
        update_call = mock_cursor.execute.call_args[0]
        assert "UPDATE restore_codes" in update_call[0]
        assert "used = 1" in update_call[0]
        mock_conn.return_value.commit.assert_called_once()
