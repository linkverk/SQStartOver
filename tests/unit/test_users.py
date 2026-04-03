"""
Unit tests for users.py module.

Tests user management operations including creating, updating,
deleting users, and password management.
"""

import pytest
from unittest.mock import Mock, patch
from users import (
    create_system_admin,
    create_service_engineer,
    delete_user,
    reset_user_password,
    update_user_profile,
    list_all_users,
    _generate_temporary_password,
)


# ============================================================================
# Create System Admin Tests
# ============================================================================


@pytest.mark.unit
class TestCreateSystemAdmin:
    """Test creating system administrator accounts"""

    @patch("users.log_activity")
    @patch("users.get_connection")
    @patch("users.hash_password")
    @patch("users.encrypt_username")
    @patch("users.get_current_user")
    @patch("users.check_permission")
    def test_create_system_admin_success(
        self,
        mock_check_perm,
        mock_get_user,
        mock_encrypt,
        mock_hash,
        mock_conn,
        mock_log,
    ):
        """Test successful system admin creation"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "super_admin", "role": "super_admin"}
        mock_encrypt.return_value = "encrypted_admin"
        mock_hash.return_value = "hashed_password"

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None  # Username doesn't exist
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg, temp_pw = create_system_admin("admin_001", "John", "Doe")

        assert success is True
        assert "created successfully" in msg.lower()
        assert temp_pw is not None
        assert len(temp_pw) == 12  # Temp password length
        mock_cursor.execute.assert_any_call(
            "SELECT id FROM users WHERE username = ?", ("encrypted_admin",)
        )

    @patch("users.check_permission")
    def test_create_system_admin_no_permission(self, mock_check_perm):
        """Test creating system admin without permission"""
        mock_check_perm.return_value = False

        success, msg, temp_pw = create_system_admin("admin_001", "John", "Doe")

        assert success is False
        assert "access denied" in msg.lower()
        assert temp_pw is None

    @patch("users.get_connection")
    @patch("users.encrypt_username")
    @patch("users.get_current_user")
    @patch("users.check_permission")
    def test_create_system_admin_duplicate_username(
        self, mock_check_perm, mock_get_user, mock_encrypt, mock_conn
    ):
        """Test creating system admin with existing username"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "super_admin"}
        mock_encrypt.return_value = "encrypted_admin"

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1,)  # Username exists
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg, temp_pw = create_system_admin("admin_001", "John", "Doe")

        assert success is False
        assert "already exists" in msg.lower()
        assert temp_pw is None

    @patch("users.check_permission")
    def test_create_system_admin_invalid_username(self, mock_check_perm):
        """Test creating system admin with invalid username"""
        mock_check_perm.return_value = True

        success, msg, temp_pw = create_system_admin("bad", "John", "Doe")

        assert success is False
        assert "validation error" in msg.lower()
        assert temp_pw is None

    @patch("users.check_permission")
    def test_create_system_admin_invalid_name(self, mock_check_perm):
        """Test creating system admin with invalid name"""
        mock_check_perm.return_value = True

        success, msg, temp_pw = create_system_admin("admin_001", "", "Doe")

        assert success is False
        assert "validation error" in msg.lower()

    @patch("users.log_activity")
    @patch("users.get_connection")
    @patch("users.hash_password")
    @patch("users.encrypt_username")
    @patch("users.get_current_user")
    @patch("users.check_permission")
    def test_create_system_admin_with_password(
        self,
        mock_check_perm,
        mock_get_user,
        mock_encrypt,
        mock_hash,
        mock_conn,
        mock_log,
    ):
        """Test creating system admin with provided password"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "super_admin"}
        mock_encrypt.return_value = "encrypted_admin"
        mock_hash.return_value = "hashed_password"

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg, temp_pw = create_system_admin(
            "admin_001", "John", "Doe", "CustomPass123!"
        )

        assert success is True
        assert temp_pw is None  # No temp password when provided


# ============================================================================
# Create Service Engineer Tests
# ============================================================================


@pytest.mark.unit
class TestCreateServiceEngineer:
    """Test creating service engineer accounts"""

    @patch("users.log_activity")
    @patch("users.get_connection")
    @patch("users.hash_password")
    @patch("users.encrypt_username")
    @patch("users.get_current_user")
    @patch("users.check_permission")
    def test_create_service_engineer_success(
        self,
        mock_check_perm,
        mock_get_user,
        mock_encrypt,
        mock_hash,
        mock_conn,
        mock_log,
    ):
        """Test successful service engineer creation"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001", "role": "system_admin"}
        mock_encrypt.return_value = "encrypted_engineer"
        mock_hash.return_value = "hashed_password"

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg, temp_pw = create_service_engineer("engineer1", "Jane", "Smith")

        assert success is True
        assert "created successfully" in msg.lower()
        assert temp_pw is not None

    @patch("users.check_permission")
    def test_create_service_engineer_no_permission(self, mock_check_perm):
        """Test creating service engineer without permission"""
        mock_check_perm.return_value = False

        success, msg, temp_pw = create_service_engineer("engineer1", "Jane", "Smith")

        assert success is False
        assert "access denied" in msg.lower()
        assert temp_pw is None

    @patch("users.get_connection")
    @patch("users.encrypt_username")
    @patch("users.get_current_user")
    @patch("users.check_permission")
    def test_create_service_engineer_duplicate(
        self, mock_check_perm, mock_get_user, mock_encrypt, mock_conn
    ):
        """Test creating service engineer with existing username"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001"}
        mock_encrypt.return_value = "encrypted_engineer"

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1,)
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg, temp_pw = create_service_engineer("engineer1", "Jane", "Smith")

        assert success is False
        assert "already exists" in msg.lower()

    @patch("users.log_activity")
    @patch("users.get_connection")
    @patch("users.hash_password")
    @patch("users.encrypt_username")
    @patch("users.get_current_user")
    @patch("users.check_permission")
    def test_create_service_engineer_with_password(
        self,
        mock_check_perm,
        mock_get_user,
        mock_encrypt,
        mock_hash,
        mock_conn,
        mock_log,
    ):
        """Test creating service engineer with provided password (no temp password)"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001"}
        mock_encrypt.return_value = "encrypted_engineer"
        mock_hash.return_value = "hashed_password"

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg, temp_pw = create_service_engineer(
            "engineer1", "Jane", "Smith", "CustomPass123!"
        )

        assert success is True
        assert temp_pw is None  # No temp password when provided

    @patch("users.check_permission")
    def test_create_service_engineer_invalid_username(self, mock_check_perm):
        """Test creating service engineer with invalid username"""
        mock_check_perm.return_value = True

        success, msg, temp_pw = create_service_engineer("bad", "Jane", "Smith")

        assert success is False
        assert "validation error" in msg.lower()
        assert temp_pw is None


# ============================================================================
# Delete User Tests
# ============================================================================


@pytest.mark.unit
class TestDeleteUser:
    """Test deleting user accounts"""

    @patch("users.log_activity")
    @patch("users.get_connection")
    @patch("users.encrypt_username")
    @patch("users.check_permission")
    @patch("users.get_current_user")
    def test_delete_user_success(
        self, mock_get_user, mock_check_perm, mock_encrypt, mock_conn, mock_log
    ):
        """Test successful user deletion"""
        mock_get_user.return_value = {"username": "super_admin", "role": "super_admin"}
        mock_check_perm.return_value = True
        mock_encrypt.return_value = "encrypted_admin"

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1, "system_admin", "John", "Doe")
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = delete_user("admin_001")

        assert success is True
        assert "deleted successfully" in msg.lower()

    @patch("users.get_current_user")
    def test_delete_user_not_logged_in(self, mock_get_user):
        """Test deleting user when not logged in"""
        mock_get_user.return_value = None

        success, msg = delete_user("admin_001")

        assert success is False
        assert "logged in" in msg.lower()

    @patch("users.get_current_user")
    def test_delete_user_cannot_delete_super_admin(self, mock_get_user):
        """Test that super_admin account cannot be deleted"""
        mock_get_user.return_value = {"username": "super_admin", "role": "super_admin"}

        success, msg = delete_user("super_admin")

        assert success is False
        assert "cannot delete" in msg.lower()

    @patch("users.get_current_user")
    def test_delete_user_super_admin_cannot_delete_self(self, mock_get_user):
        """Test that Super Admin cannot delete their own account"""
        mock_get_user.return_value = {"username": "super_admin", "role": "super_admin"}

        success, msg = delete_user("super_admin")

        assert success is False
        assert "cannot delete" in msg.lower()

    @patch("users.get_current_user")
    def test_delete_user_service_engineer_cannot_delete_self(self, mock_get_user):
        """Test that Service Engineer cannot delete their own account"""
        mock_get_user.return_value = {
            "username": "engineer1",
            "role": "service_engineer",
        }

        success, msg = delete_user("engineer1")

        assert success is False
        assert "cannot delete" in msg.lower()

    @patch("users.log_activity")
    @patch("users.get_connection")
    @patch("users.encrypt_username")
    @patch("users.check_permission")
    @patch("users.get_current_user")
    def test_delete_user_system_admin_can_delete_self(
        self, mock_get_user, mock_check_perm, mock_encrypt, mock_conn, mock_log
    ):
        """Test that System Admin CAN delete their own account (assignment requirement)"""
        mock_get_user.return_value = {"username": "admin_001", "role": "system_admin"}
        mock_check_perm.return_value = True
        mock_encrypt.return_value = "encrypted_admin"

        # Mock database connection
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1, "system_admin", "John", "Doe")
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.commit = Mock()
        mock_conn.return_value.close = Mock()

        success, msg = delete_user("admin_001")

        assert success is True
        assert "deleted successfully" in msg.lower()
        mock_cursor.execute.assert_called()
        mock_conn.return_value.commit.assert_called_once()

    @patch("users.get_connection")
    @patch("users.encrypt_username")
    @patch("users.get_current_user")
    def test_delete_user_not_found(self, mock_get_user, mock_encrypt, mock_conn):
        """Test deleting non-existent user"""
        mock_get_user.return_value = {"username": "super_admin"}
        mock_encrypt.return_value = "encrypted_user"

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = delete_user("nonexist")

        assert success is False
        assert "not found" in msg.lower()

    @patch("users.get_connection")
    @patch("users.encrypt_username")
    @patch("users.check_permission")
    @patch("users.get_current_user")
    def test_delete_user_insufficient_permission(
        self, mock_get_user, mock_check_perm, mock_encrypt, mock_conn
    ):
        """Test deleting user without sufficient permission"""
        mock_get_user.return_value = {"username": "admin_001", "role": "system_admin"}
        mock_check_perm.return_value = False  # No permission to delete system admin
        mock_encrypt.return_value = "encrypted_user"

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1, "system_admin", "John", "Doe")
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = delete_user("admin_002")

        assert success is False
        assert "access denied" in msg.lower()

    @patch("users.get_current_user")
    def test_delete_user_invalid_username(self, mock_get_user):
        """Test deleting user with invalid username"""
        mock_get_user.return_value = {"username": "super_admin"}

        success, msg = delete_user("bad")  # Too short

        assert success is False
        assert "invalid username" in msg.lower()

    @patch("users.log_activity")
    @patch("users.get_connection")
    @patch("users.encrypt_username")
    @patch("users.check_permission")
    @patch("users.get_current_user")
    def test_delete_service_engineer_insufficient_permission(
        self, mock_get_user, mock_check_perm, mock_encrypt, mock_conn, mock_log
    ):
        """Test deleting service engineer without permission"""
        mock_get_user.return_value = {"username": "nonadmin", "role": "other"}
        mock_check_perm.return_value = False
        mock_encrypt.return_value = "encrypted_engineer"

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1, "service_engineer", "Jane", "Doe")
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = delete_user("engineer1")

        assert success is False
        assert "access denied" in msg.lower()


# ============================================================================
# Reset Password Tests
# ============================================================================


@pytest.mark.unit
class TestResetUserPassword:
    """Test resetting user passwords"""

    @patch("users.log_activity")
    @patch("users.get_connection")
    @patch("users.hash_password")
    @patch("users.encrypt_username")
    @patch("users.check_permission")
    @patch("users.get_current_user")
    def test_reset_password_success(
        self,
        mock_get_user,
        mock_check_perm,
        mock_encrypt,
        mock_hash,
        mock_conn,
        mock_log,
    ):
        """Test successful password reset"""
        mock_get_user.return_value = {"username": "super_admin"}
        mock_check_perm.return_value = True
        mock_encrypt.return_value = "encrypted_user"
        mock_hash.return_value = "new_hash"

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1, "system_admin")
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg, temp_pw = reset_user_password("admin_001")

        assert success is True
        assert "reset successfully" in msg.lower()
        assert temp_pw is not None
        assert len(temp_pw) == 12

    @patch("users.get_current_user")
    def test_reset_password_not_logged_in(self, mock_get_user):
        """Test resetting password when not logged in"""
        mock_get_user.return_value = None

        success, msg, temp_pw = reset_user_password("admin_001")

        assert success is False
        assert "logged in" in msg.lower()
        assert temp_pw is None

    @patch("users.get_current_user")
    def test_reset_password_cannot_reset_super_admin(self, mock_get_user):
        """Test that super_admin password cannot be reset"""
        mock_get_user.return_value = {"username": "super_admin"}

        success, msg, temp_pw = reset_user_password("super_admin")

        assert success is False
        assert "cannot reset" in msg.lower()
        assert temp_pw is None

    @patch("users.get_connection")
    @patch("users.encrypt_username")
    @patch("users.get_current_user")
    def test_reset_password_user_not_found(
        self, mock_get_user, mock_encrypt, mock_conn
    ):
        """Test resetting password for non-existent user"""
        mock_get_user.return_value = {"username": "super_admin"}
        mock_encrypt.return_value = "encrypted_user"

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg, temp_pw = reset_user_password("nonexist")

        assert success is False
        assert "not found" in msg.lower()
        assert temp_pw is None

    @patch("users.get_connection")
    @patch("users.encrypt_username")
    @patch("users.check_permission")
    @patch("users.get_current_user")
    def test_reset_password_no_permission(
        self, mock_get_user, mock_check_perm, mock_encrypt, mock_conn
    ):
        """Test resetting password without permission"""
        mock_get_user.return_value = {"username": "admin_001", "role": "system_admin"}
        mock_check_perm.return_value = False
        mock_encrypt.return_value = "encrypted_user"

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1, "system_admin")
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg, temp_pw = reset_user_password("admin_002")

        assert success is False
        assert "access denied" in msg.lower()
        assert temp_pw is None

    @patch("users.get_current_user")
    def test_reset_password_invalid_username(self, mock_get_user):
        """Test resetting password with invalid username"""
        mock_get_user.return_value = {"username": "super_admin"}

        success, msg, temp_pw = reset_user_password("bad")  # Too short

        assert success is False
        assert "invalid username" in msg.lower()
        assert temp_pw is None

    @patch("users.get_connection")
    @patch("users.encrypt_username")
    @patch("users.check_permission")
    @patch("users.get_current_user")
    def test_reset_service_engineer_password_no_permission(
        self, mock_get_user, mock_check_perm, mock_encrypt, mock_conn
    ):
        """Test resetting service engineer password without permission"""
        mock_get_user.return_value = {"username": "nonadmin", "role": "other"}
        mock_check_perm.return_value = False
        mock_encrypt.return_value = "encrypted_engineer"

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1, "service_engineer")
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg, temp_pw = reset_user_password("engineer1")

        assert success is False
        assert "access denied" in msg.lower()
        assert temp_pw is None


# ============================================================================
# Update User Profile Tests
# ============================================================================


@pytest.mark.unit
class TestUpdateUserProfile:
    """Test updating user profiles"""

    @patch("users.log_activity")
    @patch("users.get_connection")
    @patch("users.encrypt_username")
    @patch("users.check_permission")
    @patch("users.get_current_user")
    def test_update_profile_success(
        self, mock_get_user, mock_check_perm, mock_encrypt, mock_conn, mock_log
    ):
        """Test successful profile update"""
        mock_get_user.return_value = {"username": "super_admin"}
        mock_check_perm.return_value = True
        mock_encrypt.return_value = "encrypted_user"

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1, "system_admin", "John", "Doe")
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = update_user_profile("admin_001", first_name="Johnny")

        assert success is True
        assert "updated successfully" in msg.lower()

    @patch("users.get_current_user")
    def test_update_profile_not_logged_in(self, mock_get_user):
        """Test updating profile when not logged in"""
        mock_get_user.return_value = None

        success, msg = update_user_profile("admin_001", first_name="Johnny")

        assert success is False
        assert "logged in" in msg.lower()

    @patch("users.get_current_user")
    def test_update_profile_no_fields(self, mock_get_user):
        """Test updating profile with no fields specified"""
        mock_get_user.return_value = {"username": "super_admin"}

        success, msg = update_user_profile("admin_001")

        assert success is False
        assert "at least" in msg.lower()

    @patch("users.get_connection")
    @patch("users.encrypt_username")
    @patch("users.get_current_user")
    def test_update_profile_user_not_found(
        self, mock_get_user, mock_encrypt, mock_conn
    ):
        """Test updating profile for non-existent user"""
        mock_get_user.return_value = {"username": "super_admin"}
        mock_encrypt.return_value = "encrypted_user"

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = update_user_profile("nonexist", first_name="Johnny")

        assert success is False
        assert "not found" in msg.lower()

    @patch("users.get_current_user")
    def test_update_profile_invalid_name(self, mock_get_user):
        """Test updating profile with invalid name"""
        mock_get_user.return_value = {"username": "super_admin"}

        success, msg = update_user_profile("admin_001", first_name="")

        assert success is False
        assert "validation error" in msg.lower()

    @patch("users.log_activity")
    @patch("users.get_connection")
    @patch("users.encrypt_username")
    @patch("users.check_permission")
    @patch("users.get_current_user")
    def test_update_profile_multiple_fields(
        self, mock_get_user, mock_check_perm, mock_encrypt, mock_conn, mock_log
    ):
        """Test updating multiple profile fields"""
        mock_get_user.return_value = {"username": "super_admin"}
        mock_check_perm.return_value = True
        mock_encrypt.return_value = "encrypted_user"

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1, "system_admin", "John", "Doe")
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = update_user_profile(
            "admin_001", first_name="Johnny", last_name="Smith"
        )

        assert success is True
        # Should update both fields
        update_call = [
            call for call in mock_cursor.execute.call_args_list if "UPDATE" in str(call)
        ]
        assert len(update_call) == 1

    @patch("users.get_current_user")
    def test_update_profile_invalid_username(self, mock_get_user):
        """Test updating profile with invalid username"""
        mock_get_user.return_value = {"username": "super_admin"}

        success, msg = update_user_profile("bad", first_name="Johnny")

        assert success is False
        assert "invalid username" in msg.lower()

    @patch("users.get_connection")
    @patch("users.encrypt_username")
    @patch("users.check_permission")
    @patch("users.get_current_user")
    def test_update_system_admin_profile_no_permission(
        self, mock_get_user, mock_check_perm, mock_encrypt, mock_conn
    ):
        """Test updating system admin profile without permission"""
        mock_get_user.return_value = {"username": "admin_001", "role": "system_admin"}
        mock_check_perm.return_value = False
        mock_encrypt.return_value = "encrypted_user"

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1, "system_admin", "John", "Doe")
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = update_user_profile("admin_002", first_name="Johnny")

        assert success is False
        assert "access denied" in msg.lower()

    @patch("users.get_connection")
    @patch("users.encrypt_username")
    @patch("users.check_permission")
    @patch("users.get_current_user")
    def test_update_service_engineer_profile_no_permission(
        self, mock_get_user, mock_check_perm, mock_encrypt, mock_conn
    ):
        """Test updating service engineer profile without permission"""
        mock_get_user.return_value = {"username": "nonadmin", "role": "other"}
        mock_check_perm.return_value = False
        mock_encrypt.return_value = "encrypted_engineer"

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1, "service_engineer", "Jane", "Doe")
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = update_user_profile("engineer1", first_name="Janet")

        assert success is False
        assert "access denied" in msg.lower()


# ============================================================================
# List Users Tests
# ============================================================================


@pytest.mark.unit
class TestListAllUsers:
    """Test listing all users"""

    @patch("users.get_connection")
    @patch("users.decrypt_username")
    @patch("users.get_role_name")
    def test_list_all_users_success(self, mock_get_role, mock_decrypt, mock_conn):
        """Test listing all users"""
        mock_cursor = Mock()
        mock_cursor.fetchall.return_value = [
            ("encrypted_user1", "super_admin", "Super", "Admin", "2025-01-01"),
            ("encrypted_user2", "system_admin", "John", "Doe", "2025-01-02"),
        ]
        mock_conn.return_value.cursor.return_value = mock_cursor

        mock_decrypt.side_effect = ["super_admin", "admin_001"]
        mock_get_role.side_effect = ["Super Administrator", "System Administrator"]

        users = list_all_users()

        assert len(users) == 2
        assert users[0]["username"] == "super_admin"
        assert users[0]["role"] == "super_admin"
        assert users[1]["username"] == "admin_001"
        assert users[1]["role"] == "system_admin"

    @patch("users.get_connection")
    def test_list_all_users_empty(self, mock_conn):
        """Test listing users when database is empty"""
        mock_cursor = Mock()
        mock_cursor.fetchall.return_value = []
        mock_conn.return_value.cursor.return_value = mock_cursor

        users = list_all_users()

        assert users == []


# ============================================================================
# Temporary Password Generation Tests
# ============================================================================


@pytest.mark.unit
class TestGenerateTemporaryPassword:
    """Test temporary password generation"""

    def test_generate_temporary_password_length(self):
        """Test that temporary password has correct length"""
        temp_pw = _generate_temporary_password()

        assert len(temp_pw) == 12

    def test_generate_temporary_password_has_uppercase(self):
        """Test that temporary password contains uppercase letter"""
        temp_pw = _generate_temporary_password()

        assert any(c.isupper() for c in temp_pw)

    def test_generate_temporary_password_has_lowercase(self):
        """Test that temporary password contains lowercase letter"""
        temp_pw = _generate_temporary_password()

        assert any(c.islower() for c in temp_pw)

    def test_generate_temporary_password_has_digit(self):
        """Test that temporary password contains digit"""
        temp_pw = _generate_temporary_password()

        assert any(c.isdigit() for c in temp_pw)

    def test_generate_temporary_password_has_special(self):
        """Test that temporary password contains special character"""
        temp_pw = _generate_temporary_password()
        special_chars = "~!@#$%&_-+="

        assert any(c in special_chars for c in temp_pw)

    def test_generate_temporary_password_unique(self):
        """Test that generated passwords are unique"""
        passwords = [_generate_temporary_password() for _ in range(10)]

        # All should be unique
        assert len(set(passwords)) == 10
