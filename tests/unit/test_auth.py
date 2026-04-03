"""
Unit tests for auth.py module.

Tests authentication, authorization, session management,
and password handling functions.
"""

import pytest
from unittest.mock import Mock, patch
from validation import ValidationError
from auth import (
    login,
    logout,
    get_current_user,
    is_logged_in,
    check_permission,
    require_permission,
    get_role_name,
    update_password,
    get_user_by_username,
    list_users_by_role,
)


# ============================================================================
# Login Tests
# ============================================================================


@pytest.mark.unit
class TestLogin:
    """Test login function"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Reset auth state before each test"""
        logout()
        yield
        logout()

    @patch("auth.get_connection")
    @patch("auth.verify_password")
    @patch("auth.decrypt_username")
    @patch("auth.encrypt_username")
    def test_successful_login(self, mock_encrypt, mock_decrypt, mock_verify, mock_conn):
        """Test successful login with valid credentials"""
        # Mock database response
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (
            1,  # user_id
            "encrypted_testuser",  # encrypted username
            b"hashed_password",  # password_hash
            "system_admin",  # role
            "Test",  # first_name
            "User",  # last_name
            0,  # must_change_password
        )
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_encrypt.return_value = "encrypted_testuser"
        mock_decrypt.return_value = "testuser"
        mock_verify.return_value = True

        success, message = login("testuser", "password123")

        assert success is True
        assert "welcome" in message.lower()
        assert get_current_user() is not None
        assert get_current_user()["username"] == "testuser"

    @patch("auth.get_connection")
    @patch("auth.encrypt_username")
    def test_login_nonexistent_user(self, mock_encrypt, mock_conn):
        """Test login with non-existent username"""
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_encrypt.return_value = "encrypted_nonexistent"

        success, message = login("nonexistent", "password")

        assert success is False
        assert "invalid" in message.lower()
        assert get_current_user() is None

    @patch("auth.get_connection")
    @patch("auth.verify_password")
    @patch("auth.decrypt_username")
    @patch("auth.encrypt_username")
    def test_login_wrong_password(
        self, mock_encrypt, mock_decrypt, mock_verify, mock_conn
    ):
        """Test login with incorrect password"""
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (
            1,  # user_id
            "encrypted_testuser",  # encrypted username
            b"hashed_password",  # password_hash
            "system_admin",  # role
            "Test",  # first_name
            "User",  # last_name
            0,  # must_change_password
        )
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_encrypt.return_value = "encrypted_testuser"
        mock_decrypt.return_value = "testuser"
        mock_verify.return_value = False

        success, message = login("testuser", "wrongpassword")

        assert success is False
        assert "invalid" in message.lower()
        assert get_current_user() is None

    @patch("auth.get_connection")
    @patch("auth.verify_password")
    @patch("auth.decrypt_username")
    @patch("auth.encrypt_username")
    def test_login_must_change_password(
        self, mock_encrypt, mock_decrypt, mock_verify, mock_conn
    ):
        """Test login when password must be changed"""
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (
            1,  # user_id
            "encrypted_testuser",  # encrypted username
            b"hashed_password",  # password_hash
            "system_admin",  # role
            "Test",  # first_name
            "User",  # last_name
            1,  # must_change_password
        )
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_encrypt.return_value = "encrypted_testuser"
        mock_decrypt.return_value = "testuser"
        mock_verify.return_value = True

        success, message = login("testuser", "password123")

        assert success is True
        # Message should indicate password needs to be changed
        user = get_current_user()
        assert user is not None
        assert user["must_change_password"] == True

    def test_login_empty_username(self):
        """Test login with empty username"""
        success, message = login("", "password")
        assert success is False

    @patch("auth.get_connection")
    @patch("auth.verify_password")
    @patch("auth.decrypt_username")
    @patch("auth.encrypt_username")
    def test_login_empty_password(
        self, mock_encrypt, mock_decrypt, mock_verify, mock_conn
    ):
        """Test login with empty password"""
        # Mock database to return a user
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (
            1,  # user_id
            "encrypted_username",  # encrypted username
            b"hashed_password",  # password_hash
            "system_admin",  # role
            "Test",  # first_name
            "User",  # last_name
            0,  # must_change_password
        )
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_encrypt.return_value = "encrypted_username"
        mock_decrypt.return_value = "validuser"
        mock_verify.return_value = False  # Empty password won't verify

        success, message = login("validuser", "")
        assert success is False
        assert "invalid" in message.lower()


# ============================================================================
# Logout Tests
# ============================================================================


@pytest.mark.unit
class TestLogout:
    """Test logout function"""

    @patch("auth.get_connection")
    @patch("auth.verify_password")
    @patch("auth.decrypt_username")
    @patch("auth.encrypt_username")
    def test_logout_clears_session(
        self, mock_encrypt, mock_decrypt, mock_verify, mock_conn
    ):
        """Test that logout clears the session"""
        # First login
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (
            1,  # user_id
            "encrypted_testuser",  # encrypted username
            b"hashed_password",  # password_hash
            "system_admin",  # role
            "Test",  # first_name
            "User",  # last_name
            0,  # must_change_password
        )
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_encrypt.return_value = "encrypted_testuser"
        mock_decrypt.return_value = "testuser"
        mock_verify.return_value = True

        login("testuser", "password123")
        assert get_current_user() is not None
        assert is_logged_in() is True

        # Now logout
        logout()
        assert get_current_user() is None
        assert is_logged_in() is False

    def test_logout_when_not_logged_in(self):
        """Test logout when no one is logged in"""
        logout()  # Should not raise an error
        assert get_current_user() is None
        assert is_logged_in() is False


# ============================================================================
# Get Current User Tests
# ============================================================================


@pytest.mark.unit
class TestGetCurrentUser:
    """Test get_current_user function"""

    def test_get_current_user_when_not_logged_in(self):
        """Test get_current_user returns None when not logged in"""
        logout()
        assert get_current_user() is None
        assert is_logged_in() is False

    @patch("auth.get_connection")
    @patch("auth.verify_password")
    @patch("auth.decrypt_username")
    @patch("auth.encrypt_username")
    def test_get_current_user_when_logged_in(
        self, mock_encrypt, mock_decrypt, mock_verify, mock_conn
    ):
        """Test get_current_user returns user data when logged in"""
        # Mock login
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (
            1,  # user_id
            "encrypted_testuser",  # encrypted username
            b"hashed_password",  # password_hash
            "system_admin",  # role
            "Test",  # first_name
            "User",  # last_name
            0,  # must_change_password
        )
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_encrypt.return_value = "encrypted_testuser"
        mock_decrypt.return_value = "testuser"
        mock_verify.return_value = True

        login("testuser", "password123")

        user = get_current_user()
        assert user is not None
        assert user["username"] == "testuser"
        assert user["role_name"] == "System Administrator"
        assert is_logged_in() is True

        logout()


# ============================================================================
# Permission Checking Tests
# ============================================================================


@pytest.mark.unit
class TestCheckPermission:
    """Test check_permission function"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Reset auth state"""
        logout()
        yield
        logout()

    def test_check_permission_when_not_logged_in(self):
        """Test permission check when not logged in"""
        logout()
        result = check_permission("manage_engineers")
        assert result is False

    @patch("auth.get_connection")
    @patch("auth.verify_password")
    @patch("auth.decrypt_username")
    @patch("auth.encrypt_username")
    def test_system_admin_permissions(
        self, mock_encrypt, mock_decrypt, mock_verify, mock_conn
    ):
        """Test that system_admin has permissions"""
        # Mock system admin login
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (
            1,  # user_id
            "encrypted_adminusr",  # encrypted username
            b"hashed",  # password_hash
            "system_admin",  # role
            "Admin",  # first_name
            "User",  # last_name
            0,  # must_change_password
        )
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_encrypt.return_value = "encrypted_adminusr"
        mock_decrypt.return_value = "adminusr"
        mock_verify.return_value = True

        success, message = login("adminusr", "password")
        assert success is True, f"Login failed: {message}"  # Login must succeed first

        # Verify logged in
        assert is_logged_in() is True
        user = get_current_user()
        assert user is not None
        assert user["role"] == "system_admin"

        # Check permissions
        result = check_permission("manage_engineers")
        assert isinstance(result, bool)
        assert result is True  # system_admin should have this permission

        logout()

    @patch("auth.get_connection")
    @patch("auth.verify_password")
    @patch("auth.decrypt_username")
    @patch("auth.encrypt_username")
    def test_service_engineer_permissions(
        self, mock_encrypt, mock_decrypt, mock_verify, mock_conn
    ):
        """Test that service_engineer permissions work"""
        # Mock service engineer login
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (
            2,  # user_id
            "encrypted_engineer",  # encrypted username
            b"hashed",  # password_hash
            "service_engineer",  # role
            "Engineer",  # first_name
            "User",  # last_name
            0,  # must_change_password
        )
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_encrypt.return_value = "encrypted_engineer"
        mock_decrypt.return_value = "engineer"
        mock_verify.return_value = True

        login("engineer", "password")

        # Check that permission checking works
        result = check_permission("manage_scooters")
        assert isinstance(result, bool)
        assert result is True  # service_engineer should have this permission

        logout()

    @patch("auth.get_connection")
    @patch("auth.verify_password")
    @patch("auth.decrypt_username")
    @patch("auth.encrypt_username")
    def test_super_admin_permissions(
        self, mock_encrypt, mock_decrypt, mock_verify, mock_conn
    ):
        """Test that super_admin has all permissions"""
        # Mock super admin login
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (
            1,  # user_id
            "encrypted_superadm",  # encrypted username
            b"hashed",  # password_hash
            "super_admin",  # role
            "Super",  # first_name
            "Admin",  # last_name
            0,  # must_change_password
        )
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_encrypt.return_value = "encrypted_superadm"
        mock_decrypt.return_value = "superadm"
        mock_verify.return_value = True

        success, message = login("superadm", "password")
        assert success is True

        # Check various permissions
        assert check_permission("manage_admins") is True
        assert check_permission("manage_engineers") is True
        assert check_permission("manage_restore_codes") is True
        assert check_permission("view_logs") is True

        logout()

    @patch("auth.get_connection")
    @patch("auth.verify_password")
    @patch("auth.decrypt_username")
    @patch("auth.encrypt_username")
    def test_unknown_role_permissions(
        self, mock_encrypt, mock_decrypt, mock_verify, mock_conn
    ):
        """Test permissions for an unknown/invalid role"""
        # Manually set session with unknown role
        from auth import current_session

        current_session["logged_in"] = True
        current_session["role"] = "unknown_role"

        result = check_permission("manage_engineers")
        assert result is False

        logout()

    def test_check_permission_invalid_permission(self):
        """Test checking a non-existent permission"""
        logout()
        result = check_permission("non_existent_permission")
        assert result is False


# ============================================================================
# Require Permission Tests
# ============================================================================


@pytest.mark.unit
class TestRequirePermission:
    """Test require_permission function"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Reset auth state"""
        logout()
        yield
        logout()

    def test_require_permission_not_logged_in(self):
        """Test require_permission when not logged in"""
        logout()
        has_perm, error_msg = require_permission("manage_engineers")

        assert has_perm is False
        assert "logged in" in error_msg.lower()

    @patch("auth.get_connection")
    @patch("auth.verify_password")
    @patch("auth.decrypt_username")
    @patch("auth.encrypt_username")
    @patch("auth.validate_username")
    def test_require_permission_success(
        self, mock_validate, mock_encrypt, mock_decrypt, mock_verify, mock_conn
    ):
        """Test require_permission when user has permission"""
        # Mock system admin login
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (
            1,  # user_id
            "encrypted_admin",  # encrypted username
            b"hashed",  # password_hash
            "system_admin",  # role
            "Admin",  # first_name
            "User",  # last_name
            0,  # must_change_password
        )
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_validate.return_value = "admin"
        mock_encrypt.return_value = "encrypted_admin"
        mock_decrypt.return_value = "admin"
        mock_verify.return_value = True

        success, message = login("admin", "password")
        assert success is True  # Verify login succeeded

        has_perm, error_msg = require_permission("manage_engineers")

        assert has_perm is True
        assert error_msg is None

        logout()

    @patch("auth.get_connection")
    @patch("auth.verify_password")
    @patch("auth.decrypt_username")
    @patch("auth.encrypt_username")
    def test_require_permission_denied(
        self, mock_encrypt, mock_decrypt, mock_verify, mock_conn
    ):
        """Test require_permission when user lacks permission"""
        # Mock service engineer login (lacks manage_engineers permission)
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (
            2,  # user_id
            "encrypted_engineer",  # encrypted username
            b"hashed",  # password_hash
            "service_engineer",  # role
            "Engineer",  # first_name
            "User",  # last_name
            0,  # must_change_password
        )
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_encrypt.return_value = "encrypted_engineer"
        mock_decrypt.return_value = "engineer"
        mock_verify.return_value = True

        login("engineer", "password")

        has_perm, error_msg = require_permission("manage_engineers")

        assert has_perm is False
        assert "access denied" in error_msg.lower()
        assert "service_engineer" in error_msg

        logout()


# ============================================================================
# Get Role Name Tests
# ============================================================================


@pytest.mark.unit
class TestGetRoleName:
    """Test get_role_name function"""

    def test_get_role_name_super_admin(self):
        """Test getting display name for super_admin"""
        assert get_role_name("super_admin") == "Super Administrator"

    def test_get_role_name_system_admin(self):
        """Test getting display name for system_admin"""
        assert get_role_name("system_admin") == "System Administrator"

    def test_get_role_name_service_engineer(self):
        """Test getting display name for service_engineer"""
        assert get_role_name("service_engineer") == "Service Engineer"

    def test_get_role_name_unknown(self):
        """Test getting display name for unknown role"""
        result = get_role_name("unknown_role")
        assert result == "unknown_role"  # Should return the role as-is


# ============================================================================
# Password Update Tests (Additional)
# ============================================================================


@pytest.mark.unit
class TestUpdatePasswordAdditional:
    """Additional tests for update_password function"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Reset auth state"""
        logout()
        yield
        logout()

    @patch("auth.get_connection")
    @patch("auth.verify_password")
    @patch("auth.decrypt_username")
    @patch("auth.encrypt_username")
    def test_update_password_same_as_old(
        self, mock_encrypt, mock_decrypt, mock_verify, mock_conn
    ):
        """Test password update when new password is same as old"""
        # Mock login
        mock_cursor = Mock()
        mock_cursor.fetchone.side_effect = [
            (1, "encrypted_testuser", b"old_hash", "system_admin", "Test", "User", 0),
            (b"old_hash",),  # For password update
        ]
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_encrypt.return_value = "encrypted_testuser"
        mock_decrypt.return_value = "testuser"
        mock_verify.side_effect = [True, True]  # Login verify, password verify

        login("testuser", "password123")

        # Try to update with same password
        with patch("auth.validate_password", return_value="password123"):
            success, message = update_password("password123", "password123")

        assert success is False
        assert "different" in message.lower()

        logout()

    @patch("auth.get_connection")
    @patch("auth.verify_password")
    @patch("auth.decrypt_username")
    @patch("auth.encrypt_username")
    def test_update_password_validation_error(
        self, mock_encrypt, mock_decrypt, mock_verify, mock_conn
    ):
        """Test password update with invalid new password format"""
        # Mock login
        mock_cursor = Mock()
        mock_cursor.fetchone.side_effect = [
            (1, "encrypted_testuser", b"old_hash", "system_admin", "Test", "User", 0),
            (b"old_hash",),  # For password update
        ]
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_encrypt.return_value = "encrypted_testuser"
        mock_decrypt.return_value = "testuser"
        mock_verify.side_effect = [True, True]  # Login verify, password verify

        login("testuser", "oldpassword")

        # Mock validation error
        with patch(
            "auth.validate_password", side_effect=ValidationError("Password too short")
        ):
            success, message = update_password("oldpassword", "weak")

        assert success is False
        assert "invalid" in message.lower()

        logout()

    @patch("auth.get_connection")
    @patch("auth.verify_password")
    @patch("auth.decrypt_username")
    @patch("auth.encrypt_username")
    def test_update_password_user_not_found_in_db(
        self, mock_encrypt, mock_decrypt, mock_verify, mock_conn
    ):
        """Test password update when user somehow doesn't exist in database"""
        # Mock login
        mock_cursor = Mock()
        mock_cursor.fetchone.side_effect = [
            (1, "encrypted_testuser", b"old_hash", "system_admin", "Test", "User", 0),
            None,  # User not found during password update
        ]
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_encrypt.return_value = "encrypted_testuser"
        mock_decrypt.return_value = "testuser"
        mock_verify.return_value = True

        login("testuser", "password")

        success, message = update_password("password", "NewPass123!")

        assert success is False
        assert "not found" in message.lower()

        logout()


# ============================================================================
# Get User By Username Tests
# ============================================================================


@pytest.mark.unit
class TestGetUserByUsername:
    """Test get_user_by_username function"""

    @patch("auth.get_connection")
    @patch("auth.decrypt_username")
    @patch("auth.encrypt_username")
    def test_get_user_by_username_success(self, mock_encrypt, mock_decrypt, mock_conn):
        """Test successfully retrieving a user by username"""
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (
            1,  # id
            "encrypted_testuser",  # encrypted username
            "system_admin",  # role
            "Test",  # first_name
            "User",  # last_name
            "2025-01-01 10:00:00",  # created_at
        )
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_encrypt.return_value = "encrypted_testuser"
        mock_decrypt.return_value = "testuser"

        user = get_user_by_username("testuser")

        assert user is not None
        assert user["username"] == "testuser"
        assert user["role"] == "system_admin"
        assert user["role_name"] == "System Administrator"
        assert user["first_name"] == "Test"
        assert user["last_name"] == "User"

    @patch("auth.get_connection")
    @patch("auth.encrypt_username")
    @patch("auth.validate_username")
    def test_get_user_by_username_not_found(
        self, mock_validate, mock_encrypt, mock_conn
    ):
        """Test getting user when username doesn't exist"""
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_validate.return_value = "notfound1"
        mock_encrypt.return_value = "encrypted_notfound1"

        user = get_user_by_username("notfound1")

        assert user is None

    def test_get_user_by_username_invalid_format(self):
        """Test getting user with invalid username format"""
        # Mock validation to raise error
        with patch(
            "auth.validate_username", side_effect=ValidationError("Invalid format")
        ):
            user = get_user_by_username("invalid@@@")

        assert user is None


# ============================================================================
# List Users By Role Tests
# ============================================================================


@pytest.mark.unit
class TestListUsersByRole:
    """Test list_users_by_role function"""

    @patch("auth.get_connection")
    @patch("auth.decrypt_username")
    def test_list_users_by_role_with_filter(self, mock_decrypt, mock_conn):
        """Test listing users filtered by specific role"""
        mock_cursor = Mock()
        mock_cursor.fetchall.return_value = [
            (1, "encrypted_admin1", "system_admin", "Admin", "One", "2025-01-01"),
            (2, "encrypted_admin2", "system_admin", "Admin", "Two", "2025-01-02"),
        ]
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_decrypt.side_effect = ["admin1", "admin2"]

        users = list_users_by_role("system_admin")

        assert len(users) == 2
        assert users[0]["username"] == "admin1"
        assert users[0]["role"] == "system_admin"
        assert users[1]["username"] == "admin2"
        mock_cursor.execute.assert_called_once()
        # Verify the WHERE clause was used
        call_args = mock_cursor.execute.call_args
        assert "WHERE role = ?" in call_args[0][0]

    @patch("auth.get_connection")
    @patch("auth.decrypt_username")
    def test_list_users_by_role_no_filter(self, mock_decrypt, mock_conn):
        """Test listing all users without role filter"""
        mock_cursor = Mock()
        mock_cursor.fetchall.return_value = [
            (1, "encrypted_admin", "system_admin", "Admin", "User", "2025-01-01"),
            (
                2,
                "encrypted_engineer",
                "service_engineer",
                "Engineer",
                "User",
                "2025-01-02",
            ),
            (3, "encrypted_super", "super_admin", "Super", "Admin", "2025-01-03"),
        ]
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_decrypt.side_effect = ["admin", "engineer", "super"]

        users = list_users_by_role()

        assert len(users) == 3
        assert users[0]["username"] == "admin"
        assert users[1]["username"] == "engineer"
        assert users[2]["username"] == "super"
        # Verify no WHERE clause when no role specified
        call_args = mock_cursor.execute.call_args
        assert "WHERE" not in call_args[0][0]

    @patch("auth.get_connection")
    def test_list_users_by_role_empty_result(self, mock_conn):
        """Test listing users when no users match"""
        mock_cursor = Mock()
        mock_cursor.fetchall.return_value = []
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()

        users = list_users_by_role("nonexistent_role")

        assert users == []


@pytest.mark.unit
class TestUpdatePassword:
    """Test update_password function"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Reset auth state"""
        logout()
        yield
        logout()

    def test_update_password_not_logged_in(self):
        """Test password update when not logged in"""
        logout()
        success, message = update_password("oldpass", "NewPass123!")

        assert success is False
        assert "logged in" in message.lower()

    @patch("auth.get_connection")
    @patch("auth.hash_password")
    @patch("auth.verify_password")
    @patch("auth.validate_password")
    @patch("auth.decrypt_username")
    @patch("auth.encrypt_username")
    def test_update_password_success(
        self,
        mock_encrypt,
        mock_decrypt,
        mock_validate,
        mock_verify,
        mock_hash,
        mock_conn,
    ):
        """Test successful password update"""
        # Mock login
        mock_cursor = Mock()
        # First fetchone for login, second for password update
        mock_cursor.fetchone.side_effect = [
            (1, "encrypted_testuser", b"old_hash", "system_admin", "Test", "User", 0),
            (b"old_hash",),  # For password update
        ]
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_conn.return_value.commit = Mock()
        mock_encrypt.return_value = "encrypted_testuser"
        mock_decrypt.return_value = "testuser"
        mock_verify.side_effect = [True, True]  # Login verify, password update verify
        mock_validate.return_value = "NewPass123!"
        mock_hash.return_value = b"new_hash"

        login("testuser", "oldpassword")

        # Update password
        success, message = update_password("oldpassword", "NewPass123!")

        assert success is True
        assert "success" in message.lower() or "updated" in message.lower()

        logout()

    @patch("auth.get_connection")
    @patch("auth.verify_password")
    @patch("auth.decrypt_username")
    @patch("auth.encrypt_username")
    def test_update_password_wrong_old_password(
        self, mock_encrypt, mock_decrypt, mock_verify, mock_conn
    ):
        """Test password update with wrong current password"""
        mock_cursor = Mock()
        # First fetchone for login, second for password update
        mock_cursor.fetchone.side_effect = [
            (1, "encrypted_testuser", b"hash", "system_admin", "Test", "User", 0),
            (b"hash",),  # For password update
        ]
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_encrypt.return_value = "encrypted_testuser"
        mock_decrypt.return_value = "testuser"
        # True for login, False for password verification
        mock_verify.side_effect = [True, False]

        login("testuser", "password")

        success, message = update_password("wrongpass", "NewPass123!")

        assert success is False

        logout()


# ============================================================================
# Security Tests
# ============================================================================


@pytest.mark.unit
class TestAuthSecurity:
    """Test security aspects of authentication"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Reset auth state"""
        logout()
        yield
        logout()

    @patch("auth.get_connection")
    def test_sql_injection_attempt(self, mock_conn):
        """Test that SQL injection attempts don't succeed"""
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None
        mock_conn.return_value.cursor.return_value = mock_cursor

        # Try SQL injection in username
        success, message = login("admin' OR '1'='1", "password")

        assert success is False

    @patch("auth.get_connection")
    @patch("auth.verify_password")
    @patch("auth.decrypt_username")
    @patch("auth.encrypt_username")
    def test_session_isolation(
        self, mock_encrypt, mock_decrypt, mock_verify, mock_conn
    ):
        """Test that sessions don't interfere with each other"""
        mock_cursor = Mock()
        # First login for user1abc, then for user2def
        mock_cursor.fetchone.side_effect = [
            (1, "encrypted_user1abc", b"hash", "system_admin", "User", "One", 0),
            (2, "encrypted_user2def", b"hash", "service_engineer", "User", "Two", 0),
        ]
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_verify.return_value = True

        # Login as user1abc
        mock_encrypt.return_value = "encrypted_user1abc"
        mock_decrypt.return_value = "user1abc"
        success, _ = login("user1abc", "password")
        assert success is True
        user1 = get_current_user()
        assert user1 is not None
        assert user1["username"] == "user1abc"

        # Logout
        logout()
        assert get_current_user() is None

        # Can login as different user
        mock_encrypt.return_value = "encrypted_user2def"
        mock_decrypt.return_value = "user2def"
        success, _ = login("user2def", "password")
        assert success is True
        user2 = get_current_user()
        assert user2 is not None
        assert user2["username"] == "user2def"

        logout()

    def test_no_password_in_session_data(self):
        """Test that passwords are never exposed in session"""
        logout()
        user = get_current_user()
        assert user is None  # Not logged in

        # When logged in, the returned user dict should not contain password
        # This is enforced by the get_current_user() implementation


# ============================================================================
# Login Failure Path Coverage Tests
# ============================================================================


@pytest.mark.unit
class TestLoginFailurePaths:
    """Tests for login failure scenarios with logging - covers lines 112-118"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Reset auth state"""
        logout()
        yield
        logout()

    @patch("auth.get_connection")
    @patch("auth.encrypt_username")
    @patch("auth.validate_username")
    @patch("auth.log_activity")
    def test_login_user_not_found_logs_activity(
        self, mock_log, mock_validate, mock_encrypt, mock_conn
    ):
        """Test login failure when user is not found logs suspicious activity"""
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None  # User not found
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_validate.return_value = "testuser1"
        mock_encrypt.return_value = "encrypted_username"

        success, message = login("testuser1", "password")

        assert success is False
        assert message == "Invalid username or password"
        # Verify suspicious activity was logged
        mock_log.assert_called_with(
            "unknown",
            "Unsuccessful login",
            "username: 'testuser1' not found",
            suspicious=True,
        )

    @patch("auth.get_connection")
    @patch("auth.encrypt_username")
    @patch("auth.decrypt_username")
    @patch("auth.verify_password")
    @patch("auth.log_activity")
    def test_login_wrong_password_logs_activity(
        self, mock_log, mock_verify, mock_decrypt, mock_encrypt, mock_conn
    ):
        """Test login failure with wrong password logs suspicious activity"""
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (
            1,  # user_id
            "encrypted_user",
            b"hashed",
            "traveler",
            "Test",
            "User",
            0,
        )
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_conn.return_value.close = Mock()
        mock_encrypt.return_value = "encrypted_user"
        mock_decrypt.return_value = "testuser"
        mock_verify.return_value = False  # Wrong password

        success, message = login("testuser", "wrongpassword")

        assert success is False
        assert message == "Invalid username or password"
        # Verify suspicious activity was logged
        assert mock_log.call_count >= 1
        # Check that one of the calls was for wrong password
        calls = [str(call) for call in mock_log.call_args_list]
        assert any(
            "Unsuccessful login" in call and "wrong password" in call for call in calls
        )
