"""
Unit tests for travelers.py module.

Tests traveler/customer management operations including CRUD operations,
search functionality, and data encryption.
"""

import pytest
from unittest.mock import Mock, patch
from travelers import (
    add_traveler,
    update_traveler,
    delete_traveler,
    search_travelers,
    get_traveler_by_id,
    list_all_travelers,
    _generate_unique_customer_id,
)


# ============================================================================
# Generate Unique Customer ID Tests
# ============================================================================


@pytest.mark.unit
class TestGenerateUniqueCustomerId:
    """Test unique customer ID generation"""

    @patch("travelers.get_connection")
    def test_generate_unique_customer_id_success(self, mock_conn):
        """Test successfully generating unique customer ID"""
        mock_cursor = Mock()
        # First ID check returns None (ID is unique)
        mock_cursor.fetchone.return_value = None
        mock_conn.return_value.cursor.return_value = mock_cursor

        customer_id = _generate_unique_customer_id()

        assert customer_id is not None
        assert len(customer_id) == 10
        assert customer_id.isdigit()
        mock_cursor.execute.assert_called_once()

    @patch("travelers.uuid.uuid4")
    @patch("travelers.get_connection")
    def test_generate_unique_customer_id_collision_retry(self, mock_conn, mock_uuid):
        """Test ID generation retries on collision"""
        # Mock UUID to generate predictable IDs
        mock_uuid_obj = Mock()
        mock_uuid_obj.int = 12345678901234567890
        mock_uuid.return_value = mock_uuid_obj

        mock_cursor = Mock()
        # First call: ID exists (collision)
        # Second call: ID is unique
        mock_cursor.fetchone.side_effect = [
            ("1234567890",),  # Collision - ID exists
            None,  # Success - ID is unique
        ]
        mock_conn.return_value.cursor.return_value = mock_cursor

        customer_id = _generate_unique_customer_id()

        assert customer_id is not None
        assert len(customer_id) == 10
        # Should have tried twice due to collision
        assert mock_cursor.execute.call_count == 2

    @patch("travelers.uuid.uuid4")
    @patch("travelers.get_connection")
    def test_generate_unique_customer_id_max_attempts_exceeded(
        self, mock_conn, mock_uuid
    ):
        """Test ID generation fails after max attempts"""
        # Mock UUID to generate predictable IDs
        mock_uuid_obj = Mock()
        mock_uuid_obj.int = 12345678901234567890
        mock_uuid.return_value = mock_uuid_obj

        mock_cursor = Mock()
        # Always return existing ID (simulate constant collision)
        mock_cursor.fetchone.return_value = ("1234567890",)
        mock_conn.return_value.cursor.return_value = mock_cursor

        with pytest.raises(RuntimeError) as exc_info:
            _generate_unique_customer_id()

        assert "Failed to generate unique customer ID" in str(exc_info.value)
        # Should have tried 10 times
        assert mock_cursor.execute.call_count == 10


# ============================================================================
# Add Traveler Tests
# ============================================================================


@pytest.mark.unit
class TestAddTraveler:
    """Test adding new travelers"""

    @patch("travelers.log_activity")
    @patch("travelers._generate_unique_customer_id")
    @patch("travelers.get_connection")
    @patch("travelers.encrypt_field")
    @patch("travelers.get_current_user")
    @patch("travelers.check_permission")
    def test_add_traveler_success(
        self,
        mock_check_perm,
        mock_get_user,
        mock_encrypt,
        mock_conn,
        mock_gen_id,
        mock_log,
    ):
        """Test successfully adding a traveler"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001"}
        mock_encrypt.side_effect = [
            "encrypted_email",
            "encrypted_phone",
            "encrypted_license",
            "encrypted_street",
            "encrypted_house",
            "encrypted_zip",
            "encrypted_city",
        ]
        mock_gen_id.return_value = "1234567890"

        mock_cursor = Mock()
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg, customer_id = add_traveler(
            "John",
            "Doe",
            "15-03-1990",
            "Male",
            "Main Street",
            "42",
            "1234AB",
            "Amsterdam",
            "john@example.com",
            "12345678",
            "AB1234567",
        )

        assert success is True
        assert "added successfully" in msg.lower()
        assert customer_id == "1234567890"
        assert len(customer_id) == 10
        mock_gen_id.assert_called_once()
        mock_cursor.execute.assert_called_once()
        mock_conn.return_value.commit.assert_called_once()

    @patch("travelers.check_permission")
    def test_add_traveler_no_permission(self, mock_check_perm):
        """Test adding traveler without permission"""
        mock_check_perm.return_value = False

        success, msg, customer_id = add_traveler(
            "John",
            "Doe",
            "15-03-1990",
            "Male",
            "Main Street",
            "42",
            "1234AB",
            "Amsterdam",
            "john@example.com",
            "12345678",
            "AB1234567",
        )

        assert success is False
        assert "access denied" in msg.lower()
        assert customer_id is None

    @patch("travelers.check_permission")
    def test_add_traveler_invalid_first_name(self, mock_check_perm):
        """Test adding traveler with invalid first name"""
        mock_check_perm.return_value = True

        success, msg, customer_id = add_traveler(
            "",
            "Doe",
            "15-03-1990",
            "Male",
            "Main Street",
            "42",
            "1234AB",
            "Amsterdam",
            "john@example.com",
            "12345678",
            "AB1234567",
        )

        assert success is False
        assert "validation error" in msg.lower()
        assert customer_id is None

    @patch("travelers.check_permission")
    def test_add_traveler_invalid_email(self, mock_check_perm):
        """Test adding traveler with invalid email"""
        mock_check_perm.return_value = True

        success, msg, customer_id = add_traveler(
            "John",
            "Doe",
            "15-03-1990",
            "Male",
            "Main Street",
            "42",
            "1234AB",
            "Amsterdam",
            "invalid_email",
            "12345678",
            "AB1234567",
        )

        assert success is False
        assert "validation error" in msg.lower()
        assert customer_id is None

    @patch("travelers.check_permission")
    def test_add_traveler_invalid_phone(self, mock_check_perm):
        """Test adding traveler with invalid phone"""
        mock_check_perm.return_value = True

        success, msg, customer_id = add_traveler(
            "John",
            "Doe",
            "15-03-1990",
            "Male",
            "Main Street",
            "42",
            "1234AB",
            "Amsterdam",
            "john@example.com",
            "123",
            "AB1234567",  # Too short
        )

        assert success is False
        assert "validation error" in msg.lower()

    @patch("travelers.check_permission")
    def test_add_traveler_invalid_zipcode(self, mock_check_perm):
        """Test adding traveler with invalid zipcode"""
        mock_check_perm.return_value = True

        success, msg, customer_id = add_traveler(
            "John",
            "Doe",
            "15-03-1990",
            "Male",
            "Main Street",
            "42",
            "INVALID",
            "Amsterdam",
            "john@example.com",
            "12345678",
            "AB1234567",
        )

        assert success is False
        assert "validation error" in msg.lower()

    @patch("travelers.check_permission")
    def test_add_traveler_invalid_license(self, mock_check_perm):
        """Test adding traveler with invalid driving license"""
        mock_check_perm.return_value = True

        success, msg, customer_id = add_traveler(
            "John",
            "Doe",
            "15-03-1990",
            "Male",
            "Main Street",
            "42",
            "1234AB",
            "Amsterdam",
            "john@example.com",
            "12345678",
            "INVALID",
        )

        assert success is False
        assert "validation error" in msg.lower()

    @patch("travelers.check_permission")
    def test_add_traveler_invalid_gender(self, mock_check_perm):
        """Test adding traveler with invalid gender"""
        mock_check_perm.return_value = True

        success, msg, customer_id = add_traveler(
            "John",
            "Doe",
            "15-03-1990",
            "Other",
            "Main Street",
            "42",
            "1234AB",
            "Amsterdam",
            "john@example.com",
            "12345678",
            "AB1234567",
        )

        assert success is False
        assert "validation error" in msg.lower()

    @patch("travelers._generate_unique_customer_id")
    @patch("travelers.check_permission")
    def test_add_traveler_customer_id_generation_fails(
        self, mock_check_perm, mock_gen_id
    ):
        """Test adding traveler when customer ID generation fails"""
        mock_check_perm.return_value = True
        mock_gen_id.side_effect = RuntimeError(
            "Failed to generate unique customer ID after 10 attempts"
        )

        success, msg, customer_id = add_traveler(
            "John",
            "Doe",
            "15-03-1990",
            "Male",
            "Main Street",
            "42",
            "1234AB",
            "Amsterdam",
            "john@example.com",
            "12345678",
            "AB1234567",
        )

        assert success is False
        assert "failed to generate customer id" in msg.lower()
        assert customer_id is None


# ============================================================================
# Update Traveler Tests
# ============================================================================


@pytest.mark.unit
class TestUpdateTraveler:
    """Test updating traveler information"""

    @patch("travelers.log_activity")
    @patch("travelers.get_connection")
    @patch("travelers.encrypt_field")
    @patch("travelers.get_current_user")
    @patch("travelers.check_permission")
    def test_update_traveler_success(
        self, mock_check_perm, mock_get_user, mock_encrypt, mock_conn, mock_log
    ):
        """Test successfully updating a traveler"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001"}
        mock_encrypt.return_value = "encrypted_email"

        mock_cursor = Mock()
        # Mock traveler exists
        mock_cursor.fetchone.return_value = (
            1,
            "1234567890",
            "John",
            "Doe",
            "15-03-1990",
            "Male",
            "encrypted_street",
            "encrypted_house",
            "encrypted_zip",
            "encrypted_city",
            "encrypted_email",
            "encrypted_phone",
            "encrypted_license",
            "2025-01-01",
        )
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = update_traveler("1234567890", email="newemail@example.com")

        assert success is True
        assert "updated successfully" in msg.lower()
        mock_conn.return_value.commit.assert_called_once()

    @patch("travelers.check_permission")
    def test_update_traveler_no_permission(self, mock_check_perm):
        """Test updating traveler without permission"""
        mock_check_perm.return_value = False

        success, msg = update_traveler("1234567890", email="newemail@example.com")

        assert success is False
        assert "access denied" in msg.lower()

    @patch("travelers.get_current_user")
    @patch("travelers.check_permission")
    def test_update_traveler_no_fields(self, mock_check_perm, mock_get_user):
        """Test updating traveler with no fields specified"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001"}

        success, msg = update_traveler("1234567890")

        assert success is False
        assert "no fields" in msg.lower()

    @patch("travelers.get_connection")
    @patch("travelers.get_current_user")
    @patch("travelers.check_permission")
    def test_update_traveler_not_found(self, mock_check_perm, mock_get_user, mock_conn):
        """Test updating non-existent traveler"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001"}

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = update_traveler("9999999999", email="newemail@example.com")

        assert success is False
        assert "not found" in msg.lower()

    @patch("travelers.get_connection")
    @patch("travelers.get_current_user")
    @patch("travelers.check_permission")
    def test_update_traveler_invalid_field(
        self, mock_check_perm, mock_get_user, mock_conn
    ):
        """Test updating traveler with invalid field"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001"}

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1,)
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = update_traveler("1234567890", invalid_field="value")

        assert success is False
        assert "invalid field" in msg.lower()

    @patch("travelers.log_activity")
    @patch("travelers.get_connection")
    @patch("travelers.encrypt_field")
    @patch("travelers.get_current_user")
    @patch("travelers.check_permission")
    def test_update_traveler_multiple_fields(
        self, mock_check_perm, mock_get_user, mock_encrypt, mock_conn, mock_log
    ):
        """Test updating multiple traveler fields"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001"}
        mock_encrypt.side_effect = ["encrypted_email", "encrypted_phone"]

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1,) + ("data",) * 12
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = update_traveler(
            "1234567890", email="newemail@example.com", mobile_phone="87654321"
        )

        assert success is True

    @patch("travelers.log_activity")
    @patch("travelers.get_connection")
    @patch("travelers.get_current_user")
    @patch("travelers.check_permission")
    def test_update_traveler_first_name(
        self, mock_check_perm, mock_get_user, mock_conn, mock_log
    ):
        """Test updating traveler first_name field"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001"}

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1,) + ("data",) * 12
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = update_traveler("1234567890", first_name="Jane")

        assert success is True
        assert "updated successfully" in msg.lower()

    @patch("travelers.log_activity")
    @patch("travelers.get_connection")
    @patch("travelers.get_current_user")
    @patch("travelers.check_permission")
    def test_update_traveler_last_name(
        self, mock_check_perm, mock_get_user, mock_conn, mock_log
    ):
        """Test updating traveler last_name field"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001"}

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1,) + ("data",) * 12
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = update_traveler("1234567890", last_name="Smith")

        assert success is True

    @patch("travelers.log_activity")
    @patch("travelers.get_connection")
    @patch("travelers.get_current_user")
    @patch("travelers.check_permission")
    def test_update_traveler_birthday(
        self, mock_check_perm, mock_get_user, mock_conn, mock_log
    ):
        """Test updating traveler birthday field"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001"}

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1,) + ("data",) * 12
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = update_traveler("1234567890", birthday="01-01-1990")

        assert success is True

    @patch("travelers.log_activity")
    @patch("travelers.get_connection")
    @patch("travelers.get_current_user")
    @patch("travelers.check_permission")
    def test_update_traveler_gender(
        self, mock_check_perm, mock_get_user, mock_conn, mock_log
    ):
        """Test updating traveler gender field"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001"}

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1,) + ("data",) * 12
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = update_traveler("1234567890", gender="Female")

        assert success is True

    @patch("travelers.log_activity")
    @patch("travelers.get_connection")
    @patch("travelers.get_current_user")
    @patch("travelers.check_permission")
    def test_update_traveler_street_name(
        self, mock_check_perm, mock_get_user, mock_conn, mock_log
    ):
        """Test updating traveler street_name field"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001"}

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1,) + ("data",) * 12
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = update_traveler("1234567890", street_name="Oak Street")

        assert success is True

    @patch("travelers.log_activity")
    @patch("travelers.get_connection")
    @patch("travelers.get_current_user")
    @patch("travelers.check_permission")
    def test_update_traveler_house_number(
        self, mock_check_perm, mock_get_user, mock_conn, mock_log
    ):
        """Test updating traveler house_number field"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001"}

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1,) + ("data",) * 12
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = update_traveler("1234567890", house_number="123")

        assert success is True

    @patch("travelers.log_activity")
    @patch("travelers.get_connection")
    @patch("travelers.get_current_user")
    @patch("travelers.check_permission")
    def test_update_traveler_zip_code(
        self, mock_check_perm, mock_get_user, mock_conn, mock_log
    ):
        """Test updating traveler zip_code field"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001"}

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1,) + ("data",) * 12
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = update_traveler("1234567890", zip_code="5678CD")

        assert success is True

    @patch("travelers.log_activity")
    @patch("travelers.get_connection")
    @patch("travelers.get_current_user")
    @patch("travelers.check_permission")
    def test_update_traveler_city(
        self, mock_check_perm, mock_get_user, mock_conn, mock_log
    ):
        """Test updating traveler city field"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001"}

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1,) + ("data",) * 12
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = update_traveler("1234567890", city="Rotterdam")

        assert success is True

    @patch("travelers.log_activity")
    @patch("travelers.get_connection")
    @patch("travelers.encrypt_field")
    @patch("travelers.get_current_user")
    @patch("travelers.check_permission")
    def test_update_traveler_driving_license(
        self, mock_check_perm, mock_get_user, mock_encrypt, mock_conn, mock_log
    ):
        """Test updating traveler driving_license field"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001"}
        mock_encrypt.return_value = "encrypted_license"

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1,) + ("data",) * 12
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = update_traveler("1234567890", driving_license="CD9876543")

        assert success is True

    @patch("travelers.get_connection")
    @patch("travelers.get_current_user")
    @patch("travelers.check_permission")
    def test_update_traveler_validation_error(
        self, mock_check_perm, mock_get_user, mock_conn
    ):
        """Test update_traveler with validation error"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001"}

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1,) + ("data",) * 12
        mock_conn.return_value.cursor.return_value = mock_cursor

        # Invalid email should trigger validation error
        success, msg = update_traveler("1234567890", email="invalid_email")

        assert success is False
        assert "validation error" in msg.lower()


# ============================================================================
# Delete Traveler Tests
# ============================================================================


@pytest.mark.unit
class TestDeleteTraveler:
    """Test deleting travelers"""

    @patch("travelers.log_activity")
    @patch("travelers.get_connection")
    @patch("travelers.get_current_user")
    @patch("travelers.check_permission")
    def test_delete_traveler_success(
        self, mock_check_perm, mock_get_user, mock_conn, mock_log
    ):
        """Test successfully deleting a traveler"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001"}

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = ("John", "Doe")
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = delete_traveler("1234567890")

        assert success is True
        assert "deleted successfully" in msg.lower()
        # Should execute SELECT and DELETE
        assert mock_cursor.execute.call_count == 2

    @patch("travelers.check_permission")
    def test_delete_traveler_no_permission(self, mock_check_perm):
        """Test deleting traveler without permission"""
        mock_check_perm.return_value = False

        success, msg = delete_traveler("1234567890")

        assert success is False
        assert "access denied" in msg.lower()

    @patch("travelers.get_connection")
    @patch("travelers.get_current_user")
    @patch("travelers.check_permission")
    def test_delete_traveler_not_found(self, mock_check_perm, mock_get_user, mock_conn):
        """Test deleting non-existent traveler"""
        mock_check_perm.return_value = True
        mock_get_user.return_value = {"username": "admin_001"}

        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None
        mock_conn.return_value.cursor.return_value = mock_cursor

        success, msg = delete_traveler("9999999999")

        assert success is False
        assert "not found" in msg.lower()


# ============================================================================
# Search Travelers Tests
# ============================================================================


@pytest.mark.unit
class TestSearchTravelers:
    """Test searching for travelers"""

    @patch("travelers.get_connection")
    @patch("travelers.decrypt_field")
    def test_search_travelers_success(self, mock_decrypt, mock_conn):
        """Test successfully searching for travelers"""
        mock_cursor = Mock()
        mock_cursor.fetchall.return_value = [
            (
                1,
                "1234567890",
                "John",
                "Doe",
                "15-03-1990",
                "Male",
                "encrypted_street",
                "encrypted_house",
                "encrypted_zip",
                "encrypted_city",
                "encrypted_email",
                "encrypted_phone",
                "encrypted_license",
                "2025-01-01",
            )
        ]
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_decrypt.side_effect = [
            "Main Street",
            "42",
            "1234AB",
            "Amsterdam",
            "john@example.com",
            "12345678",
            "AB1234567",
        ]

        results = search_travelers("john")

        assert len(results) == 1
        assert results[0]["first_name"] == "John"
        assert results[0]["customer_id"] == "1234567890"

    @patch("travelers.get_connection")
    def test_search_travelers_empty_result(self, mock_conn):
        """Test searching with no results"""
        mock_cursor = Mock()
        mock_cursor.fetchall.return_value = []
        mock_conn.return_value.cursor.return_value = mock_cursor

        results = search_travelers("nonexistent")

        assert results == []

    def test_search_travelers_empty_search_key(self):
        """Test searching with empty search key"""
        results = search_travelers("")

        assert results == []

    def test_search_travelers_short_search_key(self):
        """Test searching with too short search key"""
        results = search_travelers("j")

        assert results == []

    @patch("travelers.get_connection")
    @patch("travelers.decrypt_field")
    def test_search_travelers_partial_match(self, mock_decrypt, mock_conn):
        """Test partial key matching"""
        mock_cursor = Mock()
        mock_cursor.fetchall.return_value = [
            (
                1,
                "1234567890",
                "Johnny",
                "Doe",
                "15-03-1990",
                "Male",
                "encrypted_street",
                "encrypted_house",
                "encrypted_zip",
                "encrypted_city",
                "encrypted_email",
                "encrypted_phone",
                "encrypted_license",
                "2025-01-01",
            ),
            (
                2,
                "0987654321",
                "John",
                "Smith",
                "20-05-1985",
                "Male",
                "Oak Street",
                "15",
                "5678CD",
                "Rotterdam",
                "encrypted_email2",
                "encrypted_phone2",
                "encrypted_license2",
                "2025-01-02",
            ),
        ]
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_decrypt.side_effect = [
            "Main Street",
            "42",
            "1234AB",
            "Amsterdam",
            "john1@example.com",
            "11111111",
            "AB1111111",
            "Oak Street",
            "15",
            "5678CD",
            "Rotterdam",
            "john2@example.com",
            "22222222",
            "AB2222222",
        ]

        results = search_travelers("john")

        assert len(results) == 2


# ============================================================================
# Get Traveler By ID Tests
# ============================================================================


@pytest.mark.unit
class TestGetTravelerById:
    """Test getting traveler by ID"""

    @patch("travelers.get_connection")
    @patch("travelers.decrypt_field")
    def test_get_traveler_by_id_success(self, mock_decrypt, mock_conn):
        """Test successfully getting traveler by ID"""
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (
            1,
            "1234567890",
            "John",
            "Doe",
            "15-03-1990",
            "Male",
            "encrypted_street",
            "encrypted_house",
            "encrypted_zip",
            "encrypted_city",
            "encrypted_email",
            "encrypted_phone",
            "encrypted_license",
            "2025-01-01",
        )
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_decrypt.side_effect = [
            "Main Street",
            "42",
            "1234AB",
            "Amsterdam",
            "john@example.com",
            "12345678",
            "AB1234567",
        ]

        traveler = get_traveler_by_id("1234567890")

        assert traveler is not None
        assert traveler["customer_id"] == "1234567890"
        assert traveler["first_name"] == "John"
        assert traveler["email"] == "john@example.com"

    @patch("travelers.get_connection")
    def test_get_traveler_by_id_not_found(self, mock_conn):
        """Test getting non-existent traveler by ID"""
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None
        mock_conn.return_value.cursor.return_value = mock_cursor

        traveler = get_traveler_by_id("9999999999")

        assert traveler is None


# ============================================================================
# List All Travelers Tests
# ============================================================================


@pytest.mark.unit
class TestListAllTravelers:
    """Test listing all travelers"""

    @patch("travelers.get_connection")
    @patch("travelers.decrypt_field")
    def test_list_all_travelers_success(self, mock_decrypt, mock_conn):
        """Test successfully listing all travelers"""
        mock_cursor = Mock()
        mock_cursor.fetchall.return_value = [
            (
                1,
                "1234567890",
                "John",
                "Doe",
                "15-03-1990",
                "Male",
                "encrypted_street1",
                "encrypted_house1",
                "encrypted_zip1",
                "encrypted_city1",
                "encrypted_email1",
                "encrypted_phone1",
                "encrypted_license1",
                "2025-01-01",
            ),
            (
                2,
                "0987654321",
                "Jane",
                "Smith",
                "20-05-1985",
                "Female",
                "encrypted_street2",
                "encrypted_house2",
                "encrypted_zip2",
                "encrypted_city2",
                "encrypted_email2",
                "encrypted_phone2",
                "encrypted_license2",
                "2025-01-02",
            ),
        ]
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_decrypt.side_effect = [
            "Main Street",
            "42",
            "1234AB",
            "Amsterdam",
            "john@example.com",
            "11111111",
            "AB1111111",
            "Oak Street",
            "15",
            "5678CD",
            "Rotterdam",
            "jane@example.com",
            "22222222",
            "AB2222222",
        ]

        travelers = list_all_travelers()

        assert len(travelers) == 2
        assert travelers[0]["first_name"] == "John"
        assert travelers[1]["first_name"] == "Jane"

    @patch("travelers.get_connection")
    def test_list_all_travelers_empty(self, mock_conn):
        """Test listing travelers when database is empty"""
        mock_cursor = Mock()
        mock_cursor.fetchall.return_value = []
        mock_conn.return_value.cursor.return_value = mock_cursor

        travelers = list_all_travelers()

        assert travelers == []

    @patch("travelers.get_connection")
    @patch("travelers.decrypt_field")
    def test_list_all_travelers_decrypts_fields(self, mock_decrypt, mock_conn):
        """Test that sensitive fields are decrypted"""
        mock_cursor = Mock()
        mock_cursor.fetchall.return_value = [
            (
                1,
                "1234567890",
                "John",
                "Doe",
                "15-03-1990",
                "Male",
                "encrypted_street",
                "encrypted_house",
                "encrypted_zip",
                "encrypted_city",
                "encrypted_email",
                "encrypted_phone",
                "encrypted_license",
                "2025-01-01",
            )
        ]
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_decrypt.side_effect = [
            "Main Street",
            "42",
            "1234AB",
            "Amsterdam",
            "john@example.com",
            "12345678",
            "AB1234567",
        ]

        travelers = list_all_travelers()

        # Should decrypt email, phone, license, and address fields
        assert mock_decrypt.call_count == 7
        assert travelers[0]["email"] == "john@example.com"
        assert travelers[0]["mobile_phone"] == "12345678"
        assert travelers[0]["driving_license"] == "AB1234567"
