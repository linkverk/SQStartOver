"""
Pytest configuration and shared fixtures.

This module provides fixtures that are available to all tests.
"""

import pytest
import sys
import os
from pathlib import Path
from unittest.mock import MagicMock

# Add src directory to Python path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """
    Provide isolated test database for each test.

    Creates a temporary SQLite database that is automatically
    cleaned up after the test completes.

    Args:
        tmp_path: Pytest's temporary directory fixture
        monkeypatch: Pytest's monkeypatch fixture for modifying behavior

    Yields:
        Path: Path to the test database file
    """
    from database import init_database, get_connection

    # Create test database in temporary directory
    db_path = tmp_path / "test.db"

    # Monkeypatch the DATABASE_FILE constant to use test database
    import database

    monkeypatch.setattr(database, "DATABASE_FILE", str(db_path))

    # Initialize test database
    init_database()

    yield db_path

    # Cleanup: close any open connections
    try:
        conn = get_connection()
        if conn:
            conn.close()
    except:
        pass


@pytest.fixture
def sample_user():
    """
    Provide sample user data for testing.

    Returns:
        dict: Sample user data with all required fields
    """
    return {
        "username": "testuser1",
        "first_name": "John",
        "last_name": "Doe",
        "role": "system_admin",
        "password": "TestPass123!@#",
    }


@pytest.fixture
def sample_traveler():
    """
    Provide sample traveler data for testing.

    Returns:
        dict: Sample traveler data with all required fields
    """
    return {
        "first_name": "Jane",
        "last_name": "Smith",
        "birthday": "15-03-1995",
        "gender": "Female",
        "street_name": "Main Street",
        "house_number": "42",
        "zip_code": "1234AB",
        "city": "Amsterdam",
        "email": "jane.smith@example.com",
        "mobile_phone": "12345678",
        "driving_license": "AB1234567",
    }


@pytest.fixture
def sample_scooter():
    """
    Provide sample scooter data for testing.

    Returns:
        dict: Sample scooter data with all required fields
    """
    return {
        "serial_number": "ABC123XYZ",
        "type": "E-Scooter Pro",
        "battery_level": 85,
        "status": "available",
        "location": "Central Station",
    }


@pytest.fixture(autouse=True)
def reset_auth_state():
    """
    Automatically reset authentication state before each test.

    This fixture runs automatically before every test to ensure
    clean state for authentication-related tests.
    """
    from auth import logout

    # Logout before test
    logout()

    yield

    # Logout after test
    logout()


@pytest.fixture
def mock_input(monkeypatch):
    """
    Provide a mock input function for testing user input.

    Returns:
        MagicMock: Mock object that can be configured to return specific values

    Example:
        def test_something(mock_input):
            mock_input.return_value = "test input"
            # or
            mock_input.side_effect = ["first", "second", "third"]
    """
    mock = MagicMock()
    monkeypatch.setattr("builtins.input", mock)
    return mock


@pytest.fixture
def mock_print(monkeypatch):
    """
    Provide a mock print function for testing output.

    Returns:
        MagicMock: Mock object that captures print calls

    Example:
        def test_something(mock_print):
            some_function_that_prints()
            assert mock_print.called
            assert "expected output" in str(mock_print.call_args)
    """
    mock = MagicMock()
    monkeypatch.setattr("builtins.print", mock)
    return mock


@pytest.fixture
def captured_output(capsys):
    """
    Helper fixture to easily capture and verify print output.

    Returns:
        callable: Function that returns captured output

    Example:
        def test_something(captured_output):
            print("test")
            output = captured_output()
            assert "test" in output
    """

    def _get_output():
        captured = capsys.readouterr()
        return captured.out + captured.err

    return _get_output
