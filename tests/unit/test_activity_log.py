"""
Unit tests for activity_log.py module.

Tests activity logging system including encryption, log retrieval,
suspicious activity tracking, and log management.
"""

import pytest
from unittest.mock import Mock, patch, mock_open, MagicMock
from pathlib import Path
from datetime import datetime
from activity_log import (
    _get_log_cipher,
    _encrypt_log_content,
    _decrypt_log_content,
    log_activity,
    get_all_logs,
    get_suspicious_logs,
    get_unread_suspicious_count,
    check_suspicious_activities,
    mark_logs_as_read,
    clear_logs,
    display_logs,
)


# ============================================================================
# Encryption Helper Tests
# ============================================================================


@pytest.mark.unit
class TestLogEncryptionHelpers:
    """Test log encryption and decryption helpers"""

    @patch("activity_log.FERNET_KEY_FILE")
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=b"u3Uc-qAi9iiCv3fkBfRUAKrM1gH8w51-nVU8M8A73Jg=",
    )
    def test_get_log_cipher_success(self, mock_file, mock_key_path):
        """Test getting Fernet cipher successfully (using valid base64 Fernet key)"""
        mock_key_path.exists.return_value = True

        cipher = _get_log_cipher()

        assert cipher is not None
        mock_file.assert_called_once()

    @patch("activity_log.FERNET_KEY_FILE")
    def test_get_log_cipher_file_not_found(self, mock_key_path):
        """Test getting cipher when key file doesn't exist"""
        mock_key_path.exists.return_value = False

        with pytest.raises(FileNotFoundError) as exc_info:
            _get_log_cipher()

        assert "Fernet key file not found" in str(exc_info.value)

    @patch("activity_log._get_log_cipher")
    def test_encrypt_log_content_success(self, mock_cipher):
        """Test encrypting log content"""
        mock_fernet = Mock()
        mock_fernet.encrypt.return_value = b"encrypted_content"
        mock_cipher.return_value = mock_fernet

        result = _encrypt_log_content("test content")

        assert result == b"encrypted_content"
        mock_fernet.encrypt.assert_called_once_with(b"test content")

    @patch("activity_log._get_log_cipher")
    def test_decrypt_log_content_success(self, mock_cipher):
        """Test decrypting log content"""
        mock_fernet = Mock()
        mock_fernet.decrypt.return_value = b"decrypted content"
        mock_cipher.return_value = mock_fernet

        result = _decrypt_log_content(b"encrypted_content")

        assert result == "decrypted content"
        mock_fernet.decrypt.assert_called_once_with(b"encrypted_content")


# ============================================================================
# Log Activity Tests
# ============================================================================


@pytest.mark.unit
class TestLogActivity:
    """Test logging activities"""

    @patch("activity_log.LOG_FILE")
    @patch("activity_log.DATA_DIR")
    @patch("activity_log._encrypt_log_content")
    @patch("builtins.open", new_callable=mock_open)
    def test_log_activity_first_log(
        self, mock_file, mock_encrypt, mock_data_dir, mock_log_file
    ):
        """Test logging first activity (creates header)"""
        mock_log_file.exists.return_value = False
        mock_data_dir.mkdir = Mock()
        mock_encrypt.return_value = b"encrypted_log"

        log_activity("test_user", "Logged in")

        mock_data_dir.mkdir.assert_called_once_with(parents=True, exist_ok=True)
        mock_encrypt.assert_called_once()
        # Check that write was called
        mock_file().write.assert_called_once_with(b"encrypted_log")

    @patch("activity_log.LOG_FILE")
    @patch("activity_log.DATA_DIR")
    @patch("activity_log._encrypt_log_content")
    @patch("activity_log._decrypt_log_content")
    @patch("builtins.open", new_callable=mock_open)
    def test_log_activity_append_log(
        self, mock_file, mock_decrypt, mock_encrypt, mock_data_dir, mock_log_file
    ):
        """Test appending to existing log file"""
        mock_log_file.exists.return_value = True
        mock_decrypt.return_value = (
            "No.,Date,Time,Username,Activity,Additional Info,Suspicious\n"
            '"1","01-01-2025","10:00:00","admin","Login","","No"\n'
        )
        mock_encrypt.return_value = b"encrypted_log"

        log_activity("test_user", "Logged out", "Session ended")

        # Decrypt may be called multiple times (once for number, once for content)
        assert mock_decrypt.call_count >= 1
        mock_encrypt.assert_called_once()
        # Verify new log number is 2
        encrypted_content = mock_encrypt.call_args[0][0]
        assert '"2"' in encrypted_content

    @patch("activity_log.LOG_FILE")
    @patch("activity_log.DATA_DIR")
    @patch("activity_log._encrypt_log_content")
    @patch("builtins.open", new_callable=mock_open)
    def test_log_activity_suspicious_flag(
        self, mock_file, mock_encrypt, mock_data_dir, mock_log_file
    ):
        """Test logging suspicious activity"""
        mock_log_file.exists.return_value = False
        mock_encrypt.return_value = b"encrypted_log"

        log_activity("hacker", "Failed login", "Wrong password", suspicious=True)

        encrypted_content = mock_encrypt.call_args[0][0]
        assert '"Yes"' in encrypted_content  # Suspicious flag
        assert "Failed login" in encrypted_content

    @patch("activity_log.LOG_FILE")
    @patch("activity_log.DATA_DIR")
    @patch("activity_log._encrypt_log_content")
    @patch("builtins.open", new_callable=mock_open)
    def test_log_activity_with_additional_info(
        self, mock_file, mock_encrypt, mock_data_dir, mock_log_file
    ):
        """Test logging with additional information"""
        mock_log_file.exists.return_value = False
        mock_encrypt.return_value = b"encrypted_log"

        log_activity("admin", "User created", "Username: john_m", suspicious=False)

        encrypted_content = mock_encrypt.call_args[0][0]
        assert "User created" in encrypted_content
        assert "Username: john_m" in encrypted_content

    @patch("activity_log.LOG_FILE")
    @patch("activity_log.DATA_DIR")
    @patch("activity_log._encrypt_log_content")
    @patch("activity_log._decrypt_log_content")
    @patch("builtins.open", new_callable=mock_open)
    def test_log_activity_corrupted_log_number(
        self, mock_file, mock_decrypt, mock_encrypt, mock_data_dir, mock_log_file
    ):
        """Test logging when existing log file has corrupted/unparseable log number"""
        mock_log_file.exists.return_value = True
        # First call: Return data that causes parsing exception when extracting log number
        # The code tries to parse: int(last_line.split(",")[0].strip('"'))
        # We'll make this raise an exception
        mock_decrypt.side_effect = [
            "No.,Date,Time,Username,Activity,Additional Info,Suspicious\n"
            '"bad","01-01-2025","10:00:00","admin","Login","","No"\n',  # First call - 'bad' can't be converted to int
            "No.,Date,Time,Username,Activity,Additional Info,Suspicious\n",  # Second call
        ]
        mock_encrypt.return_value = b"encrypted_log"

        log_activity("test_user", "Test activity")

        # Should fall back to log_number = 1 due to exception handling
        mock_encrypt.assert_called_once()
        encrypted_content = mock_encrypt.call_args[0][0]
        # Should start with log number 1 since parsing failed
        assert '"1"' in encrypted_content

    @patch("activity_log.LOG_FILE")
    @patch("activity_log.DATA_DIR")
    @patch("activity_log._encrypt_log_content")
    @patch("activity_log._decrypt_log_content")
    @patch("builtins.open", new_callable=mock_open)
    def test_log_activity_decryption_fails(
        self, mock_file, mock_decrypt, mock_encrypt, mock_data_dir, mock_log_file
    ):
        """Test logging when decryption of existing content fails"""
        # Setup: File exists but decryption fails on second call
        call_count = [0]

        def decrypt_side_effect(content):
            call_count[0] += 1
            if call_count[0] == 1:
                # First call for getting log number - succeeds
                return (
                    "No.,Date,Time,Username,Activity,Additional Info,Suspicious\n"
                    '"1","01-01-2025","10:00:00","admin","Login","","No"\n'
                )
            else:
                # Second call for reading existing content - fails
                raise Exception("Decryption failed")

        mock_log_file.exists.return_value = True
        mock_decrypt.side_effect = decrypt_side_effect
        mock_encrypt.return_value = b"encrypted_log"

        log_activity("test_user", "Test activity")

        # Should handle exception and create fresh header
        mock_encrypt.assert_called_once()
        encrypted_content = mock_encrypt.call_args[0][0]
        # Should include the header and new log entry
        assert (
            "No.,Date,Time,Username,Activity,Additional Info,Suspicious"
            in encrypted_content
        )
        assert "Test activity" in encrypted_content


# ============================================================================
# Log Retrieval Tests
# ============================================================================


@pytest.mark.unit
class TestGetAllLogs:
    """Test retrieving all logs"""

    @patch("activity_log.LOG_FILE")
    def test_get_all_logs_file_not_exists(self, mock_log_file):
        """Test getting logs when file doesn't exist"""
        mock_log_file.exists.return_value = False

        logs = get_all_logs()

        assert logs == []

    @patch("activity_log.LOG_FILE")
    @patch("activity_log._decrypt_log_content")
    @patch("builtins.open", new_callable=mock_open, read_data=b"encrypted")
    def test_get_all_logs_success(self, mock_file, mock_decrypt, mock_log_file):
        """Test successfully retrieving all logs"""
        mock_log_file.exists.return_value = True
        mock_decrypt.return_value = (
            "No.,Date,Time,Username,Activity,Additional Info,Suspicious\n"
            '"1","01-01-2025","10:00:00","admin","Login","","No"\n'
            '"2","01-01-2025","10:05:00","user1","Logout","","No"\n'
        )

        logs = get_all_logs()

        assert len(logs) == 2
        assert logs[0]["no"] == 1
        assert logs[0]["username"] == "admin"
        assert logs[0]["activity"] == "Login"
        assert logs[1]["no"] == 2
        assert logs[1]["username"] == "user1"

    @patch("activity_log.LOG_FILE")
    @patch("activity_log._decrypt_log_content")
    @patch("builtins.open", new_callable=mock_open)
    def test_get_all_logs_empty_file(self, mock_file, mock_decrypt, mock_log_file):
        """Test getting logs from file with only header"""
        mock_log_file.exists.return_value = True
        mock_decrypt.return_value = (
            "No.,Date,Time,Username,Activity,Additional Info,Suspicious\n"
        )

        logs = get_all_logs()

        assert logs == []

    @patch("activity_log.LOG_FILE")
    @patch("builtins.open", side_effect=Exception("Read error"))
    def test_get_all_logs_error_handling(self, mock_file, mock_log_file):
        """Test error handling when reading logs fails"""
        mock_log_file.exists.return_value = True

        logs = get_all_logs()

        assert logs == []


# ============================================================================
# Suspicious Logs Tests
# ============================================================================


@pytest.mark.unit
class TestSuspiciousLogs:
    """Test suspicious activity filtering and counting"""

    @patch("activity_log.get_all_logs")
    def test_get_suspicious_logs_success(self, mock_get_all):
        """Test getting only suspicious logs"""
        mock_get_all.return_value = [
            {"no": 1, "username": "admin", "activity": "Login", "suspicious": "No"},
            {
                "no": 2,
                "username": "hacker",
                "activity": "Failed login",
                "suspicious": "Yes",
            },
            {"no": 3, "username": "admin", "activity": "Logout", "suspicious": "No"},
            {
                "no": 4,
                "username": "hacker",
                "activity": "SQL injection",
                "suspicious": "Yes",
            },
        ]

        suspicious = get_suspicious_logs()

        assert len(suspicious) == 2
        assert suspicious[0]["no"] == 2
        assert suspicious[1]["no"] == 4
        assert all(log["suspicious"] == "Yes" for log in suspicious)

    @patch("activity_log.get_all_logs")
    def test_get_suspicious_logs_empty(self, mock_get_all):
        """Test getting suspicious logs when none exist"""
        mock_get_all.return_value = [
            {"no": 1, "username": "admin", "activity": "Login", "suspicious": "No"},
        ]

        suspicious = get_suspicious_logs()

        assert suspicious == []

    @patch("activity_log.LAST_CHECK_FILE")
    @patch("activity_log.get_suspicious_logs")
    def test_get_unread_suspicious_count_with_last_check(
        self, mock_get_suspicious, mock_check_file
    ):
        """Test counting unread suspicious activities"""
        mock_check_file.exists.return_value = True
        mock_get_suspicious.return_value = [
            {"no": 1, "suspicious": "Yes"},
            {"no": 2, "suspicious": "Yes"},
            {"no": 5, "suspicious": "Yes"},
            {"no": 6, "suspicious": "Yes"},
        ]

        with patch("builtins.open", mock_open(read_data="2")):
            count = get_unread_suspicious_count()

        # Should count logs with no > 2 (logs 5 and 6)
        assert count == 2

    @patch("activity_log.LAST_CHECK_FILE")
    @patch("activity_log.get_suspicious_logs")
    def test_get_unread_suspicious_count_no_last_check(
        self, mock_get_suspicious, mock_check_file
    ):
        """Test counting unread when no last check file"""
        mock_check_file.exists.return_value = False
        mock_get_suspicious.return_value = [
            {"no": 1, "suspicious": "Yes"},
            {"no": 2, "suspicious": "Yes"},
        ]

        count = get_unread_suspicious_count()

        # All should be unread
        assert count == 2

    @patch("activity_log.get_unread_suspicious_count")
    def test_check_suspicious_activities(self, mock_get_unread):
        """Test check_suspicious_activities is alias for get_unread_suspicious_count"""
        mock_get_unread.return_value = 5

        count = check_suspicious_activities()

        assert count == 5
        mock_get_unread.assert_called_once()

    @patch("activity_log.LAST_CHECK_FILE")
    @patch("activity_log.get_suspicious_logs")
    def test_get_unread_suspicious_count_corrupted_check_file(
        self, mock_get_suspicious, mock_check_file
    ):
        """Test counting unread when last check file is corrupted"""
        mock_check_file.exists.return_value = True
        mock_get_suspicious.return_value = [
            {"no": 1, "suspicious": "Yes"},
            {"no": 2, "suspicious": "Yes"},
            {"no": 5, "suspicious": "Yes"},
        ]

        # Mock open to raise exception when reading
        with patch("builtins.open", mock_open()) as mock_file:
            mock_file.side_effect = Exception("Cannot read file")
            count = get_unread_suspicious_count()

        # Should default to last_checked = 0, so all 3 logs are unread
        assert count == 3


# ============================================================================
# Log Management Tests
# ============================================================================


@pytest.mark.unit
class TestMarkLogsAsRead:
    """Test marking logs as read"""

    @patch("activity_log.DATA_DIR")
    @patch("activity_log.LAST_CHECK_FILE")
    @patch("activity_log.get_all_logs")
    @patch("builtins.open", new_callable=mock_open)
    def test_mark_logs_as_read_success(
        self, mock_file, mock_get_all, mock_check_file, mock_data_dir
    ):
        """Test marking logs as read saves highest log number"""
        mock_get_all.return_value = [
            {"no": 1, "activity": "Login"},
            {"no": 5, "activity": "Logout"},
            {"no": 3, "activity": "Update"},
        ]

        mark_logs_as_read()

        # Should write highest log number (5)
        mock_file().write.assert_called_once_with("5")
        mock_data_dir.mkdir.assert_called_once_with(parents=True, exist_ok=True)

    @patch("activity_log.get_all_logs")
    def test_mark_logs_as_read_no_logs(self, mock_get_all):
        """Test marking logs as read when no logs exist"""
        mock_get_all.return_value = []

        # Should not raise error
        mark_logs_as_read()


@pytest.mark.unit
class TestClearLogs:
    """Test clearing all logs"""

    @patch("activity_log.LAST_CHECK_FILE")
    @patch("activity_log.LOG_FILE")
    def test_clear_logs_success(self, mock_log_file, mock_check_file):
        """Test successfully clearing logs"""
        mock_log_file.exists.return_value = True
        mock_check_file.exists.return_value = True
        mock_log_file.unlink = Mock()
        mock_check_file.unlink = Mock()

        success, msg = clear_logs()

        assert success is True
        assert "cleared successfully" in msg.lower()
        mock_log_file.unlink.assert_called_once()
        mock_check_file.unlink.assert_called_once()

    @patch("activity_log.LAST_CHECK_FILE")
    @patch("activity_log.LOG_FILE")
    def test_clear_logs_files_not_exist(self, mock_log_file, mock_check_file):
        """Test clearing logs when files don't exist"""
        mock_log_file.exists.return_value = False
        mock_check_file.exists.return_value = False

        success, msg = clear_logs()

        assert success is True
        assert "cleared successfully" in msg.lower()

    @patch("activity_log.LAST_CHECK_FILE")
    @patch("activity_log.LOG_FILE")
    def test_clear_logs_error_handling(self, mock_log_file, mock_check_file):
        """Test error handling when clearing logs fails"""
        mock_log_file.exists.return_value = True
        mock_log_file.unlink.side_effect = Exception("Permission denied")

        success, msg = clear_logs()

        assert success is False
        assert "error" in msg.lower()


# ============================================================================
# Display Logs Tests
# ============================================================================


@pytest.mark.unit
class TestDisplayLogs:
    """Test log display functionality"""

    def test_display_logs_empty(self, capsys):
        """Test displaying empty logs"""
        display_logs([])

        captured = capsys.readouterr()
        assert "No logs found" in captured.out

    def test_display_logs_success(self, capsys):
        """Test displaying logs successfully"""
        logs = [
            {
                "no": 1,
                "date": "01-01-2025",
                "time": "10:00:00",
                "username": "admin",
                "activity": "Login",
                "additional_info": "Success",
                "suspicious": "No",
            },
            {
                "no": 2,
                "date": "01-01-2025",
                "time": "10:05:00",
                "username": "user1",
                "activity": "Logout",
                "additional_info": "",
                "suspicious": "No",
            },
        ]

        display_logs(logs)

        captured = capsys.readouterr()
        assert "admin" in captured.out
        assert "user1" in captured.out
        assert "Total logs: 2" in captured.out

    def test_display_logs_suspicious_only(self, capsys):
        """Test displaying only suspicious logs"""
        logs = [
            {
                "no": 1,
                "date": "01-01-2025",
                "time": "10:00:00",
                "username": "admin",
                "activity": "Login",
                "additional_info": "",
                "suspicious": "No",
            },
            {
                "no": 2,
                "date": "01-01-2025",
                "time": "10:05:00",
                "username": "hacker",
                "activity": "Failed login",
                "additional_info": "Wrong password",
                "suspicious": "Yes",
            },
        ]

        display_logs(logs, show_suspicious_only=True)

        captured = capsys.readouterr()
        assert "hacker" in captured.out
        assert "admin" not in captured.out
        assert "Total logs: 1" in captured.out

    def test_display_logs_shows_suspicious_count(self, capsys):
        """Test that display shows suspicious activity count"""
        logs = [
            {
                "no": 1,
                "date": "01-01-2025",
                "time": "10:00:00",
                "username": "admin",
                "activity": "Login",
                "additional_info": "",
                "suspicious": "No",
            },
            {
                "no": 2,
                "date": "01-01-2025",
                "time": "10:05:00",
                "username": "hacker",
                "activity": "Failed login",
                "additional_info": "",
                "suspicious": "Yes",
            },
        ]

        display_logs(logs)

        captured = capsys.readouterr()
        assert "Suspicious activities: 1" in captured.out
