"""
Unit tests for input_handlers.py module.

Tests all input handler functions with mocked user input,
validation, exit/cancel behavior, and error handling.
"""

import pytest
from unittest.mock import patch
from input_handlers import (
    CancelInputException,
    prompt_with_validation,
    prompt_integer_with_validation,
    prompt_menu_choice,
    prompt_confirmation,
    prompt_optional_field,
    prompt_choice_from_list,
)
from validation import validate_email, validate_state_of_charge


# ============================================================================
# CancelInputException Tests
# ============================================================================


@pytest.mark.unit
class TestCancelInputException:
    """Test CancelInputException class"""

    def test_exception_can_be_raised(self):
        """Test that CancelInputException can be raised"""
        with pytest.raises(CancelInputException):
            raise CancelInputException("Test message")

    def test_exception_message(self):
        """Test that exception carries message"""
        try:
            raise CancelInputException("User cancelled")
        except CancelInputException as e:
            assert str(e) == "User cancelled"


# ============================================================================
# prompt_with_validation Tests
# ============================================================================


@pytest.mark.unit
class TestPromptWithValidation:
    """Test prompt_with_validation function"""

    @patch("builtins.input")
    @patch("builtins.print")
    def test_valid_input_first_try(self, mock_print, mock_input):
        """Test valid input on first attempt"""
        mock_input.return_value = "user@example.com"

        result = prompt_with_validation("Email: ", validate_email)

        assert result == "user@example.com"
        mock_print.assert_not_called()  # No error messages
        mock_input.assert_called_once_with("Email: ")

    @patch("builtins.input")
    @patch("builtins.print")
    def test_invalid_then_valid_input(self, mock_print, mock_input):
        """Test retry after invalid input"""
        mock_input.side_effect = ["invalid", "user@example.com"]

        result = prompt_with_validation("Email: ", validate_email)

        assert result == "user@example.com"
        assert mock_print.call_count == 1
        # Verify error message format
        error_msg = str(mock_print.call_args[0][0])
        assert "❌ Error:" in error_msg
        assert "Expected:" in error_msg

    @patch("builtins.input")
    @patch("builtins.print")
    def test_multiple_retries(self, mock_print, mock_input):
        """Test multiple retry attempts"""
        mock_input.side_effect = ["bad1", "bad2", "bad3", "user@example.com"]

        result = prompt_with_validation("Email: ", validate_email)

        assert result == "user@example.com"
        assert mock_print.call_count == 3  # Three error messages

    @patch("builtins.input")
    def test_exit_command(self, mock_input):
        """Test that 'exit' raises CancelInputException"""
        mock_input.return_value = "exit"

        with pytest.raises(CancelInputException):
            prompt_with_validation("Email: ", validate_email)

    @patch("builtins.input")
    def test_cancel_command(self, mock_input):
        """Test that 'cancel' raises CancelInputException"""
        mock_input.return_value = "cancel"

        with pytest.raises(CancelInputException):
            prompt_with_validation("Email: ", validate_email)

    @patch("builtins.input")
    def test_exit_case_insensitive(self, mock_input):
        """Test that exit is case insensitive"""
        mock_input.return_value = "EXIT"

        with pytest.raises(CancelInputException):
            prompt_with_validation("Email: ", validate_email)

    @patch("builtins.input")
    def test_exit_disabled(self, mock_input):
        """Test that exit can be disabled"""
        mock_input.return_value = "exit"

        # When allow_exit=False, 'exit' should be treated as normal input
        # This will fail validation, so mock should provide valid input next
        mock_input.side_effect = ["exit", "user@example.com"]

        result = prompt_with_validation("Email: ", validate_email, allow_exit=False)
        assert result == "user@example.com"

    @patch("builtins.input")
    @patch("builtins.print")
    def test_whitespace_trimmed(self, mock_print, mock_input):
        """Test that input whitespace is trimmed"""
        mock_input.return_value = "  user@example.com  "

        result = prompt_with_validation("Email: ", validate_email)

        # validate_email should return lowercase without spaces
        assert result == "user@example.com"


# ============================================================================
# prompt_integer_with_validation Tests
# ============================================================================


@pytest.mark.unit
class TestPromptIntegerWithValidation:
    """Test prompt_integer_with_validation function"""

    @patch("builtins.input")
    @patch("builtins.print")
    def test_valid_integer_input(self, mock_print, mock_input):
        """Test valid integer input"""
        mock_input.return_value = "75"

        result = prompt_integer_with_validation(
            "Battery (0-100): ", validate_state_of_charge
        )

        assert result == 75
        mock_print.assert_not_called()

    @patch("builtins.input")
    @patch("builtins.print")
    def test_string_to_integer_conversion(self, mock_print, mock_input):
        """Test that string numbers are converted to integers"""
        mock_input.return_value = "  100  "

        result = prompt_integer_with_validation("Battery: ", validate_state_of_charge)

        assert result == 100
        assert isinstance(result, int)

    @patch("builtins.input")
    @patch("builtins.print")
    def test_non_numeric_input(self, mock_print, mock_input):
        """Test non-numeric input handling"""
        mock_input.side_effect = ["abc", "75"]

        result = prompt_integer_with_validation("Battery: ", validate_state_of_charge)

        assert result == 75
        assert mock_print.call_count == 1
        error_msg = str(mock_print.call_args[0][0])
        assert "must be a number" in error_msg.lower()

    @patch("builtins.input")
    @patch("builtins.print")
    def test_out_of_range_integer(self, mock_print, mock_input):
        """Test integer out of valid range"""
        mock_input.side_effect = ["150", "75"]

        result = prompt_integer_with_validation("Battery: ", validate_state_of_charge)

        assert result == 75
        assert mock_print.call_count == 1

    @patch("builtins.input")
    def test_exit_on_integer_prompt(self, mock_input):
        """Test exit command on integer prompt"""
        mock_input.return_value = "exit"

        with pytest.raises(CancelInputException):
            prompt_integer_with_validation("Battery: ", validate_state_of_charge)


# ============================================================================
# prompt_menu_choice Tests
# ============================================================================


@pytest.mark.unit
class TestPromptMenuChoice:
    """Test prompt_menu_choice function"""

    @patch("builtins.input")
    @patch("builtins.print")
    def test_valid_menu_choice(self, mock_print, mock_input):
        """Test valid menu choice"""
        mock_input.return_value = "3"

        result = prompt_menu_choice("Choose (1-5): ", 1, 5)

        assert result == "3"
        mock_print.assert_not_called()

    @patch("builtins.input")
    @patch("builtins.print")
    def test_minimum_choice(self, mock_print, mock_input):
        """Test minimum valid choice"""
        mock_input.return_value = "1"

        result = prompt_menu_choice("Choose (1-5): ", 1, 5)

        assert result == "1"

    @patch("builtins.input")
    @patch("builtins.print")
    def test_maximum_choice(self, mock_print, mock_input):
        """Test maximum valid choice"""
        mock_input.return_value = "5"

        result = prompt_menu_choice("Choose (1-5): ", 1, 5)

        assert result == "5"

    @patch("builtins.input")
    @patch("builtins.print")
    def test_choice_below_minimum(self, mock_print, mock_input):
        """Test choice below minimum"""
        mock_input.side_effect = ["0", "3"]

        result = prompt_menu_choice("Choose (1-5): ", 1, 5)

        assert result == "3"
        assert mock_print.call_count == 1
        error_msg = str(mock_print.call_args[0][0])
        assert "out of range" in error_msg.lower()
        assert "1 and 5" in error_msg

    @patch("builtins.input")
    @patch("builtins.print")
    def test_choice_above_maximum(self, mock_print, mock_input):
        """Test choice above maximum"""
        mock_input.side_effect = ["10", "3"]

        result = prompt_menu_choice("Choose (1-5): ", 1, 5)

        assert result == "3"
        assert mock_print.call_count == 1

    @patch("builtins.input")
    @patch("builtins.print")
    def test_non_numeric_menu_choice(self, mock_print, mock_input):
        """Test non-numeric menu choice"""
        mock_input.side_effect = ["abc", "3"]

        result = prompt_menu_choice("Choose (1-5): ", 1, 5)

        assert result == "3"
        assert mock_print.call_count == 1
        error_msg = str(mock_print.call_args[0][0])
        assert "valid number" in error_msg.lower()

    @patch("builtins.input")
    def test_exit_on_menu_choice(self, mock_input):
        """Test exit on menu choice"""
        mock_input.return_value = "cancel"

        with pytest.raises(CancelInputException):
            prompt_menu_choice("Choose (1-5): ", 1, 5)


# ============================================================================
# prompt_confirmation Tests
# ============================================================================


@pytest.mark.unit
class TestPromptConfirmation:
    """Test prompt_confirmation function"""

    @patch("builtins.input")
    @patch("builtins.print")
    def test_yes_confirmation(self, mock_print, mock_input):
        """Test 'yes' returns True"""
        mock_input.return_value = "yes"

        result = prompt_confirmation("Confirm? (yes/no): ")

        assert result is True
        mock_print.assert_not_called()

    @patch("builtins.input")
    @patch("builtins.print")
    def test_no_confirmation(self, mock_print, mock_input):
        """Test 'no' returns False"""
        mock_input.return_value = "no"

        result = prompt_confirmation("Confirm? (yes/no): ")

        assert result is False
        mock_print.assert_not_called()

    @patch("builtins.input")
    @patch("builtins.print")
    def test_case_insensitive_yes(self, mock_print, mock_input):
        """Test case insensitive 'yes'"""
        mock_input.return_value = "YES"

        result = prompt_confirmation("Confirm? (yes/no): ")

        assert result is True

    @patch("builtins.input")
    @patch("builtins.print")
    def test_case_insensitive_no(self, mock_print, mock_input):
        """Test case insensitive 'no'"""
        mock_input.return_value = "NO"

        result = prompt_confirmation("Confirm? (yes/no): ")

        assert result is False

    @patch("builtins.input")
    @patch("builtins.print")
    def test_invalid_confirmation(self, mock_print, mock_input):
        """Test invalid confirmation input"""
        mock_input.side_effect = ["maybe", "yes"]

        result = prompt_confirmation("Confirm? (yes/no): ")

        assert result is True
        assert mock_print.call_count == 1
        error_msg = str(mock_print.call_args[0][0])
        assert "yes or no" in error_msg.lower()

    @patch("builtins.input")
    def test_exit_on_confirmation(self, mock_input):
        """Test exit on confirmation"""
        mock_input.return_value = "exit"

        with pytest.raises(CancelInputException):
            prompt_confirmation("Confirm? (yes/no): ")


# ============================================================================
# prompt_optional_field Tests
# ============================================================================


@pytest.mark.unit
class TestPromptOptionalField:
    """Test prompt_optional_field function"""

    @patch("builtins.input")
    @patch("builtins.print")
    def test_skip_with_enter(self, mock_print, mock_input):
        """Test skipping field with empty input"""
        mock_input.return_value = ""

        result = prompt_optional_field("New email", validate_email)

        assert result is None
        mock_print.assert_not_called()

    @patch("builtins.input")
    @patch("builtins.print")
    def test_skip_with_whitespace(self, mock_print, mock_input):
        """Test skipping field with whitespace"""
        mock_input.return_value = "   "

        result = prompt_optional_field("New email", validate_email)

        assert result is None

    @patch("builtins.input")
    @patch("builtins.print")
    def test_provide_new_value(self, mock_print, mock_input):
        """Test providing new value"""
        mock_input.return_value = "new@example.com"

        result = prompt_optional_field("New email", validate_email)

        assert result == "new@example.com"
        mock_print.assert_not_called()

    @patch("builtins.input")
    @patch("builtins.print")
    def test_show_current_value(self, mock_print, mock_input):
        """Test that current value is shown in prompt"""
        mock_input.return_value = ""

        with patch("builtins.input", return_value="") as mock_input:
            result = prompt_optional_field(
                "New email", validate_email, current_value="old@example.com"
            )

            # Check that prompt includes current value
            prompt_text = mock_input.call_args[0][0]
            assert "old@example.com" in prompt_text
            assert "Enter to skip" in prompt_text

    @patch("builtins.input")
    @patch("builtins.print")
    def test_invalid_then_valid(self, mock_print, mock_input):
        """Test validation retry on optional field"""
        mock_input.side_effect = ["invalid", "new@example.com"]

        result = prompt_optional_field("New email", validate_email)

        assert result == "new@example.com"
        assert mock_print.call_count == 1

    @patch("builtins.input")
    def test_exit_on_optional_field(self, mock_input):
        """Test exit on optional field"""
        mock_input.return_value = "exit"

        with pytest.raises(CancelInputException):
            prompt_optional_field("New email", validate_email)

    @patch("builtins.input")
    @patch("builtins.print")
    def test_optional_field_disabled_exit(self, mock_print, mock_input):
        """Test optional field with exit disabled"""
        mock_input.side_effect = ["exit", ""]

        # 'exit' should fail validation, then skip with empty
        result = prompt_optional_field("New email", validate_email, allow_exit=False)

        assert result is None
        assert mock_print.call_count == 1


# ============================================================================
# prompt_choice_from_list Tests
# ============================================================================


@pytest.mark.unit
class TestPromptChoiceFromList:
    """Test prompt_choice_from_list function"""

    @patch("builtins.input")
    @patch("builtins.print")
    def test_select_first_option(self, mock_print, mock_input):
        """Test selecting first option"""
        mock_input.return_value = "1"
        options = ["Option A", "Option B", "Option C"]

        result = prompt_choice_from_list("Select option:", options)

        assert result == "Option A"

    @patch("builtins.input")
    @patch("builtins.print")
    def test_select_last_option(self, mock_print, mock_input):
        """Test selecting last option"""
        mock_input.return_value = "3"
        options = ["Option A", "Option B", "Option C"]

        result = prompt_choice_from_list("Select option:", options)

        assert result == "Option C"

    @patch("builtins.input")
    @patch("builtins.print")
    def test_display_all_options(self, mock_print, mock_input):
        """Test that all options are displayed"""
        mock_input.return_value = "2"
        options = ["Red", "Green", "Blue"]

        result = prompt_choice_from_list("Select color:", options)

        # Verify all options were printed
        print_calls = [str(call) for call in mock_print.call_args_list]
        output = " ".join(print_calls)
        assert "Red" in output
        assert "Green" in output
        assert "Blue" in output

    @patch("builtins.input")
    @patch("builtins.print")
    def test_invalid_choice_then_valid(self, mock_print, mock_input):
        """Test invalid choice followed by valid"""
        mock_input.side_effect = ["5", "2"]
        options = ["Option A", "Option B", "Option C"]

        result = prompt_choice_from_list("Select option:", options)

        assert result == "Option B"

    @patch("builtins.input")
    def test_exit_on_list_choice(self, mock_input):
        """Test exit on list choice"""
        mock_input.return_value = "cancel"
        options = ["Option A", "Option B"]

        with pytest.raises(CancelInputException):
            prompt_choice_from_list("Select option:", options)

    @patch("builtins.input")
    @patch("builtins.print")
    def test_two_item_list(self, mock_print, mock_input):
        """Test with two-item list (like gender)"""
        mock_input.return_value = "1"
        options = ["Male", "Female"]

        result = prompt_choice_from_list("Select gender:", options)

        assert result == "Male"

    @patch("builtins.input")
    @patch("builtins.print")
    def test_large_list(self, mock_print, mock_input):
        """Test with larger list (like cities)"""
        mock_input.return_value = "5"
        options = ["Amsterdam", "Rotterdam", "Utrecht", "Den Haag", "Eindhoven"]

        result = prompt_choice_from_list("Select city:", options)

        assert result == "Eindhoven"


# ============================================================================
# Integration-style Tests
# ============================================================================


@pytest.mark.unit
class TestInputHandlersIntegration:
    """Test realistic usage patterns"""

    @patch("builtins.input")
    @patch("builtins.print")
    def test_form_completion_with_exit_midway(self, mock_print, mock_input):
        """Test user completing part of form then exiting"""
        # Simulate filling email, then exiting on confirmation
        mock_input.side_effect = ["user@example.com", "exit"]

        # First field succeeds
        email = prompt_with_validation("Email: ", validate_email)
        assert email == "user@example.com"

        # Second field exits
        with pytest.raises(CancelInputException):
            prompt_confirmation("Continue? (yes/no): ")

    @patch("builtins.input")
    @patch("builtins.print")
    def test_multiple_validation_retries_then_success(self, mock_print, mock_input):
        """Test realistic scenario of multiple failed attempts"""
        # User tries several bad emails, then gets it right
        mock_input.side_effect = [
            "plaintext",
            "@nodomain",
            "no@domain",
            "user@example.com",
        ]

        result = prompt_with_validation("Email: ", validate_email)

        assert result == "user@example.com"
        assert mock_print.call_count == 3  # Three error messages

    @patch("builtins.input")
    @patch("builtins.print")
    def test_update_form_skip_all_fields(self, mock_print, mock_input):
        """Test skipping all optional fields in update form"""
        # User presses Enter on all optional fields
        mock_input.side_effect = ["", "", ""]

        email = prompt_optional_field("New email", validate_email)
        phone = prompt_optional_field("New phone", lambda x: x)
        name = prompt_optional_field("New name", lambda x: x)

        assert email is None
        assert phone is None
        assert name is None
