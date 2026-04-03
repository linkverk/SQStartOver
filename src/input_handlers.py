# ═══════════════════════════════════════════════════════════════════════════
# IMPORTS & EXCEPTIONS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Core imports and custom exception classes
#
# Key components:
# - ValidationError: Import from validation module
# - CancelInputException: Custom exception for user cancellation
#
# Note: CancelInputException is raised when user types 'exit' or 'cancel'
#       to abort input. All prompt functions support this mechanism.
# ═══════════════════════════════════════════════════════════════════════════

from validation import ValidationError
import re


class CancelInputException(Exception):
    """Raised when user types 'exit' or 'cancel' to abort input."""
    pass


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: VALIDATION INPUT PROMPTS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Input prompt functions with immediate validation feedback
#
# Key components:
# - prompt_with_validation(): Generic validation prompt with retry loop
# - prompt_integer_with_validation(): Integer-specific validation prompt
# - prompt_password_with_confirmation(): Password entry with confirm step
#
# Features:
# - Immediate validation with error feedback
# - Support for 'exit' or 'cancel' commands (case-insensitive)
# - Automatic retry loop until valid input or cancellation
# - Shows validation error messages
# ═══════════════════════════════════════════════════════════════════════════


def prompt_with_validation(prompt_text, validator_func, allow_exit=True):
    """
    Prompt user for input with immediate validation loop and exit support.

    Args:
        prompt_text (str): Text to show to user (e.g., "Email: ")
        validator_func (callable): Validation function from validation.py
        allow_exit (bool): If True, user can type 'exit' or 'cancel' to abort

    Returns:
        Validated value (type depends on validator function)

    Raises:
        CancelInputException: If user types 'exit' or 'cancel' and allow_exit=True

    Example:
        try:
            email = prompt_with_validation("Email: ", validate_email)
        except CancelInputException:
            print("Operation cancelled")
    """
    while True:
        user_input = input(prompt_text)

        # Check for exit/cancel commands (case-insensitive)
        if allow_exit and user_input.strip().lower() in ["exit", "cancel"]:
            raise CancelInputException("User cancelled input")

        try:
            validated_value = validator_func(user_input)
            return validated_value
        except ValidationError as e:
            print(f"❌ Error: {e}\n")


def prompt_integer_with_validation(prompt_text, validator_func, allow_exit=True):
    """
    Prompt user for integer input with immediate validation loop.

    Similar to prompt_with_validation but handles integer conversion.

    Args:
        prompt_text (str): Text to show to user
        validator_func (callable): Validation function that accepts int or str
        allow_exit (bool): If True, user can type 'exit' or 'cancel' to abort

    Returns:
        int: Validated integer value

    Raises:
        CancelInputException: If user types 'exit' or 'cancel' and allow_exit=True
    """
    while True:
        user_input = input(prompt_text)

        if allow_exit and user_input.strip().lower() in ["exit", "cancel"]:
            raise CancelInputException("User cancelled input")

        try:
            validated_value = validator_func(user_input)
            return validated_value
        except ValidationError as e:
            print(f"❌ Error: {e}\n")
        except ValueError:
            print("❌ Error: Please enter a valid number\n")


def prompt_password_with_confirmation(prompt_text, validator_func,
                                       current_password=None, allow_exit=True):
    """
    Prompt user for password with validation and confirmation.

    Flow:
    1. Prompt for password with validation
    2. Check if different from current password (if provided)
    3. Prompt for confirmation
    4. Validate confirmation matches
    5. Retry on any error

    Args:
        prompt_text (str): Text for password prompt
        validator_func (callable): Validation function for password format
        current_password (str, optional): Current password to compare against
        allow_exit (bool): If True, user can type 'exit' or 'cancel' to abort

    Returns:
        str: Validated and confirmed password

    Raises:
        CancelInputException: If user types 'exit' or 'cancel' and allow_exit=True
    """
    while True:
        password = prompt_with_validation(prompt_text, validator_func, allow_exit)

        if current_password is not None and password == current_password:
            print("\n❌ New password must be different from current password.")
            print("Please try again.\n")
            continue

        confirm = input("Confirm password: ")

        if allow_exit and confirm.strip().lower() in ["exit", "cancel"]:
            raise CancelInputException("User cancelled input")

        if not confirm:
            print("\n❌ Confirmation password cannot be empty.")
            print("Please try again.\n")
            continue

        if password != confirm:
            print("\n❌ Passwords do not match.")
            print("Please try again.\n")
            continue

        return password


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: MENU & CHOICE PROMPTS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Menu navigation and user choice prompt functions
#
# Key components:
# - prompt_menu_choice(): Numbered menu choice validation (range check)
# - prompt_confirmation(): Yes/no confirmation prompts
# - prompt_optional_field(): Optional field updates with skip support
# - prompt_choice_from_list(): Select from numbered list of options
#
# Features:
# - Range validation for menu choices
# - Yes/no confirmation with retry on invalid input
# - Optional field support (Enter to skip, exit to cancel)
# - Automatic numbering and display for list choices
# ═══════════════════════════════════════════════════════════════════════════


def prompt_menu_choice(prompt_text, min_choice, max_choice, allow_exit=True):
    """
    Prompt user for menu choice with validation and exit support.

    Args:
        prompt_text (str): Text to show (e.g., "Enter choice (1-5): ")
        min_choice (int): Minimum valid choice number
        max_choice (int): Maximum valid choice number
        allow_exit (bool): If True, user can type 'exit' or 'cancel' to abort

    Returns:
        str: The validated choice as a string (e.g., "1", "2")

    Raises:
        CancelInputException: If user types 'exit' or 'cancel' and allow_exit=True
    """
    while True:
        user_input = input(prompt_text)

        if allow_exit and user_input.strip().lower() in ["exit", "cancel"]:
            raise CancelInputException("User cancelled input")

        try:
            choice_num = int(user_input)
        except ValueError:
            print("❌ Error: Invalid choice\n")
            continue

        if choice_num < min_choice or choice_num > max_choice:
            print("❌ Error: Invalid choice\n")
            continue

        return user_input


def prompt_confirmation(prompt_text, allow_exit=True):
    """
    Prompt user for yes/no confirmation with validation.

    Args:
        prompt_text (str): Confirmation question
        allow_exit (bool): If True, user can type 'exit' or 'cancel' to abort

    Returns:
        bool: True if user entered 'yes'/'y', False if 'no'/'n'

    Raises:
        CancelInputException: If user types 'exit' or 'cancel' and allow_exit=True
    """
    while True:
        user_input = input(prompt_text).strip().lower()

        if allow_exit and user_input in ["exit", "cancel"]:
            raise CancelInputException("User cancelled input")

        if user_input in ["yes", "y"]:
            return True
        elif user_input in ["no", "n"]:
            return False
        else:
            print("❌ Error: Please enter yes or no.\n")


def prompt_optional_field(prompt_text, validator_func, current_value=None,
                          allow_exit=True):
    """
    Prompt for optional field update with skip, exit, or validate.

    Shows instructions for skipping (Enter), exiting (exit/cancel),
    or entering a new value. Validates input only if user provides one.

    Args:
        prompt_text (str): Base prompt text (e.g., "New email")
        validator_func (callable): Validation function to use if input provided
        current_value (str, optional): Current value to show in brackets
        allow_exit (bool): If True, user can type 'exit' or 'cancel' to abort

    Returns:
        str or None: Validated new value, or None if user skipped (pressed Enter)

    Raises:
        CancelInputException: If user types 'exit' or 'cancel' and allow_exit=True
    """
    if current_value:
        full_prompt = f"{prompt_text} [{current_value}] (Enter to skip, 'exit' to cancel): "
    else:
        full_prompt = f"{prompt_text} (Enter to skip, 'exit' to cancel): "

    while True:
        user_input = input(full_prompt)

        # Empty input — skip this field
        if not user_input.strip():
            return None

        # Check for exit/cancel commands
        if allow_exit and user_input.strip().lower() in ["exit", "cancel"]:
            raise CancelInputException("User cancelled input")

        # Validate the input
        try:
            validated_value = validator_func(user_input)
            return validated_value
        except ValidationError as e:
            print(f"❌ Error: {e}\n")


def prompt_choice_from_list(prompt_text, options, allow_exit=True):
    """
    Prompt user to select from a numbered list of options.

    Displays options with numbers and validates the selection.

    Args:
        prompt_text (str): Text to show before the list
        options (list): List of option strings to display and choose from
        allow_exit (bool): If True, user can type 'exit' or 'cancel' to abort

    Returns:
        str: The selected option string from the list

    Raises:
        CancelInputException: If user types 'exit' or 'cancel' and allow_exit=True

    Example:
        gender = prompt_choice_from_list("Select gender:", ["Male", "Female"])
        city = prompt_choice_from_list("Select city:", VALID_CITIES)
    """
    print(f"\n{prompt_text}")
    for i, option in enumerate(options, 1):
        print(f"  {i}) {option}")

    choice = prompt_menu_choice(f"Enter choice (1-{len(options)}): ",
                                 1, len(options), allow_exit)
    return options[int(choice) - 1]
