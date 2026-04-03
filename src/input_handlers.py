# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: IMPORTS & EXCEPTIONS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Core imports and custom exception classes
#
# Key components:
# - ValidationError: Import from validation module
# - CancelInputException: Custom exception for user cancellation
#
# Note: CancelInputException is raised when user types 'exit' or 'cancel'
# ═══════════════════════════════════════════════════════════════════════════

from validation import ValidationError
import re


class CancelInputException(Exception):
    """Raised when user types 'exit' or 'cancel' to abort input."""

    pass


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: VALIDATION INPUT PROMPTS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Input prompt functions with immediate validation feedback
#
# Key components:
# - prompt_with_validation(): Generic validation prompt with retry loop
# - prompt_integer_with_validation(): Integer-specific validation prompt
#
# Features:
# - Immediate validation with error feedback
# - Support for 'exit' or 'cancel' commands
# - Automatic retry loop until valid input or cancellation
# - Shows validation error messages with examples
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
            return
    """
    while True:
        user_input = input(prompt_text)

        # Check for exit/cancel commands
        if allow_exit and user_input in ["exit", "Exit", "EXIT", "cancel", "Cancel", "CANCEL"]:
            raise CancelInputException("User cancelled input")

        try:
            # Call validator function
            validated_value = validator_func(user_input)
            return validated_value
        except ValidationError as e:
            # Show error with example and repeat the prompt
            print(f"❌ Error: {e}\n")


def prompt_integer_with_validation(prompt_text, validator_func, allow_exit=True):
    """
    Prompt user for integer input with immediate validation loop and exit support.

    Similar to prompt_with_validation but handles integer conversion
    and validation (e.g., battery level, house number).

    Args:
        prompt_text (str): Text to show to user
        validator_func (callable): Validation function that accepts int or str
        allow_exit (bool): If True, user can type 'exit' or 'cancel' to abort

    Returns:
        int: Validated integer value

    Raises:
        CancelInputException: If user types 'exit' or 'cancel' and allow_exit=True

    Example:
        try:
            battery = prompt_integer_with_validation("Battery level (0-100): ", validate_battery_level)
        except CancelInputException:
            print("Operation cancelled")
            return
    """
    while True:
        user_input = input(prompt_text)

        # Check for exit/cancel commands
        if allow_exit and user_input in ["exit", "Exit", "EXIT", "cancel", "Cancel", "CANCEL"]:
            raise CancelInputException("User cancelled input")

        try:
            # Validator will handle conversion and range checking
            validated_value = validator_func(user_input)
            return validated_value
        except ValidationError as e:
            print(f"❌ Error: {e}\n")
        except ValueError:
            print(f"❌ Error: Please enter a valid number\n")


def prompt_password_with_confirmation(
    prompt_text, validator_func, current_password=None, allow_exit=True
):
    """
    Prompt user for password with validation and confirmation.

    Handles the complete password entry flow:
    1. Prompts for password with validation
    2. Checks if different from current password (if provided)
    3. Prompts for confirmation
    4. Validates confirmation matches
    5. Retries on any error

    Args:
        prompt_text (str): Text to show for password prompt (e.g., "Enter new password: ")
        validator_func (callable): Validation function for password format
        current_password (str, optional): Current password to compare against
        allow_exit (bool): If True, user can type 'exit' or 'cancel' to abort

    Returns:
        str: Validated and confirmed password

    Raises:
        CancelInputException: If user types 'exit' or 'cancel' and allow_exit=True

    Example:
        try:
            new_pwd = prompt_password_with_confirmation(
                "Enter new password: ",
                validate_password,
                current_password="old_password"
            )
        except CancelInputException:
            print("Password change cancelled")
            return
    """
    while True:
        # Step 1: Get password with validation
        password = prompt_with_validation(prompt_text, validator_func, allow_exit)

        # Step 2: Check if different from current password (if provided)
        if current_password is not None and password == current_password:
            print("\n❌ New password must be different from current password.")
            print("Please try again.\n")
            continue

        # Step 3: Get confirmation
        confirm = input("Confirm password: ")

        # Check for exit/cancel
        if allow_exit and confirm in ["exit", "Exit", "EXIT", "cancel", "Cancel", "CANCEL"]:
            raise CancelInputException("User cancelled input")

        # Step 4: Validate confirmation
        if not confirm:
            print("\n❌ Confirmation password cannot be empty.")
            print("Please try again.\n")
            continue

        if password != confirm:
            print("\n❌ Passwords do not match.")
            print("Please try again.\n")
            continue

        # All validations passed
        return password


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: MENU & CHOICE PROMPTS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Menu navigation and user choice prompt functions
#
# Key components:
# - prompt_menu_choice(): Numbered menu choice validation
# - prompt_confirmation(): Yes/no confirmation prompts
# - prompt_optional_field(): Optional field updates with skip support
# - prompt_choice_from_list(): Select from numbered list of options
#
# Features:
# - Range validation for menu choices
# - Yes/no confirmation with validation
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

    Example:
        try:
            choice = prompt_menu_choice("Enter choice (1-6): ", 1, 6)
            if choice == "1":
                # Handle option 1
        except CancelInputException:
            print("Returning to main menu")
            return
    """
    while True:
        user_input = input(prompt_text)

        # Check for exit/cancel commands
        if allow_exit and user_input in ["exit", "Exit", "EXIT", "cancel", "Cancel", "CANCEL"]:
            raise CancelInputException("User cancelled input")

        # Validate it's a number
        try:
            choice_num = int(user_input)
        except ValueError:
            print(f"❌ Error: Invalid choice\n")
            continue

        # Validate it's in range
        if choice_num < min_choice or choice_num > max_choice:
            print(f"❌ Error: Invalid choice\n")
            continue

        # Valid choice
        return user_input


def prompt_confirmation(prompt_text, allow_exit=True):
    """
    Prompt user for yes/no confirmation with validation.

    Args:
        prompt_text (str): Confirmation question (e.g., "Are you sure? (yes/no): ")
        allow_exit (bool): If True, user can type 'exit' or 'cancel' to abort

    Returns:
        bool: True if user entered 'yes', False if 'no'

    Raises:
        CancelInputException: If user types 'exit' or 'cancel' and allow_exit=True

    Example:
        try:
            if prompt_confirmation("Delete this user? (yes/no): "):
                # User confirmed - delete
            else:
                # User said no
        except CancelInputException:
            print("Operation cancelled")
            return
    """
    while True:
        user_input = input(prompt_text)

        # Check for exit/cancel commands
        if allow_exit and user_input in ["exit", "Exit", "EXIT", "cancel", "Cancel", "CANCEL"]:
            raise CancelInputException("User cancelled input")

        if user_input in ["yes", "Yes", "YES"]:
            return True
        elif user_input in ["no", "No", "NO"]:
            return False
        else:
            print(f"❌ Error: Invalid input.\n")


def prompt_optional_field(
    prompt_text, validator_func, current_value=None, allow_exit=True
):
    """
    Prompt for optional field update with skip, exit, or validate.

    Shows instructions for skipping (Enter), exiting (exit/cancel), or entering new value.
    Validates input only if user provides a non-empty value.

    Args:
        prompt_text (str): Base prompt text (e.g., "New email")
        validator_func (callable): Validation function to use if input provided
        current_value (str, optional): Current value to show in brackets
        allow_exit (bool): If True, user can type 'exit' or 'cancel' to abort

    Returns:
        str or None: Validated new value, or None if user skipped (pressed Enter)

    Raises:
        CancelInputException: If user types 'exit' or 'cancel' and allow_exit=True

    Example:
        try:
            new_email = prompt_optional_field("New email", validate_email, current_value="old@example.com")
            if new_email:
                # User provided new email - update it
            else:
                # User skipped - keep current value
        except CancelInputException:
            print("Update cancelled")
            return
    """
    # Build full prompt with instructions
    if current_value:
        full_prompt = (
            f"{prompt_text} [{current_value}] (Enter to skip, 'exit' to cancel): "
        )
    else:
        full_prompt = f"{prompt_text} (Enter to skip, 'exit' to cancel): "

    while True:
        user_input = input(full_prompt)

        # Empty input - skip this field
        if not user_input:
            return None

        # Check for exit/cancel commands
        if allow_exit and user_input in ["exit", "Exit", "EXIT", "cancel", "Cancel", "CANCEL"]:
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

    Args:
        prompt_text (str): Text to show before the list
        options (list): List of option strings to display and choose from
        allow_exit (bool): If True, user can type 'exit' or 'cancel' to abort

    Returns:
        str: The selected option string from the list

    Raises:
        CancelInputException: If user types 'exit' or 'cancel' and allow_exit=True

    Example:
        try:
            gender = prompt_choice_from_list("Select gender:", ["Male", "Female"])
            # gender will be "Male" or "Female"
        except CancelInputException:
            print("Selection cancelled")
            return
    """
    print(f"\n{prompt_text}")
    for i, option in enumerate(options, 1):
        print(f"  {i}) {option}")

    choice = prompt_menu_choice(
        f"Enter choice (1-{len(options)}): ", 1, len(options), allow_exit
    )
    return options[int(choice) - 1]

def validate_username_input(username):
    if not isinstance(username, str):
        return False

    #_check_null_bytes(username, "Username")

    # Special case: allow "super_admin" system account (bypasses length rule)
    if username == "super_admin":
        if not re.match(r"^[a-z_]", username):  # pragma: no cover
            return False
        if not re.match(r"^[a-z0-9_'.]+$", username):  # pragma: no cover
            return False
        return True

    # Validate length for regular users
    if len(username) < 8:
        return False
    if len(username) > 10:
        return False

    if not re.match(r"^[a-z_]", username):
        return False

    if not re.match(r"^[a-z0-9_'.]+$", username):
        return False

    return True

def validate_password_input(password):
    if not isinstance(password, str):
        return False

    #_check_null_bytes(password, "Password")

    if len(password) < 12:
        return False
    if len(password) > 30:
        return False

    if not re.search(r"[a-z]", password):
        return False
    
    if not re.search(r"[A-Z]", password):
        return False

    if not re.search(r"\d", password):
        return False
    if not re.search(r"[~!@#$%&_\-+=`|\\(){}[\]:;'<>,.?/]", password):
        return False

    return True

def validate_email_input(email):
    if not isinstance(email, str):
        return False

    #check_null_bytes(email, "Email")

    if len(email) > 50:
        return False

    email_pattern = r"^[a-z0-9._+-]+@[a-z0-9.-]+\.[a-z]{2,}$"

    if not re.match(email_pattern, email):
        return False

    return True

def validate_phone_input(phone): # TODO: hier nog ff naar kijken ook naar validate_phone functie
    if not isinstance(phone, str):
        return False

    #_check_null_bytes(phone, "Phone")

    # Accept already-formatted value (e.g. after a previous validate_phone call)
    if re.match(r"^\+31-6-\d{8}$", phone):
        return True

    # Validate: must be exactly 8 digits
    if not re.match(r"^\d{8}$", phone):
        return False

    return f"+31-6-{phone}"

def validate_customer_id_input(customer_id):
    if not isinstance(customer_id, str):
        return False

    if not customer_id.isdigit():
        return False

    if int(customer_id) < 1:
        return False

    return True

def validate_search_key_input(search_key):
    if not isinstance(search_key, str):
        return False

    #_check_null_bytes(search_key, "Search key")

    if (search_key not in ["brand", "Brand", "model", "Model", "GPS", "gps", "GPS coordinates", "gps coordinates"]):
        return False

    return True
