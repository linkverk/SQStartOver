# ═══════════════════════════════════════════════════════════════════════════
# INPUT HANDLERS - Prompt functions with validation and exit support
# ═══════════════════════════════════════════════════════════════════════════

from validation import ValidationError
import re


class CancelInputException(Exception):
    """Raised when user types 'exit' or 'cancel' to abort input."""
    pass


# ═══════════════════════════════════════════════════════════════════════════
# VALIDATION INPUT PROMPTS
# ═══════════════════════════════════════════════════════════════════════════


def prompt_with_validation(prompt_text, validator_func, allow_exit=True):
    """Prompt user for input with immediate validation loop and exit support."""
    while True:
        user_input = input(prompt_text)
        if allow_exit and user_input.strip().lower() in ["exit", "cancel"]:
            raise CancelInputException("User cancelled input")
        try:
            validated_value = validator_func(user_input)
            return validated_value
        except ValidationError as e:
            print(f"❌ Error: {e}\n")


def prompt_integer_with_validation(prompt_text, validator_func, allow_exit=True):
    """Prompt user for integer input with validation."""
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


def prompt_password_with_confirmation(prompt_text, validator_func, current_password=None, allow_exit=True):
    """Prompt for password with validation and confirmation."""
    while True:
        password = prompt_with_validation(prompt_text, validator_func, allow_exit)
        if current_password is not None and password == current_password:
            print("\n❌ New password must be different from current password.\nPlease try again.\n")
            continue
        confirm = input("Confirm password: ")
        if allow_exit and confirm.strip().lower() in ["exit", "cancel"]:
            raise CancelInputException("User cancelled input")
        if not confirm:
            print("\n❌ Confirmation password cannot be empty.\nPlease try again.\n")
            continue
        if password != confirm:
            print("\n❌ Passwords do not match.\nPlease try again.\n")
            continue
        return password


# ═══════════════════════════════════════════════════════════════════════════
# MENU & CHOICE PROMPTS
# ═══════════════════════════════════════════════════════════════════════════


def prompt_menu_choice(prompt_text, min_choice, max_choice, allow_exit=True):
    """Prompt user for menu choice with validation."""
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
    """Prompt user for yes/no confirmation."""
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


def prompt_optional_field(prompt_text, validator_func, current_value=None, allow_exit=True):
    """Prompt for optional field update. Enter to skip, exit to cancel."""
    if current_value:
        full_prompt = f"{prompt_text} [{current_value}] (Enter to skip, 'exit' to cancel): "
    else:
        full_prompt = f"{prompt_text} (Enter to skip, 'exit' to cancel): "

    while True:
        user_input = input(full_prompt)
        if not user_input.strip():
            return None
        if allow_exit and user_input.strip().lower() in ["exit", "cancel"]:
            raise CancelInputException("User cancelled input")
        try:
            validated_value = validator_func(user_input)
            return validated_value
        except ValidationError as e:
            print(f"❌ Error: {e}\n")


def prompt_choice_from_list(prompt_text, options, allow_exit=True):
    """Prompt user to select from a numbered list of options."""
    print(f"\n{prompt_text}")
    for i, option in enumerate(options, 1):
        print(f"  {i}) {option}")
    choice = prompt_menu_choice(f"Enter choice (1-{len(options)}): ", 1, len(options), allow_exit)
    return options[int(choice) - 1]
