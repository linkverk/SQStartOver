# ═══════════════════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════════════════
# Description: All module imports for the Urban Mobility Backend System UI
#
# External libraries: os
# Internal modules: auth, users, travelers, scooters, activity_log, backup, validation, input_handlers
#
# All validation functions are actively used throughout the UI for:
# - Immediate user input validation with feedback loops
# - Cross-field validation (e.g., GPS coordinates, target SoC min/max)
# - Security protection (null-byte detection, format validation)
# - Data integrity enforcement before database operations
# ═══════════════════════════════════════════════════════════════════════════

import os

# Local imports
from auth import login, logout, get_current_user, update_password
from users import (
    create_system_admin,
    create_service_engineer,
    delete_user,
    list_all_users,
    reset_user_password,
    update_user_profile,
)
from travelers import (
    add_traveler,
    update_traveler,
    delete_traveler,
    search_travelers,
    get_traveler_by_id,
    list_all_travelers,
)
from scooters import (
    add_scooter,
    update_scooter,
    delete_scooter,
    search_scooters,
    get_scooter_by_serial,
    list_all_scooters,
)
from activity_log import (
    get_all_logs,
    display_logs,
    check_suspicious_activities,
)
from backup import (
    create_backup,
    restore_backup,
    generate_restore_code,
    revoke_restore_code,
    list_backups,
    list_restore_codes,
)
from validation import ValidationError, VALID_CITIES
from validation import (
    validate_email,
    validate_phone,
    validate_zipcode,
    validate_birthday,
    validate_driving_license,
    validate_name,
    validate_house_number,
    validate_username,
    validate_password,
    validate_serial_number,
    validate_brand,
    validate_model,
    validate_top_speed,
    validate_battery_capacity,
    validate_state_of_charge,
    validate_target_range_soc,
    validate_gps_location,
    validate_out_of_service_status,
    validate_mileage,
    validate_date,
    validate_city,
    validate_float,
    validate_nonempty,
)
from input_handlers import (
    CancelInputException,
    prompt_with_validation,
    prompt_integer_with_validation,
    prompt_password_with_confirmation,
    prompt_menu_choice,
    prompt_confirmation,
    prompt_optional_field,
    prompt_choice_from_list,
    validate_phone_input,
    validate_email_input,
    validate_password_input,
    validate_username_input,
    validate_customer_id_input,
    validate_search_key_input,
)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Helper functions for user interface operations
#
# Key components:
# - clear_screen(): Cross-platform screen clearing
# - print_header(): Formatted section headers
# - print_user_info(): Display current logged-in user
# - wait_for_enter(): Input blocking for user interaction
# - validate_unique_username(): Check username uniqueness
# - validate_unique_serial_number(): Check scooter serial uniqueness
#
# Note: Input validation functions (prompt_with_validation, etc.) are imported from input_handlers
# ═══════════════════════════════════════════════════════════════════════════


def clear_screen():
    """Clear console screen for better UX."""
    os.system("cls" if os.name == "nt" else "clear")


def print_header(title):
    """
    Print formatted header.

    Args:
        title (str): Header title
    """
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_user_info():
    """Print current user information."""
    user = get_current_user()
    if user:
        print(f"\nLogged in as: {user['username']} ({user['role_name']})")


def wait_for_enter():
    """Wait for user to press Enter."""
    input("\nPress Enter to continue...")


def validate_unique_username(username):
    """
    Validate username and check if it doesn't already exist.

    Args:
        username (str): Username to validate

    Returns:
        str: Validated username

    Raises:
        ValidationError: If username is invalid or already exists
    """
    # First do normal validation
    username = validate_username(username)

    # Then check if it exists
    all_users = list_all_users()
    for user in all_users:
        if user["username"] == username:
            raise ValidationError(f"Username '{username}' already exists")

    return username


def validate_unique_serial_number(serial_number):
    """
    Validate serial number and check if it doesn't already exist.

    Args:
        serial_number (str): Serial number to validate

    Returns:
        str: Validated serial number

    Raises:
        ValidationError: If serial number is invalid or already exists
    """
    # First do normal validation
    serial_number = validate_serial_number(serial_number)

    # Then check if it exists
    scooter = get_scooter_by_serial(serial_number)
    if scooter:
        raise ValidationError(f"Serial number '{serial_number}' already exists")

    return serial_number


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: MENU SYSTEMS & NAVIGATION
# ═══════════════════════════════════════════════════════════════════════════
# Description: Main menu and submenu functions for navigation
#
# Key components:
# - show_main_menu(): Role-based main menu display (Super Admin, System Admin, Service Engineer)
# - manage_system_admins_menu(): System Administrator management submenu
# - manage_service_engineers_menu(): Service Engineer management submenu
# - manage_travelers_menu(): Traveler/customer management submenu
# - manage_scooters_menu(): Scooter fleet management submenu (Admin/Super Admin)
# - service_engineer_scooter_menu(): Limited scooter menu for Service Engineers
# ═══════════════════════════════════════════════════════════════════════════


def show_main_menu():
    """
    Display main menu based on user role.

    Different menus for Super Admin, System Admin, and Service Engineer.
    """
    user = get_current_user()

    if not user:
        return False

    clear_screen()
    print_header("URBAN MOBILITY BACKEND SYSTEM")
    print_user_info()

    # Check for suspicious activities (Assignment requirement)
    suspicious_count = check_suspicious_activities()
    if suspicious_count > 0:
        print(f"\n⚠️  WARNING: {suspicious_count} suspicious activities detected!")
        print("   Check system logs for details.")

    print("\nMAIN MENU:")

    if user["role"] == "super_admin":
        # Super Admin menu
        print("  1. Manage System Administrators")
        print("  2. Manage Service Engineers")
        print("  3. Manage Travelers")
        print("  4. Manage Scooters")
        print("  5. View System Logs")
        print("  6. Backup & Restore")
        print("  7. View My Profile")
        print("  8. Logout")

    elif user["role"] == "system_admin":
        # System Admin menu
        print("  1. Manage Service Engineers")
        print("  2. Manage Travelers")
        print("  3. Manage Scooters")
        print("  4. View System Logs")
        print("  5. Backup & Restore")
        print("  6. View My Profile")
        print("  7. Update My Password")
        print("  8. Logout")

    elif user["role"] == "service_engineer":
        # Service Engineer menu
        print("  1. Update Scooter Information")
        print("  2. Search Scooters")
        print("  3. View My Profile")
        print("  4. Update My Password")
        print("  5. Logout")

    print("\n" + "-" * 70)
    return True


def manage_system_admins_menu():
    """Menu for managing System Administrators."""
    while True:
        clear_screen()
        print_header("MANAGE SYSTEM ADMINISTRATORS")
        print_user_info()

        print("\n1. Create New System Administrator")
        print("2. List All System Administrators")
        print("3. Reset Admin Password")
        print("4. Update Admin Profile")
        print("5. Delete System Administrator")
        print("6. Back to Main Menu")

        try:
            choice = prompt_menu_choice("\nEnter choice (1-6): ", 1, 6)
        except CancelInputException:
            break

        if choice == "1":
            create_system_admin_ui()
        elif choice == "2":
            list_system_admins_ui()
        elif choice == "3":
            reset_admin_password_ui()
        elif choice == "4":
            update_admin_profile_ui()
        elif choice == "5":
            delete_system_admin_ui()
        elif choice == "6":
            break


def manage_service_engineers_menu():
    """Menu for managing Service Engineers."""
    while True:
        clear_screen()
        print_header("MANAGE SERVICE ENGINEERS")
        print_user_info()

        print("\n1. Create New Service Engineer")
        print("2. List All Service Engineers")
        print("3. Reset Engineer Password")
        print("4. Update Engineer Profile")
        print("5. Delete Service Engineer")
        print("6. Back to Main Menu")

        try:
            choice = prompt_menu_choice("\nEnter choice (1-6): ", 1, 6)
        except CancelInputException:
            break

        if choice == "1":
            create_service_engineer_ui()
        elif choice == "2":
            list_service_engineers_ui()
        elif choice == "3":
            reset_engineer_password_ui()
        elif choice == "4":
            update_engineer_profile_ui()
        elif choice == "5":
            delete_service_engineer_ui()
        elif choice == "6":
            break


def manage_travelers_menu():
    """Menu for managing Travelers."""
    while True:
        clear_screen()
        print_header("MANAGE TRAVELERS")
        print_user_info()

        print("\n1. Add New Traveler")
        print("2. Search Travelers")
        print("3. List All Travelers")
        print("4. Update Traveler Information")
        print("5. Delete Traveler")
        print("6. Back to Main Menu")

        try:
            choice = prompt_menu_choice("\nEnter choice (1-6): ", 1, 6)
        except CancelInputException:
            break

        if choice == "1":
            add_traveler_ui()
        elif choice == "2":
            search_travelers_ui()
        elif choice == "3":
            list_travelers_ui()
        elif choice == "4":
            update_traveler_ui()
        elif choice == "5":
            delete_traveler_ui()
        elif choice == "6":
            break


def manage_scooters_menu():
    """Menu for managing Scooters."""
    while True:
        clear_screen()
        print_header("MANAGE SCOOTERS")
        print_user_info()

        print("\n1. Add New Scooter")
        print("2. Search Scooters")
        print("3. List All Scooters")
        print("4. Update Scooter Information")
        print("5. Delete Scooter")
        print("6. Back to Main Menu")

        try:
            choice = prompt_menu_choice("\nEnter choice (1-6): ", 1, 6)
        except CancelInputException:
            break

        if choice == "1":
            add_scooter_ui()
        elif choice == "2":
            search_scooters_ui()
        elif choice == "3":
            list_scooters_ui()
        elif choice == "4":
            update_scooter_ui()
        elif choice == "5":
            delete_scooter_ui()
        elif choice == "6":
            break


def service_engineer_scooter_menu():
    """Simplified scooter menu for Service Engineers."""
    while True:
        clear_screen()
        print_header("UPDATE SCOOTER INFORMATION")
        print_user_info()

        print("\n1. Update Scooter")
        print("2. Back to Main Menu")

        try:
            choice = prompt_menu_choice("\nEnter choice (1-2): ", 1, 2)
        except CancelInputException:
            break

        if choice == "1":
            update_scooter_engineer_ui()
        elif choice == "2":
            break


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: SYSTEM ADMINISTRATOR UI
# ═══════════════════════════════════════════════════════════════════════════
# Description: User interface functions for System Administrator management
#
# Key components:
# - create_system_admin_ui(): Create new System Admin with validation
# - list_system_admins_ui(): Display all System Administrators
# - reset_admin_password_ui(): Reset System Admin password
# - update_admin_profile_ui(): Update System Admin name
# - delete_system_admin_ui(): Delete System Admin with confirmation
#
# Note: Only accessible by Super Admin role
# ═══════════════════════════════════════════════════════════════════════════


def create_system_admin_ui():
    """Create new System Administrator with per-field validation."""
    clear_screen()
    print_header("CREATE NEW SYSTEM ADMINISTRATOR")
    print_user_info()

    print("\nEnter System Administrator information:")
    print("\nUsername requirements:")
    print("  - Length: 8-10 characters")
    print("  - Start with letter or '_'")
    print("  - Can contain: a-z, 0-9, _, ', .")

    # Username - validated with immediate feedback including uniqueness check
    username = prompt_with_validation("\nEnter username: ", validate_unique_username)

    # First name - validated
    first_name = prompt_with_validation(
        "Enter first name: ", lambda x: validate_name(x, "First name")
    )

    # Last name - validated
    last_name = prompt_with_validation(
        "Enter last name: ", lambda x: validate_name(x, "Last name")
    )

    success, msg, temp_password = create_system_admin(username, first_name, last_name)

    print(f"\n{msg}")
    if success:
        print(f"Temporary password: {temp_password}")
        print("\n⚠️  IMPORTANT: Save this password! User must change it on first login.")

    wait_for_enter()


def list_system_admins_ui():
    """List all System Administrators."""
    clear_screen()
    print_header("SYSTEM ADMINISTRATORS")
    print_user_info()

    users = [u for u in list_all_users() if u["role"] == "system_admin"]

    if not users:
        print("\nNo System Administrators found.")
    else:
        print(f"\nTotal: {len(users)} System Administrator(s)")
        print("\n" + "-" * 70)
        for user in users:
            print(
                f"Username: {user['username']:15s} | Name: {user['first_name']} {user['last_name']}"
            )
            print(f"Created: {user['created_at']}")
            print("-" * 70)

    wait_for_enter()


def reset_admin_password_ui():
    """Reset System Administrator password."""
    clear_screen()
    print_header("RESET ADMIN PASSWORD")
    print_user_info()

    try:
        username = prompt_with_validation(
            "\nEnter admin username to reset: ", validate_nonempty
        )

        success, msg, temp_password = reset_user_password(username)

        print(f"\n{msg}")
        if success:
            print(f"New temporary password: {temp_password}")

    except CancelInputException:
        print("\nOperation cancelled.")

    wait_for_enter()


def update_admin_profile_ui():
    """Update System Administrator profile."""
    clear_screen()
    print_header("UPDATE ADMIN PROFILE")
    print_user_info()

    try:
        username = prompt_with_validation(
            "\nEnter admin username to update: ", validate_nonempty
        )

        all_users = list_all_users()
        admin = None
        for user in all_users:
            if user["username"] == username and user["role"] == "system_admin":
                admin = user
                break

        if not admin:
            print(f"\n❌ System Administrator '{username}' not found.")
            wait_for_enter()
            return

        first_name = prompt_optional_field(
            "New first name", lambda x: validate_name(x, "First name")
        )
        last_name = prompt_optional_field(
            "New last name", lambda x: validate_name(x, "Last name")
        )

        updates = {}
        if first_name:
            updates["first_name"] = first_name
        if last_name:
            updates["last_name"] = last_name

        if not updates:
            print("\nNo changes made.")
        else:
            success, msg = update_user_profile(username, **updates)
            print(f"\n{msg}")

    except CancelInputException:
        print("\nUpdate cancelled.")

    wait_for_enter()


def delete_system_admin_ui():
    """Delete System Administrator."""
    clear_screen()
    print_header("DELETE SYSTEM ADMINISTRATOR")
    print_user_info()

    try:
        username = prompt_with_validation(
            "\nEnter admin username to delete: ", validate_nonempty
        )

        # Check if user exists by trying to find them in the list
        all_users = list_all_users()
        user_to_delete = None
        for user in all_users:
            if user["username"] == username and user["role"] == "system_admin":
                user_to_delete = user
                break

        if not user_to_delete:
            print(f"\n❌ System Administrator '{username}' not found.")
            wait_for_enter()
            return

        # Show user information
        print(f"\n✓ System Administrator found:")
        print(f"  Username: {user_to_delete['username']}")
        print(f"  Name: {user_to_delete['first_name']} {user_to_delete['last_name']}")
        print(f"  Created: {user_to_delete['created_at']}")

        # Ask for confirmation
        if prompt_confirmation(
            f"\n⚠️  Are you sure you want to delete this user? (yes/no): "
        ):
            success, msg = delete_user(username)
            print(f"\n{msg}")
        else:
            print("\nDeletion cancelled.")

    except CancelInputException:
        print("\nOperation cancelled.")

    wait_for_enter()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: SERVICE ENGINEER UI
# ═══════════════════════════════════════════════════════════════════════════
# Description: User interface functions for Service Engineer management
#
# Key components:
# - create_service_engineer_ui(): Create new Service Engineer with validation
# - list_service_engineers_ui(): Display all Service Engineers
# - reset_engineer_password_ui(): Reset Service Engineer password
# - update_engineer_profile_ui(): Update Service Engineer name
# - delete_service_engineer_ui(): Delete Service Engineer with confirmation
#
# Note: Accessible by Super Admin and System Admin roles
# ═══════════════════════════════════════════════════════════════════════════


def create_service_engineer_ui():
    """Create new Service Engineer with per-field validation."""
    clear_screen()
    print_header("CREATE NEW SERVICE ENGINEER")
    print_user_info()

    print("\nEnter Service Engineer information:")
    print("\nUsername requirements:")
    print("  - Length: 8-10 characters")
    print("  - Start with letter or '_'")
    print("  - Can contain: a-z, 0-9, _, ', .")

    # Username - validated with immediate feedback including uniqueness check
    username = prompt_with_validation("\nEnter username: ", validate_unique_username)

    # First name - validated
    first_name = prompt_with_validation(
        "Enter first name: ", lambda x: validate_name(x, "First name")
    )

    # Last name - validated
    last_name = prompt_with_validation(
        "Enter last name: ", lambda x: validate_name(x, "Last name")
    )

    success, msg, temp_password = create_service_engineer(
        username, first_name, last_name
    )

    print(f"\n{msg}")
    if success:
        print(f"Temporary password: {temp_password}")
        print("\n⚠️  IMPORTANT: Save this password! User must change it on first login.")

    wait_for_enter()


def list_service_engineers_ui():
    """List all Service Engineers."""
    clear_screen()
    print_header("SERVICE ENGINEERS")
    print_user_info()

    users = [u for u in list_all_users() if u["role"] == "service_engineer"]

    if not users:
        print("\nNo Service Engineers found.")
    else:
        print(f"\nTotal: {len(users)} Service Engineer(s)")
        print("\n" + "-" * 70)
        for user in users:
            print(
                f"Username: {user['username']:15s} | Name: {user['first_name']} {user['last_name']}"
            )
            print(f"Created: {user['created_at']}")
            print("-" * 70)

    wait_for_enter()


def reset_engineer_password_ui():
    """Reset Service Engineer password."""
    clear_screen()
    print_header("RESET ENGINEER PASSWORD")
    print_user_info()

    try:
        username = prompt_with_validation(
            "\nEnter engineer username to reset: ", validate_nonempty
        )

        success, msg, temp_password = reset_user_password(username)

        print(f"\n{msg}")
        if success:
            print(f"New temporary password: {temp_password}")

    except CancelInputException:
        print("\nOperation cancelled.")

    wait_for_enter()


def update_engineer_profile_ui():
    """Update Service Engineer profile."""
    clear_screen()
    print_header("UPDATE ENGINEER PROFILE")
    print_user_info()

    try:
        username = prompt_with_validation(
            "\nEnter engineer username to update: ", validate_nonempty
        )

        # Check if engineer exists before asking for updates
        all_users = list_all_users()
        engineer = None
        for user in all_users:
            if user["username"] == username and user["role"] == "service_engineer":
                engineer = user
                break

        if not engineer:
            print(f"\n❌ Service Engineer '{username}' not found.")
            wait_for_enter()
            return

        first_name = prompt_optional_field(
            "New first name", lambda x: validate_name(x, "First name")
        )
        last_name = prompt_optional_field(
            "New last name", lambda x: validate_name(x, "Last name")
        )

        updates = {}
        if first_name:
            updates["first_name"] = first_name
        if last_name:
            updates["last_name"] = last_name

        if not updates:
            print("\nNo changes made.")
        else:
            success, msg = update_user_profile(username, **updates)
            print(f"\n{msg}")

    except CancelInputException:
        print("\nUpdate cancelled.")

    wait_for_enter()


def delete_service_engineer_ui():
    """Delete Service Engineer."""
    clear_screen()
    print_header("DELETE SERVICE ENGINEER")
    print_user_info()

    try:
        username = prompt_with_validation(
            "\nEnter engineer username to delete: ", validate_nonempty
        )

        # Check if user exists by trying to find them in the list
        all_users = list_all_users()
        user_to_delete = None
        for user in all_users:
            if user["username"] == username and user["role"] == "service_engineer":
                user_to_delete = user
                break

        if not user_to_delete:
            print(f"\n❌ Service Engineer '{username}' not found.")
            wait_for_enter()
            return

        # Show user information
        print(f"\n✓ Service Engineer found:")
        print(f"  Username: {user_to_delete['username']}")
        print(f"  Name: {user_to_delete['first_name']} {user_to_delete['last_name']}")
        print(f"  Created: {user_to_delete['created_at']}")

        # Ask for confirmation
        if prompt_confirmation(
            f"\n⚠️  Are you sure you want to delete this user? (yes/no): "
        ):
            success, msg = delete_user(username)
            print(f"\n{msg}")
        else:
            print("\nDeletion cancelled.")

    except CancelInputException:
        print("\nOperation cancelled.")

    wait_for_enter()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5: TRAVELER/CUSTOMER UI
# ═══════════════════════════════════════════════════════════════════════════
# Description: User interface functions for traveler/customer management
#
# Key components:
# - add_traveler_ui(): Add new traveler with complete profile validation
# - search_travelers_ui(): Search travelers by name or customer ID
# - list_travelers_ui(): Display all travelers with key information
# - update_traveler_ui(): Update traveler contact information (email/phone)
# - delete_traveler_ui(): Delete traveler with confirmation
#
# Note: Accessible by Super Admin and System Admin roles
# ═══════════════════════════════════════════════════════════════════════════


def add_traveler_ui():
    """Add new traveler with per-field validation."""
    clear_screen()
    print_header("ADD NEW TRAVELER")
    print_user_info()

    print("\nEnter traveler information (type 'exit' or 'cancel' to abort):")

    try:
        # First name - validated
        first_name = prompt_with_validation(
            "\nFirst name: ", lambda x: validate_name(x, "First name")
        )

        # Last name - validated
        last_name = prompt_with_validation(
            "Last name: ", lambda x: validate_name(x, "Last name")
        )

        # Birthday - validated
        birthday = prompt_with_validation(
            "Birthday (DD-MM-YYYY): ",
            validate_birthday,
        )

        # Gender - validated with menu choice
        gender = prompt_choice_from_list("Select gender:", ["Male", "Female"])

        # Street name - validated
        street_name = prompt_with_validation(
            "Street name: ", lambda x: validate_name(x, "Street name")
        )

        # House number - validated
        house_number = prompt_with_validation("House number: ", validate_house_number)

        # Zip code - validated
        zip_code = prompt_with_validation(
            "Zip code (1234AB format): ", validate_zipcode
        )

        # City - validated with menu choice
        city = prompt_choice_from_list("Select city:", VALID_CITIES)

        # Email - validated
        email = prompt_with_validation("Email (lowercase, e.g. john@example.com): ", validate_email)

        # Mobile phone - validated
        mobile_phone = prompt_with_validation(
            "Mobile phone (8 digits): +31 6 ", validate_phone
        )

        # Driving license - validated
        driving_license = prompt_with_validation(
            "Driving license (AB1234567 format): ", validate_driving_license
        )

        success, msg, customer_id = add_traveler(
            first_name,
            last_name,
            birthday,
            gender,
            street_name,
            house_number,
            zip_code,
            city,
            email,
            mobile_phone,
            driving_license,
        )

        print(f"\n{msg}")
        if success:
            print(f"Customer ID: {customer_id}")

    except CancelInputException:
        print("\nTraveler creation cancelled.")

    wait_for_enter()


def search_travelers_ui():
    """Search travelers with partial key."""
    clear_screen()
    print_header("SEARCH TRAVELERS")
    print_user_info()

    print("\nSearch by partial key (name, customer ID):")

    try:
        # Simple validation for search term
        def validate_search_term(term):
            term = term.strip()
            if not term:
                raise ValidationError(
                    "Search term cannot be empty. Expected: at least 1 character"
                )
            return term

        search_key = prompt_with_validation("Enter search term: ", validate_search_term)

        results = search_travelers(search_key)

        if not results:
            print(f"\nNo travelers found matching '{search_key}'.")
        else:
            print(f"\nFound {len(results)} traveler(s):")
            print("\n" + "-" * 70)
            for t in results:
                print(f"Customer ID: {t['customer_id']}")
                print(f"Name: {t['first_name']} {t['last_name']}")
                print(f"Email: {t['email']}")
                print(f"City: {t['city']}")
                print("-" * 70)

    except CancelInputException:
        print("\nSearch cancelled.")

    wait_for_enter()


def list_travelers_ui():
    """List all travelers."""
    clear_screen()
    print_header("ALL TRAVELERS")
    print_user_info()

    travelers = list_all_travelers()

    if not travelers:
        print("\nNo travelers found.")
    else:
        print(f"\nTotal: {len(travelers)} traveler(s)")
        print("\n" + "-" * 70)
        for t in travelers:
            print(f"Customer ID: {t['customer_id']}")
            print(f"Name: {t['first_name']} {t['last_name']}")
            print(f"Email: {t['email']}")
            print(f"Phone: {t['mobile_phone']}")
            print(f"City: {t['city']}")
            print("-" * 70)

    wait_for_enter()


def update_traveler_ui():
    """Update traveler information."""
    clear_screen()
    print_header("UPDATE TRAVELER")
    print_user_info()

    try:
        customer_id = input("\nEnter customer ID: ")
        if (not validate_customer_id_input(customer_id)):
            print("\n❌ Invalid customer ID format.")
            wait_for_enter()
            return

        # Check if traveler exists
        traveler = get_traveler_by_id(customer_id)
        if not traveler:
            print(f"\nTraveler with ID '{customer_id}' not found.")
            wait_for_enter()
            return

        print(
            f"\nCurrent information for: {traveler['first_name']} {traveler['last_name']}"
        )
        print(f"Customer ID: {traveler['customer_id']}")
        print(f"Birthday: {traveler['birthday']} (cannot be changed)")
        print(f"Gender: {traveler['gender']} (cannot be changed)")
        print(
            f"Address: {traveler['street_name']} {traveler['house_number']}, {traveler['zip_code']} {traveler['city']}"
        )
        print(f"Email: {traveler['email']}")
        print(f"Phone: {traveler['mobile_phone']}")
        print(f"License: {traveler['driving_license']}")
        print(f"Registered: {traveler['registration_date']} (cannot be changed)")

        print("\n" + "=" * 70)
        print("UPDATE TRAVELER INFORMATION")
        print("=" * 70)
        print("Leave any field blank to keep the current value.")
        print("Type 'exit' or 'cancel' to abort the update.\n")

        # Personal Information (names can be updated for legal name changes)
        print("--- Personal Information ---")
        first_name = prompt_optional_field(
            "New first name", lambda x: validate_name(x, "First name"), current_value=traveler['first_name']
        )
        last_name = prompt_optional_field(
            "New last name", lambda x: validate_name(x, "Last name"), current_value=traveler['last_name']
        )

        # Address Information
        print("\n--- Address Information ---")
        street_name = prompt_optional_field(
            "New street name", lambda x: validate_name(x, "Street name"), current_value=traveler['street_name']
        )
        house_number = prompt_optional_field(
            "New house number", validate_house_number, current_value=traveler['house_number']
        )
        zip_code = prompt_optional_field(
            "New zip code (1234AB format)", validate_zipcode, current_value=traveler['zip_code']
        )
        city = prompt_optional_field(
            "New city", validate_city, current_value=traveler['city']
        )

        # Contact Information
        print("\n--- Contact Information ---")
        email = prompt_optional_field(
            "New email (lowercase, e.g. john@example.com)", validate_email, current_value=traveler['email']
        )
        mobile_phone = prompt_optional_field(
            "New phone (8 digits)", validate_phone, current_value=traveler['mobile_phone']
        )

        # Driving License Information
        print("\n--- License Information ---")
        driving_license = prompt_optional_field(
            "New driving license (AB1234567 format)", validate_driving_license, current_value=traveler['driving_license']
        )

        # Build updates dictionary
        updates = {}
        if first_name:
            updates["first_name"] = first_name
        if last_name:
            updates["last_name"] = last_name
        if street_name:
            updates["street_name"] = street_name
        if house_number:
            updates["house_number"] = house_number
        if zip_code:
            updates["zip_code"] = zip_code
        if city:
            updates["city"] = city
        if email:
            updates["email"] = email
        if mobile_phone:
            updates["mobile_phone"] = mobile_phone
        if driving_license:
            updates["driving_license"] = driving_license

        if not updates:
            print("\nNo changes made.")
        else:
            print("\n" + "=" * 70)
            print("SUMMARY OF CHANGES")
            print("=" * 70)
            for key, value in updates.items():
                print(f"  {key}: {value}")
            print("=" * 70)

            if prompt_confirmation("\nConfirm these changes? (yes/no): "):
                success, msg = update_traveler(customer_id, **updates)
                print(f"\n{msg}")
            else:
                print("\nUpdate cancelled.")

    except CancelInputException:
        print("\nUpdate cancelled.")

    wait_for_enter()


def delete_traveler_ui():
    """Delete traveler."""
    clear_screen()
    print_header("DELETE TRAVELER")
    print_user_info()

    customer_id = input("\nEnter customer ID to delete: ")
    if (not validate_customer_id_input(customer_id)):
        print("\n❌ Invalid customer ID format.")
        wait_for_enter()
        return

    if not customer_id:
        print("\n❌ Customer ID cannot be empty.")
        wait_for_enter()
        return

    # First check if traveler exists
    traveler = get_traveler_by_id(customer_id)

    if not traveler:
        print(f"\n❌ Traveler with customer ID '{customer_id}' not found.")
        wait_for_enter()
        return

    # Show traveler information
    print(f"\n✓ Traveler found:")
    print(f"  Customer ID: {traveler['customer_id']}")
    print(f"  Name: {traveler['first_name']} {traveler['last_name']}")
    print(f"  Birthday: {traveler['birthday']}")
    print(f"  Gender: {traveler['gender']}")
    print(
        f"  Address: {traveler['street_name']} {traveler['house_number']}, {traveler['zip_code']} {traveler['city']}"
    )
    print(f"  Email: {traveler['email']}")
    print(f"  Phone: {traveler['mobile_phone']}")
    print(f"  License: {traveler['driving_license']}")

    # Now ask for confirmation
    if prompt_confirmation(f"\n⚠️  Are you sure you want to delete this traveler? (yes/no): "):
        success, msg = delete_traveler(customer_id)
        print(f"\n{msg}")
    else:
        print("\nDeletion cancelled.")

    wait_for_enter()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6: SCOOTER FLEET MANAGEMENT UI
# ═══════════════════════════════════════════════════════════════════════════
# Description: User interface functions for scooter fleet management
#
# Key components:
# - add_scooter_ui(): Add new scooter to fleet with validation
# - search_scooters_ui(): Search scooters by type, location, or status
# - list_scooters_ui(): Display all scooters with complete information
# - update_scooter_ui(): Update scooter (Admin - all fields)
# - update_scooter_engineer_ui(): Update scooter (Engineer - limited fields only)
# - delete_scooter_ui(): Delete scooter with confirmation
#
# Note: Different permissions for Admins vs Service Engineers
# ═══════════════════════════════════════════════════════════════════════════


def add_scooter_ui():
    """
    Add new scooter with per-field validation.

    Each field is validated immediately with feedback loop.
    User can retry invalid input before moving to next field.
    """
    clear_screen()
    print_header("ADD NEW SCOOTER")
    print_user_info()

    print("\nEnter scooter information:")

    # Serial number - validated with uniqueness check
    serial_number = prompt_with_validation(
        "Serial number (10-17 characters): ", validate_unique_serial_number
    )

    # Brand - validated
    brand = prompt_with_validation("Brand (e.g., Segway, NIU): ", validate_brand)

    # Model - validated
    model = prompt_with_validation("Model (e.g., ES2, Pro Max): ", validate_model)

    # Top speed - validated
    top_speed = prompt_with_validation("Top speed in km/h (0-80): ", validate_top_speed)

    # Battery capacity - validated
    battery_capacity = prompt_integer_with_validation(
        "Battery capacity in Wh (0-10000): ", validate_battery_capacity
    )

    # State of Charge - validated
    state_of_charge = prompt_integer_with_validation(
        "Current State of Charge % (0-100): ", validate_state_of_charge
    )

    # Target range SoC - with min < max validation
    print("\nTarget-range State of Charge (recommended battery operating range):")
    while True:
        target_range_soc_min = prompt_integer_with_validation(
            "Minimum SoC % (e.g., 20): ", validate_state_of_charge
        )
        target_range_soc_max = prompt_integer_with_validation(
            "Maximum SoC % (e.g., 80): ", validate_state_of_charge
        )

        # Validate that min < max
        try:
            target_range_soc_min, target_range_soc_max = validate_target_range_soc(
                target_range_soc_min, target_range_soc_max
            )
            break  # Valid range, exit loop
        except ValidationError as e:
            print(f"❌ Error: {e}\n")
            print("Please re-enter the target range values.\n")

    # GPS Location
    print("\nGPS Location (Rotterdam region):")
    print(
        "Examples: Rotterdam Centraal (51.92481, 4.46910), Erasmusbrug (51.91081, 4.48250)"
    )
    # Get latitude and longitude separately, then validate together
    latitude_input = prompt_with_validation("Latitude (51.8-52.05): ", validate_float)
    longitude_input = prompt_with_validation("Longitude (4.25-4.65): ", validate_float)

    # Validate GPS coordinates are within Rotterdam region
    latitude, longitude = validate_gps_location(latitude_input, longitude_input)

    # Out-of-service status - validated with menu choice
    status_choice = prompt_choice_from_list(
        "Out-of-service status:", ["In service (available)", "Out of service (maintenance/unavailable)"]
    )
    out_of_service_status = status_choice == "Out of service (maintenance/unavailable)"

    # Mileage - validated
    mileage = prompt_with_validation("Mileage in km (0-999999): ", validate_mileage)

    # Last maintenance date - optional, but validated if provided
    print("\nLast maintenance date (optional, press Enter to skip):")
    last_maintenance_date = prompt_optional_field(
        "Date (YYYY-MM-DD)", validate_date, allow_exit=False
    )

    # All fields validated - now add to database
    success, msg = add_scooter(
        serial_number=serial_number,
        brand=brand,
        model=model,
        top_speed=top_speed,
        battery_capacity=battery_capacity,
        state_of_charge=state_of_charge,
        target_range_soc_min=target_range_soc_min,
        target_range_soc_max=target_range_soc_max,
        latitude=latitude,
        longitude=longitude,
        out_of_service_status=out_of_service_status,
        mileage=mileage,
        last_maintenance_date=last_maintenance_date,
    )

    print(f"\n{msg}")
    wait_for_enter()


def search_scooters_ui():
    """Search scooters."""
    clear_screen()
    print_header("SEARCH SCOOTERS")
    print_user_info()

    print("\nSearch by: brand, model, or GPS coordinates")
    search_key = input("Enter search term: ")
    if (not validate_search_key_input(search_key)):
        print("\n❌ Invalid search term format.")
        wait_for_enter()
        return

    if not search_key:
        print("\nSearch term cannot be empty.")
        wait_for_enter()
        return

    results = search_scooters(search_key)

    if not results:
        print(f"\nNo scooters found matching '{search_key}'.")
    else:
        print(f"\nFound {len(results)} scooter(s):")
        print("\n" + "-" * 80)
        for s in results:
            print(f"Serial Number: {s['serial_number']}")
            print(f"Brand: {s['brand']}")
            print(f"Model: {s['model']}")
            print(f"Top Speed: {s['top_speed']} km/h")
            print(f"Battery Capacity: {s['battery_capacity']} Wh")
            print(f"State of Charge: {s['state_of_charge']}%")
            print(
                f"Target SoC Range: {s['target_range_soc_min']}-{s['target_range_soc_max']}%"
            )
            print(f"Location: {s['latitude']}, {s['longitude']}")
            print(f"Out of Service: {'Yes' if s['out_of_service_status'] else 'No'}")
            print(f"Mileage: {s['mileage']} km")
            print(f"Last Maintenance: {s['last_maintenance_date'] or 'Never'}")
            print(f"In Service Since: {s['in_service_date']}")
            print("-" * 80)

    wait_for_enter()


def list_scooters_ui():
    """List all scooters."""
    clear_screen()
    print_header("ALL SCOOTERS")
    print_user_info()

    scooters = list_all_scooters()

    if not scooters:
        print("\nNo scooters found.")
    else:
        print(f"\nTotal: {len(scooters)} scooter(s)")
        print("\n" + "-" * 80)
        for s in scooters:
            print(f"Serial Number: {s['serial_number']}")
            print(f"Brand: {s['brand']}")
            print(f"Model: {s['model']}")
            print(f"Top Speed: {s['top_speed']} km/h")
            print(f"Battery Capacity: {s['battery_capacity']} Wh")
            print(f"State of Charge: {s['state_of_charge']}%")
            print(
                f"Target SoC Range: {s['target_range_soc_min']}-{s['target_range_soc_max']}%"
            )
            print(f"Location: {s['latitude']}, {s['longitude']}")
            print(f"Out of Service: {'Yes' if s['out_of_service_status'] else 'No'}")
            print(f"Mileage: {s['mileage']} km")
            print(f"Last Maintenance: {s['last_maintenance_date'] or 'Never'}")
            print(f"In Service Since: {s['in_service_date']}")
            print("-" * 80)

    wait_for_enter()


def update_scooter_ui():
    """Update scooter (Super/System Admin - all fields)."""
    clear_screen()
    print_header("UPDATE SCOOTER")
    print_user_info()

    try:
        serial_number = input("\nEnter scooter serial number: ")

        # Get current scooter
        scooter = get_scooter_by_serial(serial_number)
        if not scooter:
            print(f"\nScooter '{serial_number}' not found.")
            wait_for_enter()
            return

        print(f"\nCurrent information for scooter: {scooter.get('serial_number')}")
        print(f"Serial Number: {scooter.get('serial_number')} (cannot be changed)")
        print(f"Brand: {scooter.get('brand', 'N/A')}")
        print(f"Model: {scooter.get('model', 'N/A')}")
        print(f"Top Speed: {scooter.get('top_speed', 'N/A')} km/h")
        print(f"Battery Capacity: {scooter.get('battery_capacity', 'N/A')} Wh")
        print(f"State of Charge: {scooter.get('state_of_charge', 'N/A')}%")
        print(
            f"Target SoC Range: {scooter.get('target_range_soc_min', 'N/A')}-{scooter.get('target_range_soc_max', 'N/A')}%"
        )
        print(
            f"Location: {scooter.get('latitude', 'N/A')}, {scooter.get('longitude', 'N/A')}"
        )
        print(f"Out of Service: {'Yes' if scooter.get('out_of_service_status') else 'No'}")
        print(f"Mileage: {scooter.get('mileage', 'N/A')} km")
        print(f"Last Maintenance: {scooter.get('last_maintenance_date', 'N/A')}")
        print(f"In Service Since: {scooter.get('in_service_date', 'N/A')} (cannot be changed)")

        print("\n" + "=" * 70)
        print("UPDATE SCOOTER INFORMATION")
        print("=" * 70)
        print("Leave any field blank to keep the current value.")
        print("Type 'exit' or 'cancel' to abort the update.\n")

        # Scooter Specifications
        print("--- Scooter Specifications ---")
        brand = prompt_optional_field("New brand", validate_brand, current_value=scooter.get('brand'))
        model = prompt_optional_field("New model", validate_model, current_value=scooter.get('model'))
        top_speed = prompt_optional_field("New top speed (km/h)", validate_top_speed, current_value=scooter.get('top_speed'))
        battery_capacity = prompt_optional_field("New battery capacity (Wh)", validate_battery_capacity, current_value=scooter.get('battery_capacity'))

        # Battery Status
        print("\n--- Battery Status ---")
        state_of_charge = prompt_optional_field("New state of charge (%)", validate_state_of_charge, current_value=scooter.get('state_of_charge'))

        print("\nTarget SoC Range (enter both values or skip both):")
        target_min = prompt_optional_field("New target min SoC (%)", validate_state_of_charge, current_value=scooter.get('target_range_soc_min'))
        target_max = prompt_optional_field("New target max SoC (%)", validate_state_of_charge, current_value=scooter.get('target_range_soc_max'))

        # Validate target range if both provided
        if target_min is not None and target_max is not None:
            target_min, target_max = validate_target_range_soc(target_min, target_max)
        elif target_min is not None or target_max is not None:
            print("\n❌ Error: Both target min and max SoC must be provided together.")
            wait_for_enter()
            return

        # GPS Location
        print("\n--- GPS Location ---")
        print("Rotterdam region - enter both coordinates or skip both")
        print("Examples: Rotterdam Centraal (51.92481, 4.46910), Erasmusbrug (51.91081, 4.48250)")
        latitude = prompt_optional_field("New latitude (51.8-52.05)", validate_float, current_value=scooter.get('latitude'))
        longitude = prompt_optional_field("New longitude (4.25-4.65)", validate_float, current_value=scooter.get('longitude'))

        # Validate GPS if both provided
        if latitude is not None and longitude is not None:
            latitude, longitude = validate_gps_location(latitude, longitude)
        elif latitude is not None or longitude is not None:
            print("\n❌ Error: Both latitude and longitude must be provided together.")
            wait_for_enter()
            return

        # Service Status
        print("\n--- Service Status ---")
        print(f"Current status: {'Out of service' if scooter.get('out_of_service_status') else 'In service'}")
        service_input = prompt_optional_field(
            "New status (1/Yes=Out of service, 0/No=In service)",
            lambda x: validate_out_of_service_status(x),
            allow_exit=True
        )
        out_of_service_status = service_input if service_input is not None else None

        # Maintenance Information
        print("\n--- Maintenance Information ---")
        mileage = prompt_optional_field("New mileage (km)", validate_mileage, current_value=scooter.get('mileage'))
        last_maintenance = prompt_optional_field("New last maintenance date (YYYY-MM-DD)", validate_date, current_value=scooter.get('last_maintenance_date'))

        # Build updates dictionary
        updates = {}
        if brand:
            updates["brand"] = brand
        if model:
            updates["model"] = model
        if top_speed is not None:
            updates["top_speed"] = top_speed
        if battery_capacity is not None:
            updates["battery_capacity"] = battery_capacity
        if state_of_charge is not None:
            updates["state_of_charge"] = state_of_charge
        if target_min is not None:
            updates["target_range_soc_min"] = target_min
        if target_max is not None:
            updates["target_range_soc_max"] = target_max
        if latitude is not None:
            updates["latitude"] = latitude
        if longitude is not None:
            updates["longitude"] = longitude
        if out_of_service_status is not None:
            updates["out_of_service_status"] = out_of_service_status
        if mileage is not None:
            updates["mileage"] = mileage
        if last_maintenance:
            updates["last_maintenance_date"] = last_maintenance

        if not updates:
            print("\nNo changes made.")
        else:
            print("\n" + "=" * 70)
            print("SUMMARY OF CHANGES")
            print("=" * 70)
            for key, value in updates.items():
                print(f"  {key}: {value}")
            print("=" * 70)

            if prompt_confirmation("\nConfirm these changes? (yes/no): "):
                success, msg = update_scooter(serial_number, **updates)
                print(f"\n{msg}")
            else:
                print("\nUpdate cancelled.")

    except CancelInputException:
        print("\nUpdate cancelled.")

    wait_for_enter()


def update_scooter_engineer_ui():
    """Update scooter (Service Engineer - limited fields)."""
    clear_screen()
    print_header("UPDATE SCOOTER (SERVICE ENGINEER)")
    print_user_info()

    try:
        serial_number = input("\nEnter scooter serial number: ")

        # Get current scooter
        scooter = get_scooter_by_serial(serial_number)
        if not scooter:
            print(f"\nScooter '{serial_number}' not found.")
            wait_for_enter()
            return

        print(f"\nCurrent information for scooter: {scooter.get('serial_number')}")
        print(f"Serial Number: {scooter.get('serial_number')} (cannot be changed)")
        print(f"Brand: {scooter.get('brand', 'N/A')} (cannot be changed)")
        print(f"Model: {scooter.get('model', 'N/A')} (cannot be changed)")
        print(f"Top Speed: {scooter.get('top_speed', 'N/A')} km/h (cannot be changed)")
        print(f"Battery Capacity: {scooter.get('battery_capacity', 'N/A')} Wh (cannot be changed)")
        print(f"State of Charge: {scooter.get('state_of_charge', 'N/A')}%")
        print(
            f"Target SoC Range: {scooter.get('target_range_soc_min', 'N/A')}-{scooter.get('target_range_soc_max', 'N/A')}%"
        )
        print(
            f"Location: {scooter.get('latitude', 'N/A')}, {scooter.get('longitude', 'N/A')}"
        )
        print(f"Out of Service: {'Yes' if scooter.get('out_of_service_status') else 'No'}")
        print(f"Mileage: {scooter.get('mileage', 'N/A')} km")
        print(f"Last Maintenance: {scooter.get('last_maintenance_date', 'N/A')}")
        print(f"In Service Since: {scooter.get('in_service_date', 'N/A')} (cannot be changed)")

        print("\n" + "=" * 70)
        print("UPDATE SCOOTER INFORMATION (SERVICE ENGINEER)")
        print("=" * 70)
        print("Note: You can update operational fields only.")
        print("You cannot modify specifications (brand, model, top speed, battery capacity).")
        print("\nLeave any field blank to keep the current value.")
        print("Type 'exit' or 'cancel' to abort the update.\n")

        # Battery Status
        print("--- Battery Status ---")
        state_of_charge = prompt_optional_field("New state of charge (0-100%)", validate_state_of_charge, current_value=scooter.get('state_of_charge'))

        print("\nTarget SoC Range (enter both values or skip both):")
        target_min = prompt_optional_field("New target min SoC (%)", validate_state_of_charge, current_value=scooter.get('target_range_soc_min'))
        target_max = prompt_optional_field("New target max SoC (%)", validate_state_of_charge, current_value=scooter.get('target_range_soc_max'))

        # Validate target range if both provided
        if target_min is not None and target_max is not None:
            target_min, target_max = validate_target_range_soc(target_min, target_max)
        elif target_min is not None or target_max is not None:
            print("\n❌ Error: Both target min and max SoC must be provided together.")
            wait_for_enter()
            return

        # GPS Location
        print("\n--- GPS Location ---")
        print("Rotterdam region - enter both coordinates or skip both")
        print("Examples: Rotterdam Centraal (51.92481, 4.46910), Erasmusbrug (51.91081, 4.48250)")
        latitude = prompt_optional_field("New latitude (51.8-52.05)", validate_float, current_value=scooter.get('latitude'))
        longitude = prompt_optional_field("New longitude (4.25-4.65)", validate_float, current_value=scooter.get('longitude'))

        # Validate GPS if both provided
        if latitude is not None and longitude is not None:
            latitude, longitude = validate_gps_location(latitude, longitude)
        elif latitude is not None or longitude is not None:
            print("\n❌ Error: Both latitude and longitude must be provided together.")
            wait_for_enter()
            return

        # Service Status
        print("\n--- Service Status ---")
        print(f"Current status: {'Out of service' if scooter.get('out_of_service_status') else 'In service'}")
        service_input = prompt_optional_field(
            "New status (1/Yes=Out of service, 0/No=In service)",
            lambda x: validate_out_of_service_status(x),
            allow_exit=True
        )
        out_of_service_status = service_input if service_input is not None else None

        # Maintenance Information
        print("\n--- Maintenance Information ---")
        mileage = prompt_optional_field("New mileage (km)", validate_mileage, current_value=scooter.get('mileage'))
        last_maintenance = prompt_optional_field("New last maintenance date (YYYY-MM-DD)", validate_date, current_value=scooter.get('last_maintenance_date'))

        # Build updates dictionary
        updates = {}
        if state_of_charge is not None:
            updates["state_of_charge"] = state_of_charge
        if target_min is not None:
            updates["target_range_soc_min"] = target_min
        if target_max is not None:
            updates["target_range_soc_max"] = target_max
        if latitude is not None:
            updates["latitude"] = latitude
        if longitude is not None:
            updates["longitude"] = longitude
        if out_of_service_status is not None:
            updates["out_of_service_status"] = out_of_service_status
        if mileage is not None:
            updates["mileage"] = mileage
        if last_maintenance:
            updates["last_maintenance_date"] = last_maintenance

        if not updates:
            print("\nNo changes made.")
        else:
            print("\n" + "=" * 70)
            print("SUMMARY OF CHANGES")
            print("=" * 70)
            for key, value in updates.items():
                print(f"  {key}: {value}")
            print("=" * 70)

            if prompt_confirmation("\nConfirm these changes? (yes/no): "):
                success, msg = update_scooter(serial_number, **updates)
                print(f"\n{msg}")
            else:
                print("\nUpdate cancelled.")

    except CancelInputException:
        print("\nUpdate cancelled.")

    wait_for_enter()


def delete_scooter_ui():
    """Delete scooter."""
    clear_screen()
    print_header("DELETE SCOOTER")
    print_user_info()

    try:
        serial_number = prompt_with_validation(
            "\nEnter scooter serial number to delete: ", validate_nonempty
        )

        # Check if scooter exists
        scooter = get_scooter_by_serial(serial_number)

        if not scooter:
            print(f"\n❌ Scooter with serial number '{serial_number}' not found.")
            wait_for_enter()
            return

        # Show scooter information
        print(f"\n✓ Scooter found:")
        print(f"  Serial Number: {scooter['serial_number']}")
        print(f"  Brand: {scooter['brand']}")
        print(f"  Model: {scooter['model']}")
        print(f"  Top Speed: {scooter['top_speed']} km/h")
        print(f"  State of Charge: {scooter['state_of_charge']}%")
        print(f"  Location: {scooter['latitude']}, {scooter['longitude']}")
        print(f"  Out of Service: {'Yes' if scooter['out_of_service_status'] else 'No'}")
        print(f"  Mileage: {scooter['mileage']} km")
        print(f"  Last Maintenance: {scooter['last_maintenance_date'] or 'Never'}")
        print(f"  In Service Since: {scooter['in_service_date']}")

        # Ask for confirmation
        if prompt_confirmation(
            f"\n⚠️  Are you sure you want to delete this scooter? (yes/no): "
        ):
            success, msg = delete_scooter(serial_number)
            print(f"\n{msg}")
        else:
            print("\nDeletion cancelled.")

    except CancelInputException:
        print("\nOperation cancelled.")

    wait_for_enter()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7: SYSTEM LOGS UI
# ═══════════════════════════════════════════════════════════════════════════
# Description: User interface functions for viewing system activity logs
#
# Key components:
# - view_logs_menu(): Logs viewing submenu
# - view_all_logs_ui(): Display all system logs
# - view_recent_logs_ui(): Display last 20 logs
# - view_suspicious_logs_ui(): Display only suspicious activities
#
# Note: Accessible by Super Admin and System Admin roles
# ═══════════════════════════════════════════════════════════════════════════


def view_logs_menu():
    """View system logs menu."""
    while True:
        clear_screen()
        print_header("SYSTEM LOGS")
        print_user_info()

        print("\n1. View All Logs")
        print("2. View Recent Logs (last 20)")
        print("3. View Suspicious Activities Only")
        print("4. Back to Main Menu")

        choice = input("\nEnter choice (1-4): ")

        if choice == "1":
            view_all_logs_ui()
        elif choice == "2":
            view_recent_logs_ui()
        elif choice == "3":
            view_suspicious_logs_ui()
        elif choice == "4":
            break
        else:
            print("Invalid choice. Please enter 1-4.")
            wait_for_enter()


def view_all_logs_ui():
    """View all system logs."""
    clear_screen()
    print_header("ALL SYSTEM LOGS")
    print_user_info()

    logs = get_all_logs()

    if not logs:
        print("\nNo logs found.")
    else:
        display_logs(logs)

    wait_for_enter()


def view_recent_logs_ui():
    """View recent logs."""
    clear_screen()
    print_header("RECENT LOGS (Last 20)")
    print_user_info()

    logs = get_all_logs()

    if not logs:
        print("\nNo logs found.")
    else:
        recent = logs[-20:]
        display_logs(recent)

    wait_for_enter()


def view_suspicious_logs_ui():
    """View suspicious activities only."""
    clear_screen()
    print_header("SUSPICIOUS ACTIVITIES")
    print_user_info()

    logs = get_all_logs()
    suspicious = [log for log in logs if log.get("suspicious") == "Yes"]

    if not suspicious:
        print("\nNo suspicious activities found.")
    else:
        print(f"\n⚠️  Found {len(suspicious)} suspicious activities:")
        display_logs(suspicious)

    wait_for_enter()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 8: BACKUP & RESTORE UI
# ═══════════════════════════════════════════════════════════════════════════
# Description: User interface functions for backup and disaster recovery
#
# Key components:
# - backup_restore_menu(): Backup/restore submenu with role-based options
# - create_backup_ui(): Create system backup (database + keys + logs)
# - list_backups_ui(): Display available backups
# - restore_backup_ui(): Restore from backup (with code validation for System Admins)
# - generate_restore_code_ui(): Generate one-time restore code (Super Admin only)
# - revoke_restore_code_ui(): Revoke unused restore code (Super Admin only)
# - list_restore_codes_ui(): Display active restore codes (Super Admin only)
#
# Note: Super Admin has full access; System Admin needs restore codes
# ═══════════════════════════════════════════════════════════════════════════


def backup_restore_menu():
    """Backup and restore menu."""
    user = get_current_user()

    while True:
        clear_screen()
        print_header("BACKUP & RESTORE")
        print_user_info()

        print("\n1. Create Backup")
        print("2. List Backups")
        print("3. Restore Backup")

        if user and user["role"] == "super_admin":
            print("4. Generate Restore Code")
            print("5. Revoke Restore Code")
            print("6. List Restore Codes")
            print("7. Back to Main Menu")
        else:
            print("4. Back to Main Menu")

        choice = input("\nEnter choice: ")

        if choice == "1":
            create_backup_ui()
        elif choice == "2":
            list_backups_ui()
        elif choice == "3":
            restore_backup_ui()
        elif choice == "4":
            if user and user["role"] == "super_admin":
                generate_restore_code_ui()
            else:
                break
        elif choice == "5" and user and user["role"] == "super_admin":
            revoke_restore_code_ui()
        elif choice == "6" and user and user["role"] == "super_admin":
            list_restore_codes_ui()
        elif choice == "7" and user and user["role"] == "super_admin":
            break
        else:
            print("Invalid choice.")
            wait_for_enter()


def create_backup_ui():
    """Create backup."""
    clear_screen()
    print_header("CREATE BACKUP")
    print_user_info()

    print("\nCreating backup...")
    success, msg, filename = create_backup()

    print(f"\n{msg}")
    if success:
        print(f"Backup file: {filename}")

    wait_for_enter()


def list_backups_ui():
    """List available backups."""
    clear_screen()
    print_header("AVAILABLE BACKUPS")
    print_user_info()

    backups = list_backups()

    if not backups:
        print("\nNo backups found.")
    else:
        print(f"\nTotal: {len(backups)} backup(s)")
        print("\n" + "-" * 70)
        for b in backups:
            print(f"Filename: {b['filename']}")
            print(f"Size: {b['size']} bytes")
            print(f"Created: {b['created']}")
            print("-" * 70)

    wait_for_enter()


def restore_backup_ui():
    """Restore from backup."""
    user = get_current_user()

    clear_screen()
    print_header("RESTORE BACKUP")
    print_user_info()

    backups = list_backups()

    if not backups:
        print("\nNo backups found.")
        wait_for_enter()
        return

    print("\nAvailable backups:")
    for i, b in enumerate(backups, 1):
        print(f"{i}. {b['filename']} ({b['created']})")

    choice = input(f"\nEnter backup number (1-{len(backups)}): ")

    try:
        backup_idx = int(choice) - 1
        backup_filename = backups[backup_idx]["filename"]
    except (ValueError, IndexError):
        print("\nInvalid choice.")
        wait_for_enter()
        return

    # System Admin needs restore code
    restore_code = None
    if user and user["role"] == "system_admin":
        restore_code = input("\nEnter restore code: ")

        # Validate restore code BEFORE asking for confirmation
        from backup import _validate_restore_code

        code_valid, code_backup = _validate_restore_code(restore_code)

        if not code_valid:
            print("\n❌ Invalid or expired restore code.")
            wait_for_enter()
            return

        if code_backup != backup_filename:
            print(
                f"\n❌ Restore code is valid for '{code_backup}', not '{backup_filename}'."
            )
            wait_for_enter()
            return

        print(f"\n✓ Restore code validated successfully.")

    confirm = (
        input(
            f"\n⚠️  Restore from '{backup_filename}'? This will overwrite current data. (yes/no): "
        )
        .strip()
        .lower()
    )

    if confirm == "yes":
        success, msg = restore_backup(backup_filename, restore_code)
        print(f"\n{msg}")
    else:
        print("\nRestore cancelled.")

    wait_for_enter()


def generate_restore_code_ui():
    """Generate restore code (Super Admin only)."""
    clear_screen()
    print_header("GENERATE RESTORE CODE")
    print_user_info()

    try:
        backups = list_backups()

        if not backups:
            print("\nNo backups found.")
            wait_for_enter()
            return

        print("\nAvailable backups:")
        for i, b in enumerate(backups, 1):
            print(f"{i}. {b['filename']}")

        choice = prompt_menu_choice(f"\nEnter backup number (1-{len(backups)}): ", 1, len(backups))
        backup_idx = int(choice) - 1
        backup_filename = backups[backup_idx]["filename"]

        target_username = prompt_with_validation(
            "Enter System Admin username: ", validate_nonempty
        )

        success, msg, code = generate_restore_code(backup_filename, target_username)

        print(f"\n{msg}")
        if success:
            print(f"\n✓ Restore code: {code}")
            print(f"  Valid for: {target_username}")
            print(f"  Backup: {backup_filename}")

    except CancelInputException:
        print("\nOperation cancelled.")

    wait_for_enter()


def revoke_restore_code_ui():
    """Revoke restore code (Super Admin only)."""
    clear_screen()
    print_header("REVOKE RESTORE CODE")
    print_user_info()

    codes = list_restore_codes()

    if not codes:
        print("\nNo active restore codes found.")
        wait_for_enter()
        return

    print("\nActive restore codes:")
    for i, c in enumerate(codes, 1):
        print(
            f"{i}. {c['code']} - User: {c['target_username']} - Backup: {c['backup_filename']}"
        )

    choice = input(f"\nEnter code number to revoke (1-{len(codes)}): ")

    try:
        code_idx = int(choice) - 1
        selected_code = codes[code_idx]
    except (ValueError, IndexError):
        print("\n❌ Invalid choice.")
        wait_for_enter()
        return

    # Show selected restore code information
    print(f"\n✓ Restore code selected:")
    print(f"  Code: {selected_code['code']}")
    print(f"  Target User: {selected_code['target_username']}")
    print(f"  Backup File: {selected_code['backup_filename']}")
    print(f"  Created: {selected_code['created_at']}")

    # Now ask for confirmation
    confirm = (
        input(f"\n⚠️  Are you sure you want to revoke this restore code? (yes/no): ")
        .strip()
        .lower()
    )

    if confirm == "yes":
        success, msg = revoke_restore_code(selected_code["code"])
        print(f"\n{msg}")
    else:
        print("\nRevocation cancelled.")

    wait_for_enter()


def list_restore_codes_ui():
    """List active restore codes (Super Admin only)."""
    clear_screen()
    print_header("ACTIVE RESTORE CODES")
    print_user_info()

    codes = list_restore_codes()

    if not codes:
        print("\nNo active restore codes found.")
    else:
        print(f"\nTotal: {len(codes)} active code(s)")
        print("\n" + "-" * 70)
        for c in codes:
            print(f"Code: {c['code']}")
            print(f"User: {c['target_username']}")
            print(f"Backup: {c['backup_filename']}")
            print(f"Created: {c['created_at']}")
            print("-" * 70)

    wait_for_enter()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 9: PROFILE MANAGEMENT UI
# ═══════════════════════════════════════════════════════════════════════════
# Description: User interface functions for viewing and managing own profile
#
# Key components:
# - view_my_profile_ui(): Display current user's profile information
# - update_my_password_ui(): Allow user to change their own password
# - force_password_change_ui(): Force password change on first login with temp password
#
# Note: All users can view their own profile and update their own password
# ═══════════════════════════════════════════════════════════════════════════


def view_my_profile_ui():
    """Display current user's profile information."""
    clear_screen()
    print_header("MY PROFILE")

    user = get_current_user()

    if not user:
        print("\n❌ Error: No user logged in.")
        wait_for_enter()
        return

    # Display profile information
    print("\n" + "=" * 70)
    print("PROFILE INFORMATION")
    print("=" * 70)

    print(f"\n{'Username:':<20} {user['username']}")
    print(f"{'First Name:':<20} {user['first_name']}")
    print(f"{'Last Name:':<20} {user['last_name']}")
    print(f"{'Role:':<20} {user['role_name']}")

    # Show account creation date if available
    if "created_at" in user and user["created_at"]:
        print(f"{'Account Created:':<20} {user['created_at']}")

    # Show must_change_password status
    if user.get("must_change_password"):
        print(f"\n⚠️  Status: You must change your password (using temporary password)")

    print("\n" + "=" * 70)

    # Display role-specific permissions
    print("\nYOUR PERMISSIONS:")
    print("-" * 70)

    if user["role"] == "super_admin":
        print("  ✓ Manage System Administrators (create, update, delete)")
        print("  ✓ Manage Service Engineers (create, update, delete)")
        print("  ✓ Manage Travelers (add, update, delete)")
        print("  ✓ Manage Scooters (add, update, delete)")
        print("  ✓ View System Logs")
        print("  ✓ Create and restore backups")
        print("  ✓ Generate and revoke restore codes")
        print("  ✓ Full system access")
    elif user["role"] == "system_admin":
        print("  ✓ Manage Service Engineers (create, update, delete)")
        print("  ✓ Manage Travelers (add, update, delete)")
        print("  ✓ Manage Scooters (add, update, delete)")
        print("  ✓ View System Logs")
        print("  ✓ Create and restore backups")
        print("  ✓ Generate and revoke restore codes")
    elif user["role"] == "service_engineer":
        print("  ✓ Update Scooter Information (status, battery, location, service)")
        print("  ✓ Search Scooters")
        print("  ✓ View scooter details")

    print("-" * 70)

    wait_for_enter()


def update_my_password_ui():
    """Update current user's password with per-field validation."""
    clear_screen()
    print_header("UPDATE MY PASSWORD")
    print_user_info()

    print("\nPassword requirements:")
    print("  - Length: 12-30 characters")
    print("  - At least 1 lowercase letter")
    print("  - At least 1 uppercase letter")
    print("  - At least 1 digit")
    print("  - At least 1 special character (~!@#$%&_-+=|\\(){}[]:;'<>,.?/)")

    # Step 1: Verify current password first
    current_password = input("\nEnter current password: ")

    if not current_password:
        print("\n❌ Current password cannot be empty.")
        wait_for_enter()
        return

    # Verify current password before asking for new one
    user = get_current_user()
    from database import get_connection
    from auth import verify_password

    if not user:
        print("\n❌ Error: No user logged in.")
        return

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE id = ?", (user["user_id"],))
    result = cursor.fetchone()
    conn.close()

    if not result or not verify_password(current_password, user["username"], result[0]):
        print("\n❌ Incorrect current password.")
        wait_for_enter()
        return

    # Step 2: Get new password with validation and confirmation
    print("\n✓ Current password verified.")
    new_password = prompt_password_with_confirmation(
        "Enter new password: ", validate_password, current_password=current_password
    )

    # Step 3: Update password
    success, msg = update_password(current_password, new_password)

    print(f"\n{msg}")
    wait_for_enter()


def force_password_change_ui():
    """
    Force user to change password on first login with temporary password.

    User cannot proceed until they set a new password.
    """
    clear_screen()
    print_header("⚠️  PASSWORD CHANGE REQUIRED")
    print_user_info()

    print("\n" + "=" * 70)
    print("  YOU MUST CHANGE YOUR TEMPORARY PASSWORD")
    print("=" * 70)

    print("\nPassword requirements:")
    print("  - Length: 12-30 characters")
    print("  - At least 1 lowercase letter")
    print("  - At least 1 uppercase letter")
    print("  - At least 1 digit")
    print("  - At least 1 special character (~!@#$%&_-+=|\\(){}[]:;'<>,.?/)")

    # Get new password with validation and confirmation
    try:
        new_password = prompt_password_with_confirmation(
            "Enter new password: ", validate_password
        )
    except CancelInputException:
        print("\n⚠️  Password change cancelled. You will be logged out.")
        logout()
        wait_for_enter()
        return

    # Update password (no current password needed - user just logged in)
    user = get_current_user()
    from database import get_connection
    from auth import hash_password

    try:
        if not user:
            print("\n❌ Error: No user logged in.")
            return

        conn = get_connection()
        cursor = conn.cursor()

        # Hash the new password
        new_hash = hash_password(new_password, user["username"])

        # Update password and reset must_change_password flag
        cursor.execute(
            """
            UPDATE users
            SET password_hash = ?, must_change_password = 0
            WHERE id = ?
        """,
            (new_hash, user["user_id"]),
        )

        conn.commit()
        conn.close()

        # Update session state
        user["must_change_password"] = False

        print("\n✓ Password changed successfully!")
        print("✓ You can now use the system.")
        wait_for_enter()
        return

    except Exception as e:
        print(f"\n❌ Error updating password: {e}")
        logout()
        wait_for_enter()
        return


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 10: MAIN PROGRAM LOOP & ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════
# Description: Main application entry point and program flow control
#
# Key components:
# - login_screen(): User login interface with credential validation
# - main(): Main program loop (initialization → login → menu routing → logout)
#
# Program flow:
# 1. Initialize database and system
# 2. Display login screen
# 3. Force password change if using temporary password
# 4. Show role-based main menu
# 5. Route to appropriate submenu based on user choice and role
# 6. Handle logout and restart loop
# ═══════════════════════════════════════════════════════════════════════════


def login_screen():
    """Login screen."""
    clear_screen()
    print_header("URBAN MOBILITY BACKEND SYSTEM - LOGIN")

    print("\n" + "=" * 70)
    print("  HARDCODED SUPER ADMIN CREDENTIALS:")
    print("  Username: super_admin")
    print("  Password: Admin_123?")
    print("=" * 70)

    # Validate username format to prevent injection attacks
    try:
        username = prompt_with_validation("\nUsername: ", validate_nonempty, allow_exit=False)
    except ValidationError as e:
        print("\n❌ Invalid credentials")
        wait_for_enter()
        return False
    
    if (not validate_username_input(username)):
        print("\n❌ Invalid credentials")
        wait_for_enter()
        return False

    # Password can be any string - validation happens in login()
    password = input("Password: ")

    if (not validate_password_input(password)):
        print("\n❌ Invalid credentials")
        wait_for_enter()
        return False

    success, message = login(username, password)

    if success:
        print(f"\n✓ {message}")
        wait_for_enter()

        # Check if user must change password (first login with temp password)
        user = get_current_user()
        if user and user.get("must_change_password"):
            force_password_change_ui()

        return True
    else:
        print(f"\n❌ {message}")
        wait_for_enter()
        return False


def main():
    """
    Main program loop.

    Flow:
    1. Login screen
    2. Role-based main menu
    3. Handle menu choices
    4. Logout
    """
    print("\n" + "=" * 70)
    print("  URBAN MOBILITY BACKEND SYSTEM")
    print("  Software Quality - Analysis 8")
    print("=" * 70)
    print("\nInitializing system...")

    # Initialize database (creates tables and super admin)
    try:
        from database import init_database

        init_database()
        print("✓ Database initialized")
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        return

    print("✓ System ready")
    wait_for_enter()

    # Main loop
    while True:
        # Login
        if not login_screen():
            while True:
                retry = input("\nRetry login? (yes/no): ")
                if retry == "yes":
                    break
                elif retry == "no":
                    print("\nGoodbye!")
                    return
                else:
                    print("❌ Invalid input.")
            continue

        # Main menu loop (after successful login)
        while True:
            user = get_current_user()

            if not user:
                break

            if not show_main_menu():
                break

            choice = input("\nEnter choice: ")

            # Route based on role
            if user["role"] == "super_admin":
                if choice == "1":
                    manage_system_admins_menu()
                elif choice == "2":
                    manage_service_engineers_menu()
                elif choice == "3":
                    manage_travelers_menu()
                elif choice == "4":
                    manage_scooters_menu()
                elif choice == "5":
                    view_logs_menu()
                elif choice == "6":
                    backup_restore_menu()
                elif choice == "7":
                    view_my_profile_ui()
                elif choice == "8":
                    logout()
                    print("\n✓ Logged out successfully")
                    wait_for_enter()
                    break
                else:
                    print("\nInvalid choice. Please try again.")
                    wait_for_enter()

            elif user["role"] == "system_admin":
                if choice == "1":
                    manage_service_engineers_menu()
                elif choice == "2":
                    manage_travelers_menu()
                elif choice == "3":
                    manage_scooters_menu()
                elif choice == "4":
                    view_logs_menu()
                elif choice == "5":
                    backup_restore_menu()
                elif choice == "6":
                    view_my_profile_ui()
                elif choice == "7":
                    update_my_password_ui()
                elif choice == "8":
                    logout()
                    print("\n✓ Logged out successfully")
                    wait_for_enter()
                    break
                else:
                    print("\nInvalid choice. Please try again.")
                    wait_for_enter()

            elif user["role"] == "service_engineer":
                if choice == "1":
                    service_engineer_scooter_menu()
                elif choice == "2":
                    search_scooters_ui()
                elif choice == "3":
                    view_my_profile_ui()
                elif choice == "4":
                    update_my_password_ui()
                elif choice == "5":
                    logout()
                    print("\n✓ Logged out successfully")
                    wait_for_enter()
                    break
                else:
                    print("\nInvalid choice. Please try again.")
                    wait_for_enter()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram terminated by user.")
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}")
