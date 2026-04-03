# ═══════════════════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════════════════
# Description: All module imports for the DeclaratieApp Backend System UI
#
# External libraries: os
# Internal modules: auth, users, employees, claims, activity_log, backup,
#                   validation, input_handlers
#
# All validation functions are actively used throughout the UI for:
# - Immediate user input validation with feedback loops
# - Security protection (null-byte detection, format validation)
# - Data integrity enforcement before database operations
# ═══════════════════════════════════════════════════════════════════════════

import os

from auth import login, logout, get_current_user, update_password, check_permission
from users import (
    create_manager, create_employee_user, delete_user, list_all_users,
    reset_user_password, update_user_profile,
)
from employees import (
    add_employee, update_employee, delete_employee,
    search_employees, get_employee_by_id, list_all_employees,
)
from claims import (
    add_claim, update_claim, delete_claim,
    search_claims, get_claim_by_id, list_claims,
)
from activity_log import get_all_logs, display_logs, check_suspicious_activities, mark_logs_as_read
from backup import (
    create_backup, restore_backup, generate_restore_code,
    revoke_restore_code, list_backups, list_restore_codes,
)
from validation import (
    ValidationError, VALID_CITIES, validate_email, validate_phone, validate_zipcode,
    validate_birthday, validate_name, validate_house_number, validate_username,
    validate_password, validate_city, validate_nonempty, validate_bsn,
    validate_identity_doc_type, validate_identity_doc_number,
    validate_claim_date, validate_project_number, validate_claim_type,
    validate_travel_distance, validate_salary_batch, validate_employee_id,
)
from input_handlers import (
    CancelInputException, prompt_with_validation, prompt_menu_choice,
    prompt_confirmation, prompt_optional_field, prompt_choice_from_list,
    prompt_password_with_confirmation,
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
# ═══════════════════════════════════════════════════════════════════════════

def clear_screen():
    """Clear console screen for better UX."""
    os.system("cls" if os.name == "nt" else "clear")

def print_header(title):
    """Print formatted header."""
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


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: MAIN MENU & NAVIGATION
# ═══════════════════════════════════════════════════════════════════════════
# Description: Main menu display based on user role
#
# Key components:
# - show_main_menu(): Role-based main menu (Super Admin, Manager, Employee)
#
# Roles and their menu options:
# - Super Admin: Manage Managers, Employees, Claims, Logs, Backup, Profile
# - Manager: Manage Employees, Claims, Logs, Backup, Profile, Password, Account
# - Employee: My Claims, Add Claim, Search, Profile, Password
# ═══════════════════════════════════════════════════════════════════════════

def show_main_menu():
    """Display main menu based on user role."""
    user = get_current_user()
    if not user:
        return False

    clear_screen()
    print_header("DECLARATIEAPP BACKEND SYSTEM")
    print_user_info()

    # Alert for suspicious activities (Manager and Super Admin only)
    suspicious_count = check_suspicious_activities()
    if suspicious_count > 0 and user["role"] in ("super_admin", "manager"):
        print(f"\n⚠️  WARNING: {suspicious_count} unread suspicious activities detected!")
        print("   Check system logs for details.")

    print("\nMAIN MENU:")

    if user["role"] == "super_admin":
        print("  1. Manage Managers")
        print("  2. Manage Employees (data)")
        print("  3. Manage Employee User Accounts")
        print("  4. Manage Claims")
        print("  5. View System Logs")
        print("  6. Backup & Restore")
        print("  7. View My Profile")
        print("  8. Logout")

    elif user["role"] == "manager":
        print("  1. Manage Employees (data)")
        print("  2. Manage Employee User Accounts")
        print("  3. Manage Claims")
        print("  4. View System Logs")
        print("  5. Backup & Restore")
        print("  6. View My Profile")
        print("  7. Update My Password")
        print("  8. Update My Account")
        print("  9. Delete My Account")
        print("  10. Logout")

    elif user["role"] == "employee":
        print("  1. My Claims")
        print("  2. Add New Claim")
        print("  3. Search My Claims")
        print("  4. View My Profile")
        print("  5. Update My Password")
        print("  6. Logout")

    print("\n" + "-" * 70)
    return True


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: MANAGER MANAGEMENT UI (Super Admin only)
# ═══════════════════════════════════════════════════════════════════════════
# Description: User interface for managing Manager accounts
#
# Key components:
# - manage_managers_menu(): Manager management submenu
# - create_manager_ui(): Create new Manager with validation
# - list_managers_ui(): Display all Managers
# ═══════════════════════════════════════════════════════════════════════════

def manage_managers_menu():
    """Menu for managing Managers."""
    while True:
        clear_screen()
        print_header("MANAGE MANAGERS")
        print_user_info()
        print("\n1. Create New Manager")
        print("2. List All Managers")
        print("3. Reset Manager Password")
        print("4. Update Manager Profile")
        print("5. Delete Manager")
        print("6. Back to Main Menu")
        try:
            choice = prompt_menu_choice("\nEnter choice (1-6): ", 1, 6)
        except CancelInputException:
            break
        if choice == "1":
            create_manager_ui()
        elif choice == "2":
            list_managers_ui()
        elif choice == "3":
            reset_password_ui("manager")
        elif choice == "4":
            update_profile_ui("manager")
        elif choice == "5":
            delete_user_ui("manager")
        elif choice == "6":
            break

def create_manager_ui():
    """Create new Manager with per-field validation."""
    clear_screen()
    print_header("CREATE NEW MANAGER")
    print("\nUsername: 8-10 chars, start with letter or '_', a-z 0-9 _ ' .")
    try:
        username = prompt_with_validation("\nUsername: ", validate_username)
        first_name = prompt_with_validation("First name: ", lambda x: validate_name(x, "First name"))
        last_name = prompt_with_validation("Last name: ", lambda x: validate_name(x, "Last name"))
        success, msg, temp_password = create_manager(username, first_name, last_name)
        print(f"\n{msg}")
        if success and temp_password:
            print(f"Temporary password: {temp_password}")
            print("\n⚠️  IMPORTANT: Save this password! User must change it on first login.")
    except CancelInputException:
        print("\nCancelled.")
    wait_for_enter()

def list_managers_ui():
    """List all Managers."""
    clear_screen()
    print_header("MANAGERS")
    users = [u for u in list_all_users() if u["role"] == "manager"]
    if not users:
        print("\nNo managers found.")
    else:
        print(f"\nTotal: {len(users)}")
        print("-" * 70)
        for u in users:
            print(f"Username: {u['username']:15s} | Name: {u['first_name']} {u['last_name']} | Created: {u['created_at']}")
        print("-" * 70)
    wait_for_enter()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: EMPLOYEE DATA MANAGEMENT UI (Manager / Super Admin)
# ═══════════════════════════════════════════════════════════════════════════
# Description: User interface for managing employee personal data
#
# Key components:
# - manage_employees_menu(): Employee data management submenu
# - add_employee_ui(): Add new employee with complete profile validation
# - search_employees_ui(): Search employees by partial key
# - list_employees_ui(): Display all employees
# - update_employee_ui(): Update employee contact/personal info
# - delete_employee_ui(): Delete employee with confirmation
# ═══════════════════════════════════════════════════════════════════════════

def manage_employees_menu():
    """Menu for managing Employee data."""
    while True:
        clear_screen()
        print_header("MANAGE EMPLOYEES (DATA)")
        print_user_info()
        print("\n1. Add New Employee")
        print("2. Search Employees")
        print("3. List All Employees")
        print("4. Update Employee Information")
        print("5. Delete Employee")
        print("6. Back to Main Menu")
        try:
            choice = prompt_menu_choice("\nEnter choice (1-6): ", 1, 6)
        except CancelInputException:
            break
        if choice == "1":
            add_employee_ui()
        elif choice == "2":
            search_employees_ui()
        elif choice == "3":
            list_employees_ui()
        elif choice == "4":
            update_employee_ui()
        elif choice == "5":
            delete_employee_ui()
        elif choice == "6":
            break

def add_employee_ui():
    """Add new employee with per-field validation."""
    clear_screen()
    print_header("ADD NEW EMPLOYEE")
    print("\nEnter employee information (type 'exit' to cancel):")
    try:
        first_name = prompt_with_validation("\nFirst name: ", lambda x: validate_name(x, "First name"))
        last_name = prompt_with_validation("Last name: ", lambda x: validate_name(x, "Last name"))
        birthday = prompt_with_validation("Birthday (DD-MM-YYYY): ", validate_birthday)
        gender = prompt_choice_from_list("Select gender:", ["Male", "Female"])
        street_name = prompt_with_validation("Street name: ", lambda x: validate_name(x, "Street name"))
        house_number = prompt_with_validation("House number (digits only): ", validate_house_number)
        zip_code = prompt_with_validation("Zip code (e.g. 3011AB): ", validate_zipcode)
        city = prompt_choice_from_list("Select city:", VALID_CITIES)
        email = prompt_with_validation("Email: ", validate_email)
        mobile_phone = prompt_with_validation("Mobile phone (8 digits): +31-6-", validate_phone)
        identity_doc_type = prompt_choice_from_list("Identity document type:", ["Passport", "ID-Card"])
        identity_doc_number = prompt_with_validation("Identity document number (e.g. AB1234567 or A12345678): ", validate_identity_doc_number)
        bsn = prompt_with_validation("BSN (9 digits): ", validate_bsn)

        success, msg, emp_id = add_employee(
            first_name, last_name, birthday, gender, street_name, house_number,
            zip_code, city, email, mobile_phone, identity_doc_type, identity_doc_number, bsn)
        print(f"\n{msg}")
        if success:
            print(f"Employee ID: {emp_id}")
    except CancelInputException:
        print("\nCancelled.")
    wait_for_enter()

def search_employees_ui():
    """Search employees with partial key."""
    clear_screen()
    print_header("SEARCH EMPLOYEES")
    try:
        search_key = prompt_with_validation("Enter search term: ", validate_nonempty)
        results = search_employees(search_key)
        if not results:
            print(f"\nNo employees found matching '{search_key}'.")
        else:
            print(f"\nFound {len(results)} employee(s):")
            print("-" * 70)
            for e in results:
                print(f"ID: {e['id']} | {e['first_name']} {e['last_name']} | {e['city']} | {e['email']}")
            print("-" * 70)
    except CancelInputException:
        print("\nCancelled.")
    wait_for_enter()

def list_employees_ui():
    """List all employees."""
    clear_screen()
    print_header("ALL EMPLOYEES")
    employees = list_all_employees()
    if not employees:
        print("\nNo employees found.")
    else:
        print(f"\nTotal: {len(employees)}")
        print("-" * 70)
        for e in employees:
            print(f"ID: {e['id']} | {e['first_name']} {e['last_name']} | {e['city']} | {e['email']} | Reg: {e['registration_date']}")
        print("-" * 70)
    wait_for_enter()

def update_employee_ui():
    """Update employee information."""
    clear_screen()
    print_header("UPDATE EMPLOYEE")
    try:
        emp_id = prompt_with_validation("Enter Employee ID: ", validate_employee_id)
        emp = get_employee_by_id(emp_id)
        if not emp:
            print(f"\nEmployee with ID '{emp_id}' not found.")
            wait_for_enter()
            return
        print(f"\nCurrent: {emp['first_name']} {emp['last_name']}, {emp['city']}, {emp['email']}")
        print("Leave fields blank to keep current value. Type 'exit' to cancel.\n")

        updates = {}
        for field, label, validator in [
            ("first_name", "First name", lambda x: validate_name(x, "First name")),
            ("last_name", "Last name", lambda x: validate_name(x, "Last name")),
            ("street_name", "Street name", lambda x: validate_name(x, "Street name")),
            ("house_number", "House number", validate_house_number),
            ("zip_code", "Zip code", validate_zipcode),
            ("city", "City", validate_city),
            ("email", "Email", validate_email),
            ("mobile_phone", "Phone (8 digits)", validate_phone),
        ]:
            val = prompt_optional_field(f"New {label}", validator, current_value=emp.get(field))
            if val is not None:
                updates[field] = val

        if not updates:
            print("\nNo changes made.")
        else:
            if prompt_confirmation("\nConfirm changes? (yes/no): "):
                success, msg = update_employee(emp_id, **updates)
                print(f"\n{msg}")
            else:
                print("\nCancelled.")
    except CancelInputException:
        print("\nCancelled.")
    wait_for_enter()

def delete_employee_ui():
    """Delete employee."""
    clear_screen()
    print_header("DELETE EMPLOYEE")
    try:
        emp_id = prompt_with_validation("Enter Employee ID: ", validate_employee_id)
        emp = get_employee_by_id(emp_id)
        if not emp:
            print(f"\nEmployee with ID '{emp_id}' not found.")
            wait_for_enter()
            return
        print(f"\nEmployee: {emp['first_name']} {emp['last_name']}, {emp['city']}")
        if prompt_confirmation("\n⚠️  Delete this employee? (yes/no): "):
            success, msg = delete_employee(emp_id)
            print(f"\n{msg}")
        else:
            print("\nCancelled.")
    except CancelInputException:
        print("\nCancelled.")
    wait_for_enter()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5: EMPLOYEE USER ACCOUNT MANAGEMENT UI
# ═══════════════════════════════════════════════════════════════════════════
# Description: User interface for managing Employee login accounts
#
# Key components:
# - manage_employee_accounts_menu(): Employee user accounts submenu
# - create_employee_user_ui(): Create employee login account
# - list_employee_users_ui(): List all employee user accounts
# ═══════════════════════════════════════════════════════════════════════════

def manage_employee_accounts_menu():
    """Menu for managing Employee user accounts."""
    while True:
        clear_screen()
        print_header("MANAGE EMPLOYEE USER ACCOUNTS")
        print_user_info()
        print("\n1. Create Employee User Account")
        print("2. List Employee Users")
        print("3. Reset Employee Password")
        print("4. Delete Employee User")
        print("5. Back to Main Menu")
        try:
            choice = prompt_menu_choice("\nEnter choice (1-5): ", 1, 5)
        except CancelInputException:
            break
        if choice == "1":
            create_employee_user_ui()
        elif choice == "2":
            list_employee_users_ui()
        elif choice == "3":
            reset_password_ui("employee")
        elif choice == "4":
            delete_user_ui("employee")
        elif choice == "5":
            break

def create_employee_user_ui():
    """Create Employee user account."""
    clear_screen()
    print_header("CREATE EMPLOYEE USER ACCOUNT")
    try:
        username = prompt_with_validation("\nUsername: ", validate_username)
        first_name = prompt_with_validation("First name: ", lambda x: validate_name(x, "First name"))
        last_name = prompt_with_validation("Last name: ", lambda x: validate_name(x, "Last name"))
        emp_id_input = prompt_optional_field("Link to Employee ID (optional)", validate_employee_id)
        emp_id = int(emp_id_input) if emp_id_input else None
        success, msg, temp_pw = create_employee_user(username, first_name, last_name, employee_id=emp_id)
        print(f"\n{msg}")
        if success and temp_pw:
            print(f"Temporary password: {temp_pw}")
            print("\n⚠️  User must change this password on first login.")
    except CancelInputException:
        print("\nCancelled.")
    wait_for_enter()

def list_employee_users_ui():
    """List all Employee user accounts."""
    clear_screen()
    print_header("EMPLOYEE USER ACCOUNTS")
    users = [u for u in list_all_users() if u["role"] == "employee"]
    if not users:
        print("\nNo employee users found.")
    else:
        print(f"\nTotal: {len(users)}")
        print("-" * 70)
        for u in users:
            print(f"Username: {u['username']:15s} | Name: {u['first_name']} {u['last_name']} | Created: {u['created_at']}")
        print("-" * 70)
    wait_for_enter()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6: SHARED USER MANAGEMENT UI
# ═══════════════════════════════════════════════════════════════════════════
# Description: Reusable UI functions for user operations
#
# Key components:
# - reset_password_ui(): Reset password for any user role
# - update_profile_ui(): Update profile for any user role
# - delete_user_ui(): Delete user with confirmation
# ═══════════════════════════════════════════════════════════════════════════

def reset_password_ui(role_filter):
    """Reset user password."""
    clear_screen()
    print_header(f"RESET {role_filter.upper()} PASSWORD")
    try:
        username = prompt_with_validation(f"\nEnter {role_filter} username: ", validate_nonempty)
        success, msg, temp_pw = reset_user_password(username)
        print(f"\n{msg}")
        if success:
            print(f"New temporary password: {temp_pw}")
    except CancelInputException:
        print("\nCancelled.")
    wait_for_enter()

def update_profile_ui(role_filter):
    """Update user profile."""
    clear_screen()
    print_header(f"UPDATE {role_filter.upper()} PROFILE")
    try:
        username = prompt_with_validation(f"\nEnter {role_filter} username: ", validate_nonempty)
        first_name = prompt_optional_field("New first name", lambda x: validate_name(x, "First name"))
        last_name = prompt_optional_field("New last name", lambda x: validate_name(x, "Last name"))
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
        print("\nCancelled.")
    wait_for_enter()

def delete_user_ui(role_filter):
    """Delete user with confirmation."""
    clear_screen()
    print_header(f"DELETE {role_filter.upper()}")
    try:
        username = prompt_with_validation(f"\nEnter {role_filter} username: ", validate_nonempty)
        if prompt_confirmation(f"\n⚠️  Delete user '{username}'? (yes/no): "):
            success, msg = delete_user(username)
            print(f"\n{msg}")
        else:
            print("\nCancelled.")
    except CancelInputException:
        print("\nCancelled.")
    wait_for_enter()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7: CLAIMS MANAGEMENT UI (Manager / Super Admin)
# ═══════════════════════════════════════════════════════════════════════════
# Description: User interface for managing expense claims
#
# Key components:
# - manage_claims_menu(): Claims management submenu
# - add_claim_ui(): Add new Travel or Home Office claim
# - search_claims_ui(): Search claims with partial key
# - list_claims_ui(): Display all claims
# - approve_claim_ui(): Approve or reject a claim
# - modify_claim_ui(): Modify project-number or travel-distance
# - set_salary_batch_ui(): Link claim to salary batch
# - _display_claims_list(): Helper for displaying search results
# - _display_claims_table(): Helper for formatted claim table
# ═══════════════════════════════════════════════════════════════════════════

def manage_claims_menu():
    """Claims menu for Manager / Super Admin."""
    while True:
        clear_screen()
        print_header("MANAGE CLAIMS")
        print_user_info()
        print("\n1. Search Claims")
        print("2. List All Claims")
        print("3. Approve/Reject Claim")
        print("4. Modify Claim (project-number/travel-distance)")
        print("5. Set Salary Batch")
        print("6. Back to Main Menu")
        try:
            choice = prompt_menu_choice("\nEnter choice (1-6): ", 1, 6)
        except CancelInputException:
            break
        if choice == "1":
            search_claims_ui()
        elif choice == "2":
            list_claims_ui()
        elif choice == "3":
            approve_claim_ui()
        elif choice == "4":
            modify_claim_ui()
        elif choice == "5":
            set_salary_batch_ui()
        elif choice == "6":
            break

def add_claim_ui():
    """Add claim (Employee)."""
    clear_screen()
    print_header("ADD NEW CLAIM")
    try:
        claim_date = prompt_with_validation("Claim date (YYYY-MM-DD): ", validate_claim_date)
        project_number = prompt_with_validation("Project number (2-10 digits): ", validate_project_number)
        claim_type = prompt_choice_from_list("Claim type:", ["Travel", "Home Office"])
        travel_distance = from_zip = from_house = to_zip = to_house = None
        if claim_type == "Travel":
            travel_distance = prompt_with_validation("Travel distance (km): ", validate_travel_distance)
            from_zip = prompt_with_validation("From ZIP code: ", validate_zipcode)
            from_house = prompt_with_validation("From house number: ", validate_house_number)
            to_zip = prompt_with_validation("To ZIP code: ", validate_zipcode)
            to_house = prompt_with_validation("To house number: ", validate_house_number)
        success, msg = add_claim(claim_date, project_number, claim_type,
                                 travel_distance, from_zip, from_house, to_zip, to_house)
        print(f"\n{msg}")
    except CancelInputException:
        print("\nCancelled.")
    wait_for_enter()

def search_claims_ui(employee_filter=None):
    """Search claims with partial key."""
    clear_screen()
    print_header("SEARCH CLAIMS")
    try:
        search_key = prompt_with_validation("Enter search term: ", validate_nonempty)
        results = search_claims(search_key, employee_id_filter=employee_filter)
        _display_claims_list(results, search_key)
    except CancelInputException:
        print("\nCancelled.")
    wait_for_enter()

def list_claims_ui(employee_filter=None):
    """List all claims."""
    clear_screen()
    print_header("ALL CLAIMS")
    claims_list = list_claims(employee_id_filter=employee_filter)
    if not claims_list:
        print("\nNo claims found.")
    else:
        print(f"\nTotal: {len(claims_list)}")
        _display_claims_table(claims_list)
    wait_for_enter()

def _display_claims_list(results, search_key):
    """Display search results."""
    if not results:
        print(f"\nNo claims found matching '{search_key}'.")
    else:
        print(f"\nFound {len(results)} claim(s):")
        _display_claims_table(results)

def _display_claims_table(claims_list):
    """Display formatted claims table."""
    print("-" * 100)
    for c in claims_list:
        print(f"ID: {c['id']} | Date: {c['claim_date']} | Type: {c['claim_type']} | "
              f"Project: {c['project_number']} | Emp: {c['employee_id']} | "
              f"Status: {c['approved']} | Batch: {c['salary_batch'] or '-'}")
        if c['claim_type'] == 'Travel':
            print(f"  Distance: {c['travel_distance']}km | From: {c['from_zip_code']} {c['from_house_number']} | "
                  f"To: {c['to_zip_code']} {c['to_house_number']}")
    print("-" * 100)

def approve_claim_ui():
    """Approve or reject a claim."""
    clear_screen()
    print_header("APPROVE/REJECT CLAIM")
    try:
        claim_id = prompt_with_validation("Claim ID: ", validate_nonempty)
        claim = get_claim_by_id(claim_id)
        if not claim:
            print(f"\nClaim {claim_id} not found.")
            wait_for_enter()
            return
        print(f"\nClaim: {claim['claim_date']} | {claim['claim_type']} | Project: {claim['project_number']} | Status: {claim['approved']}")
        status = prompt_choice_from_list("Set status:", ["Approved", "Rejected"])
        success, msg = update_claim(claim_id, approved=status)
        print(f"\n{msg}")
    except CancelInputException:
        print("\nCancelled.")
    wait_for_enter()

def modify_claim_ui():
    """Modify claim project-number or travel-distance."""
    clear_screen()
    print_header("MODIFY CLAIM")
    try:
        claim_id = prompt_with_validation("Claim ID: ", validate_nonempty)
        claim = get_claim_by_id(claim_id)
        if not claim:
            print(f"\nClaim {claim_id} not found.")
            wait_for_enter()
            return
        print(f"\nCurrent: Project={claim['project_number']}, Distance={claim['travel_distance'] or 'N/A'}")
        updates = {}
        pn = prompt_optional_field("New project number", validate_project_number, current_value=claim['project_number'])
        if pn:
            updates["project_number"] = pn
        td = prompt_optional_field("New travel distance", validate_travel_distance, current_value=claim['travel_distance'])
        if td:
            updates["travel_distance"] = td
        if updates:
            success, msg = update_claim(claim_id, **updates)
            print(f"\n{msg}")
        else:
            print("\nNo changes.")
    except CancelInputException:
        print("\nCancelled.")
    wait_for_enter()

def set_salary_batch_ui():
    """Set salary batch for a claim."""
    clear_screen()
    print_header("SET SALARY BATCH")
    try:
        claim_id = prompt_with_validation("Claim ID: ", validate_nonempty)
        claim = get_claim_by_id(claim_id)
        if not claim:
            print(f"\nClaim {claim_id} not found.")
            wait_for_enter()
            return
        print(f"\nClaim status: {claim['approved']}, Current batch: {claim['salary_batch'] or 'None'}")
        batch = prompt_with_validation("Salary batch (YYYY-MM): ", validate_salary_batch)
        success, msg = update_claim(claim_id, salary_batch=batch)
        print(f"\n{msg}")
    except CancelInputException:
        print("\nCancelled.")
    wait_for_enter()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 8: EMPLOYEE CLAIMS UI (Employee role)
# ═══════════════════════════════════════════════════════════════════════════
# Description: User interface for employees managing their own claims
#
# Key components:
# - my_claims_ui(): List employee's own claims
# - search_my_claims_ui(): Search employee's own claims
# - update_my_claim_ui(): Update own claim (if not linked to salary-batch)
#
# Note: Employees can only see and modify their own claims.
#       Claims linked to a salary-batch cannot be modified or deleted.
# ═══════════════════════════════════════════════════════════════════════════

def my_claims_ui():
    """List employee's own claims."""
    user = get_current_user()
    if not user or not user.get("employee_id"):
        print("\nYour account is not linked to an employee record.")
        wait_for_enter()
        return
    list_claims_ui(employee_filter=user["employee_id"])

def search_my_claims_ui():
    """Search employee's own claims."""
    user = get_current_user()
    if not user or not user.get("employee_id"):
        print("\nYour account is not linked to an employee record.")
        wait_for_enter()
        return
    search_claims_ui(employee_filter=user["employee_id"])

def update_my_claim_ui():
    """Employee updates own claim."""
    clear_screen()
    print_header("UPDATE MY CLAIM")
    user = get_current_user()
    if not user or not user.get("employee_id"):
        print("\nYour account is not linked to an employee record.")
        wait_for_enter()
        return
    try:
        claim_id = prompt_with_validation("Claim ID: ", validate_nonempty)
        claim = get_claim_by_id(claim_id)
        if not claim:
            print(f"\nClaim {claim_id} not found.")
            wait_for_enter()
            return
        if claim["employee_id"] != user["employee_id"]:
            print("\nThis is not your claim.")
            wait_for_enter()
            return
        if claim["salary_batch"]:
            print("\nCannot modify — claim is linked to a salary batch.")
            wait_for_enter()
            return
        print(f"\nCurrent: Date={claim['claim_date']}, Project={claim['project_number']}, Type={claim['claim_type']}")
        updates = {}
        cd = prompt_optional_field("New claim date (YYYY-MM-DD)", validate_claim_date, current_value=claim['claim_date'])
        if cd:
            updates["claim_date"] = cd
        pn = prompt_optional_field("New project number", validate_project_number, current_value=claim['project_number'])
        if pn:
            updates["project_number"] = pn
        if updates:
            success, msg = update_claim(claim_id, **updates)
            print(f"\n{msg}")
        else:
            print("\nNo changes.")
    except CancelInputException:
        print("\nCancelled.")
    wait_for_enter()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 9: SYSTEM LOGS UI
# ═══════════════════════════════════════════════════════════════════════════
# Description: User interface for viewing encrypted system activity logs
#
# Key components:
# - view_logs_menu(): Logs viewing submenu
#
# Note: Logs are encrypted and only readable through the system interface.
#       Viewing logs marks them as read (resets unread suspicious count).
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
            logs = get_all_logs()
            display_logs(logs)
            mark_logs_as_read()
            wait_for_enter()
        elif choice == "2":
            logs = get_all_logs()[-20:]
            display_logs(logs)
            mark_logs_as_read()
            wait_for_enter()
        elif choice == "3":
            logs = get_all_logs()
            display_logs(logs, show_suspicious_only=True)
            mark_logs_as_read()
            wait_for_enter()
        elif choice == "4":
            break


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 10: BACKUP & RESTORE UI
# ═══════════════════════════════════════════════════════════════════════════
# Description: User interface for backup and disaster recovery
#
# Key components:
# - backup_restore_menu(): Backup/restore submenu with role-based options
# - restore_backup_ui(): Restore from backup (code validation for Managers)
# - generate_restore_code_ui(): Generate one-time restore code (Super Admin)
# - revoke_restore_code_ui(): Revoke unused restore code (Super Admin)
#
# Note: Super Admin has full access and restores directly.
#       Manager needs one-use restore code (linked to specific backup + manager).
#       Super Admin cannot use restore codes — only generate/revoke them.
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
            max_choice = 7
        else:
            print("4. Back to Main Menu")
            max_choice = 4
        choice = input("\nEnter choice: ")
        if choice == "1":
            success, msg, fn = create_backup()
            print(f"\n{msg}")
            if success:
                print(f"File: {fn}")
            wait_for_enter()
        elif choice == "2":
            backups = list_backups()
            if not backups:
                print("\nNo backups found.")
            else:
                for b in backups:
                    print(f"  {b['filename']} ({b['size']} bytes, {b['created']})")
            wait_for_enter()
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
            codes = list_restore_codes()
            if not codes:
                print("\nNo active codes.")
            else:
                for c in codes:
                    print(f"  Code: {c['code']} | User: {c['target_username']} | Backup: {c['backup_filename']}")
            wait_for_enter()
        elif choice == "7" and user and user["role"] == "super_admin":
            break
        elif choice == str(max_choice):
            break

def restore_backup_ui():
    """Restore from backup."""
    user = get_current_user()
    backups = list_backups()
    if not backups:
        print("\nNo backups found.")
        wait_for_enter()
        return
    print("\nAvailable backups:")
    for i, b in enumerate(backups, 1):
        print(f"  {i}. {b['filename']} ({b['created']})")
    choice = input(f"\nBackup number (1-{len(backups)}): ")
    try:
        idx = int(choice) - 1
        backup_fn = backups[idx]["filename"]
    except (ValueError, IndexError):
        print("\nInvalid choice.")
        wait_for_enter()
        return
    restore_code = None
    if user and user["role"] == "manager":
        restore_code = input("Enter restore code: ")
    if prompt_confirmation(f"\n⚠️  Restore from '{backup_fn}'? This overwrites current data. (yes/no): "):
        success, msg = restore_backup(backup_fn, restore_code)
        print(f"\n{msg}")
    else:
        print("\nCancelled.")
    wait_for_enter()

def generate_restore_code_ui():
    """Generate restore code (Super Admin only)."""
    backups = list_backups()
    if not backups:
        print("\nNo backups.")
        wait_for_enter()
        return
    print("\nAvailable backups:")
    for i, b in enumerate(backups, 1):
        print(f"  {i}. {b['filename']}")
    try:
        choice = prompt_menu_choice(f"\nBackup number (1-{len(backups)}): ", 1, len(backups))
        backup_fn = backups[int(choice) - 1]["filename"]
        target = prompt_with_validation("Manager username: ", validate_nonempty)
        success, msg, code = generate_restore_code(backup_fn, target)
        print(f"\n{msg}")
        if success:
            print(f"Restore code: {code}")
    except CancelInputException:
        print("\nCancelled.")
    wait_for_enter()

def revoke_restore_code_ui():
    """Revoke restore code (Super Admin only)."""
    codes = list_restore_codes()
    if not codes:
        print("\nNo active codes.")
        wait_for_enter()
        return
    for i, c in enumerate(codes, 1):
        print(f"  {i}. {c['code']} - User: {c['target_username']} - Backup: {c['backup_filename']}")
    choice = input(f"\nCode number to revoke (1-{len(codes)}): ")
    try:
        idx = int(choice) - 1
        code = codes[idx]["code"]
        if prompt_confirmation(f"\nRevoke code '{code}'? (yes/no): "):
            success, msg = revoke_restore_code(code)
            print(f"\n{msg}")
    except (ValueError, IndexError):
        print("\nInvalid choice.")
    wait_for_enter()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 11: PROFILE & PASSWORD MANAGEMENT UI
# ═══════════════════════════════════════════════════════════════════════════
# Description: User interface for viewing/managing own profile and password
#
# Key components:
# - view_my_profile_ui(): Display current user's profile
# - update_my_password_ui(): Change own password (old + new + confirm)
# - force_password_change_ui(): Force change on first login with temp password
#
# Note: Super Admin password cannot be changed (hard-coded per assignment).
#       All other users must change their temporary password on first login.
# ═══════════════════════════════════════════════════════════════════════════

def view_my_profile_ui():
    """Display current user's profile information."""
    clear_screen()
    print_header("MY PROFILE")
    user = get_current_user()
    if not user:
        print("\nNot logged in.")
        wait_for_enter()
        return
    print(f"\n{'Username:':<20} {user['username']}")
    print(f"{'First Name:':<20} {user['first_name']}")
    print(f"{'Last Name:':<20} {user['last_name']}")
    print(f"{'Role:':<20} {user['role_name']}")
    if user.get("employee_id"):
        print(f"{'Employee ID:':<20} {user['employee_id']}")
    wait_for_enter()

def update_my_password_ui():
    """Update current user's password."""
    clear_screen()
    print_header("UPDATE MY PASSWORD")
    print("\nPassword: 12-50 chars, 1 lower, 1 upper, 1 digit, 1 special char")
    try:
        current_pw = input("\nCurrent password: ")
        if not current_pw:
            print("\n❌ Cannot be empty.")
            wait_for_enter()
            return
        new_pw = prompt_password_with_confirmation("New password: ", validate_password, current_password=current_pw)
        success, msg = update_password(current_pw, new_pw)
        print(f"\n{msg}")
    except CancelInputException:
        print("\nCancelled.")
    wait_for_enter()

def force_password_change_ui():
    """Force user to change password on first login with temporary password."""
    clear_screen()
    print_header("⚠️  PASSWORD CHANGE REQUIRED")
    print("\nYou must change your temporary password before continuing.")
    print("Password: 12-50 chars, 1 lower, 1 upper, 1 digit, 1 special char")
    try:
        new_pw = prompt_password_with_confirmation("New password: ", validate_password)
        user = get_current_user()
        if not user:
            return
        from database import get_connection, hash_password
        conn = get_connection()
        cursor = conn.cursor()
        new_hash = hash_password(new_pw, user["username"])
        cursor.execute("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
                        (new_hash, user["user_id"]))
        conn.commit()
        conn.close()
        from auth import current_session
        current_session["must_change_password"] = False
        print("\n✓ Password changed successfully!")
    except CancelInputException:
        print("\n⚠️  Password change cancelled. You will be logged out.")
        logout()
    wait_for_enter()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 12: LOGIN SCREEN & MAIN PROGRAM LOOP
# ═══════════════════════════════════════════════════════════════════════════
# Description: Main application entry point and program flow control
#
# Key components:
# - login_screen(): User login interface with credential validation
# - main(): Main program loop (initialization → login → menu routing → logout)
#
# Program flow:
# 1. Initialize database and system
# 2. Display login screen (with hard-coded Super Admin credentials shown)
# 3. Force password change if using temporary password
# 4. Show role-based main menu
# 5. Route to appropriate submenu based on user choice and role
# 6. Handle logout and restart loop
# ═══════════════════════════════════════════════════════════════════════════

def login_screen():
    """Login screen."""
    clear_screen()
    print_header("DECLARATIEAPP BACKEND SYSTEM - LOGIN")
    print("\n" + "=" * 70)
    print("  HARDCODED SUPER ADMIN CREDENTIALS:")
    print("  Username: super_admin")
    print("  Password: Admin_123?")
    print("=" * 70)
    try:
        username = prompt_with_validation("\nUsername: ", validate_nonempty, allow_exit=False)
    except ValidationError:
        print("\n❌ Invalid credentials")
        wait_for_enter()
        return False
    password = input("Password: ")
    if not password:
        print("\n❌ Invalid credentials")
        wait_for_enter()
        return False
    success, message = login(username, password)
    if success:
        print(f"\n✓ {message}")
        wait_for_enter()
        user = get_current_user()
        if user and user.get("must_change_password"):
            force_password_change_ui()
        return True
    else:
        print(f"\n❌ {message}")
        wait_for_enter()
        return False

def main():
    """Main program loop."""
    print("\n" + "=" * 70)
    print("  DECLARATIEAPP BACKEND SYSTEM")
    print("  Software Quality - Analysis 8")
    print("=" * 70)
    print("\nInitializing system...")
    try:
        from database import init_database
        init_database()
    except Exception as e:
        print(f"❌ Error: {e}")
        return
    print("✓ System ready")
    wait_for_enter()

    while True:
        if not login_screen():
            retry = input("\nRetry login? (yes/no): ").strip().lower()
            if retry != "yes":
                print("\nGoodbye!")
                return
            continue

        while True:
            user = get_current_user()
            if not user:
                break
            if not show_main_menu():
                break
            choice = input("\nEnter choice: ").strip()

            if user["role"] == "super_admin":
                if choice == "1":
                    manage_managers_menu()
                elif choice == "2":
                    manage_employees_menu()
                elif choice == "3":
                    manage_employee_accounts_menu()
                elif choice == "4":
                    manage_claims_menu()
                elif choice == "5":
                    view_logs_menu()
                elif choice == "6":
                    backup_restore_menu()
                elif choice == "7":
                    view_my_profile_ui()
                elif choice == "8":
                    logout()
                    print("\n✓ Logged out")
                    wait_for_enter()
                    break
                else:
                    print("\nInvalid choice.")
                    wait_for_enter()

            elif user["role"] == "manager":
                if choice == "1":
                    manage_employees_menu()
                elif choice == "2":
                    manage_employee_accounts_menu()
                elif choice == "3":
                    manage_claims_menu()
                elif choice == "4":
                    view_logs_menu()
                elif choice == "5":
                    backup_restore_menu()
                elif choice == "6":
                    view_my_profile_ui()
                elif choice == "7":
                    update_my_password_ui()
                elif choice == "8":
                    update_profile_ui("manager")
                elif choice == "9":
                    if prompt_confirmation("\n⚠️  Delete your own account? (yes/no): "):
                        success, msg = delete_user(user["username"])
                        print(f"\n{msg}")
                        if success:
                            logout()
                            wait_for_enter()
                            break
                    wait_for_enter()
                elif choice == "10":
                    logout()
                    print("\n✓ Logged out")
                    wait_for_enter()
                    break
                else:
                    print("\nInvalid choice.")
                    wait_for_enter()

            elif user["role"] == "employee":
                if choice == "1":
                    my_claims_ui()
                elif choice == "2":
                    add_claim_ui()
                elif choice == "3":
                    search_my_claims_ui()
                elif choice == "4":
                    view_my_profile_ui()
                elif choice == "5":
                    update_my_password_ui()
                elif choice == "6":
                    logout()
                    print("\n✓ Logged out")
                    wait_for_enter()
                    break
                else:
                    print("\nInvalid choice.")
                    wait_for_enter()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram terminated by user.")
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}")
