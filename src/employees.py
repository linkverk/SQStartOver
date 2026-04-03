# ═══════════════════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Employee data management imports
#
# External modules: database, validation, auth, activity_log
# ═══════════════════════════════════════════════════════════════════════════

from database import get_connection, encrypt_field, decrypt_field
from validation import (
    validate_name, validate_birthday, validate_gender, validate_house_number,
    validate_zipcode, validate_city, validate_email, validate_phone,
    validate_identity_doc_type, validate_identity_doc_number, validate_bsn,
    validate_employee_id, ValidationError,
)
from auth import get_current_user, check_permission
from activity_log import log_activity


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: CREATE OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Add new employees to the system
#
# Key components:
# - add_employee(): Create new employee record with full validation and encryption
#
# Note: Employee ID and registration date are automatically generated.
#       All sensitive fields are encrypted with Fernet before storage.
#       Employee data includes: name, birthday, gender, address, email, phone,
#       identity document (Passport/ID-Card), BSN number.
# ═══════════════════════════════════════════════════════════════════════════


def add_employee(first_name, last_name, birthday, gender, street_name, house_number,
                 zip_code, city, email, mobile_phone, identity_doc_type,
                 identity_doc_number, bsn):
    """
    Register a new employee in the system.

    Employee ID and registration date are auto-generated.
    Sensitive fields are encrypted with Fernet.

    Args:
        first_name (str): Employee's given name
        last_name (str): Employee's family name
        birthday (str): Date of birth (DD-MM-YYYY)
        gender (str): Male or Female
        street_name (str): Street name
        house_number (str): House number (digits only)
        zip_code (str): Postal code (DDDDXX)
        city (str): City (from predefined list)
        email (str): Email address
        mobile_phone (str): Mobile phone (8 digits, auto-formatted to +31-6-DDDDDDDD)
        identity_doc_type (str): Passport or ID-Card
        identity_doc_number (str): XXDDDDDDD or XDDDDDDDD
        bsn (str): BSN number (9 digits)

    Returns:
        tuple: (success: bool, message: str, employee_id: str or None)

    Example:
        success, msg, emp_id = add_employee("Jan", "de Vries", "15-03-1990", "Male", ...)
    """
    if not check_permission("manage_employees"):
        return False, "Access denied. Insufficient permissions to add employees", None

    current_user = get_current_user()

    # Validate all inputs (whitelisting approach)
    try:
        first_name = validate_name(first_name, "First name")
        last_name = validate_name(last_name, "Last name")
        birthday = validate_birthday(birthday)
        gender = validate_gender(gender)
        street_name = validate_name(street_name, "Street name")
        house_number = validate_house_number(house_number)
        zip_code = validate_zipcode(zip_code)
        city = validate_city(city)
        email = validate_email(email)
        mobile_phone = validate_phone(mobile_phone)
        identity_doc_type = validate_identity_doc_type(identity_doc_type)
        identity_doc_number = validate_identity_doc_number(identity_doc_number)
        bsn = validate_bsn(bsn)
    except ValidationError as e:
        return False, f"Validation error: {e}", None

    # Encrypt all sensitive fields with Fernet (non-deterministic)
    enc_first_name = encrypt_field(first_name)
    enc_last_name = encrypt_field(last_name)
    enc_birthday = encrypt_field(birthday)
    enc_gender = encrypt_field(gender)
    enc_street = encrypt_field(street_name)
    enc_house = encrypt_field(house_number)
    enc_zip = encrypt_field(zip_code)
    enc_city = encrypt_field(city)
    enc_email = encrypt_field(email)
    enc_phone = encrypt_field(mobile_phone)
    enc_doc_type = encrypt_field(identity_doc_type)
    enc_doc_number = encrypt_field(identity_doc_number)
    enc_bsn = encrypt_field(bsn)

    conn = get_connection()
    cursor = conn.cursor()

    # Prepared statement to prevent SQL injection
    cursor.execute(
        """
        INSERT INTO employees (first_name, last_name, birthday, gender,
            street_name, house_number, zip_code, city, email, mobile_phone,
            identity_doc_type, identity_doc_number, bsn)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (enc_first_name, enc_last_name, enc_birthday, enc_gender,
         enc_street, enc_house, enc_zip, enc_city, enc_email, enc_phone,
         enc_doc_type, enc_doc_number, enc_bsn),
    )
    employee_id = cursor.lastrowid
    conn.commit()
    conn.close()

    if current_user:
        log_activity(current_user["username"], "New employee added",
                     f"Employee ID: {employee_id}, Name: {first_name} {last_name}")

    return True, f"Employee '{first_name} {last_name}' added successfully", str(employee_id)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: UPDATE OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Update existing employee information
#
# Key components:
# - update_employee(): Update employee fields with validation and re-encryption
#
# Note: All updated fields are validated and re-encrypted before storage.
#       Uses prepared statements to prevent SQL injection.
# ═══════════════════════════════════════════════════════════════════════════


def update_employee(employee_id, **updates):
    """
    Update employee information.

    Validates inputs, encrypts updated fields, uses prepared statements.

    Args:
        employee_id (str): Employee ID to update
        **updates: Fields to update (e.g., email="new@email.com")

    Returns:
        tuple: (success: bool, message: str)

    Example:
        success, msg = update_employee("1", email="newemail@example.com", city="Rotterdam")
    """
    if not check_permission("manage_employees"):
        return False, "Access denied. Insufficient permissions to update employees"

    current_user = get_current_user()
    if not updates:
        return False, "No fields specified for update"

    conn = get_connection()
    cursor = conn.cursor()

    # Prepared statement
    cursor.execute("SELECT * FROM employees WHERE id = ?", (int(employee_id),))
    employee = cursor.fetchone()
    if not employee:
        conn.close()
        return False, f"Employee with ID '{employee_id}' not found"

    allowed_fields = {
        "first_name", "last_name", "birthday", "gender", "street_name",
        "house_number", "zip_code", "city", "email", "mobile_phone",
        "identity_doc_type", "identity_doc_number", "bsn",
    }

    update_fields = []
    params = []
    changes = []

    for field, value in updates.items():
        if field not in allowed_fields:
            conn.close()
            return False, f"Invalid field: {field}"

        # Validate each field using whitelisting
        try:
            if field in ["first_name", "last_name"]:
                value = validate_name(value, field.replace("_", " ").title())
            elif field == "birthday":
                value = validate_birthday(value)
            elif field == "gender":
                value = validate_gender(value)
            elif field == "street_name":
                value = validate_name(value, "Street name")
            elif field == "house_number":
                value = validate_house_number(value)
            elif field == "zip_code":
                value = validate_zipcode(value)
            elif field == "city":
                value = validate_city(value)
            elif field == "email":
                value = validate_email(value)
            elif field == "mobile_phone":
                value = validate_phone(value)
            elif field == "identity_doc_type":
                value = validate_identity_doc_type(value)
            elif field == "identity_doc_number":
                value = validate_identity_doc_number(value)
            elif field == "bsn":
                value = validate_bsn(value)
        except ValidationError as e:
            conn.close()
            return False, f"Validation error for {field}: {e}"

        # Re-encrypt the validated value
        encrypted_value = encrypt_field(value)
        update_fields.append(f"{field} = ?")
        params.append(encrypted_value)
        changes.append(field)

    params.append(int(employee_id))

    # Prepared statement for UPDATE
    cursor.execute(f"UPDATE employees SET {', '.join(update_fields)} WHERE id = ?",
                   tuple(params))
    conn.commit()
    conn.close()

    if current_user:
        log_activity(current_user["username"], "Employee updated",
                     f"Employee ID: {employee_id}, Updated fields: {', '.join(changes)}")
    return True, "Employee updated successfully"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: DELETE OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Delete employee records
#
# Key components:
# - delete_employee(): Remove employee from system
#
# Note: Deleting an employee also cascades to related claims (ON DELETE CASCADE).
#       Uses prepared statements to prevent SQL injection.
# ═══════════════════════════════════════════════════════════════════════════


def delete_employee(employee_id):
    """
    Delete employee record.

    Args:
        employee_id (str): Employee ID to delete

    Returns:
        tuple: (success: bool, message: str)

    Example:
        success, msg = delete_employee("1")
    """
    if not check_permission("manage_employees"):
        return False, "Access denied. Insufficient permissions to delete employees"

    current_user = get_current_user()
    conn = get_connection()
    cursor = conn.cursor()

    # Prepared statement
    cursor.execute("SELECT first_name, last_name FROM employees WHERE id = ?",
                   (int(employee_id),))
    employee = cursor.fetchone()
    if not employee:
        conn.close()
        return False, f"Employee with ID '{employee_id}' not found"

    enc_first, enc_last = employee
    first_name = decrypt_field(enc_first)
    last_name = decrypt_field(enc_last)

    # Prepared statement for DELETE
    cursor.execute("DELETE FROM employees WHERE id = ?", (int(employee_id),))
    conn.commit()
    conn.close()

    if current_user:
        log_activity(current_user["username"], "Employee deleted",
                     f"Employee ID: {employee_id}, Name: {first_name} {last_name}")
    return True, f"Employee '{first_name} {last_name}' deleted successfully"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: SEARCH & RETRIEVAL OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Search and retrieve employee information
#
# Key components:
# - _decrypt_employee_row(): Internal helper to decrypt all fields in a row
# - search_employees(): Partial key search across all decrypted fields
# - get_employee_by_id(): Get specific employee by ID
# - list_all_employees(): Get all employees with decrypted data
#
# Note: Since all employee data is Fernet-encrypted (non-deterministic),
#       searching requires decrypting all records and filtering in Python.
#       This supports the partial key search requirement (Note 2 in assignment):
#       e.g., searching "1218", "18 A", or "AK" for zip "1218 AK".
# ═══════════════════════════════════════════════════════════════════════════


def _decrypt_employee_row(row):
    """
    Decrypt all encrypted fields in an employee database row.

    Args:
        row (tuple): Raw database row (15 columns)

    Returns:
        dict: Employee data with all fields decrypted
    """
    return {
        "id": row[0],
        "first_name": decrypt_field(row[1]),
        "last_name": decrypt_field(row[2]),
        "birthday": decrypt_field(row[3]),
        "gender": decrypt_field(row[4]),
        "street_name": decrypt_field(row[5]),
        "house_number": decrypt_field(row[6]),
        "zip_code": decrypt_field(row[7]),
        "city": decrypt_field(row[8]),
        "email": decrypt_field(row[9]),
        "mobile_phone": decrypt_field(row[10]),
        "identity_doc_type": decrypt_field(row[11]),
        "identity_doc_number": decrypt_field(row[12]),
        "bsn": decrypt_field(row[13]),
        "registration_date": row[14],
    }


def search_employees(search_key):
    """
    Search employees with partial key matching.

    Since all data is encrypted, we must decrypt all records and filter in Python.
    Accepts partial keys (e.g., "1218", "18 A", or "AK" for zip "1218 AK").

    Args:
        search_key (str): Search term (partial match)

    Returns:
        list: Matching employee dictionaries

    Example:
        results = search_employees("jan")     # Finds "Jan", "Jansen", etc.
        results = search_employees("3011")    # Finds zip codes containing "3011"
        results = search_employees("123456")  # Finds BSN or doc numbers
    """
    if not search_key or len(search_key) < 1:
        return []

    search_key_lower = search_key.lower().strip()

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM employees ORDER BY id")
    results = cursor.fetchall()
    conn.close()

    matches = []
    for row in results:
        emp = _decrypt_employee_row(row)
        # Build searchable string from all decrypted text fields
        searchable = " ".join([
            str(emp["id"]),
            emp["first_name"], emp["last_name"], emp["birthday"],
            emp["gender"], emp["street_name"], emp["house_number"],
            emp["zip_code"], emp["city"], emp["email"],
            emp["mobile_phone"], emp["identity_doc_type"],
            emp["identity_doc_number"], emp["bsn"],
        ]).lower()
        if search_key_lower in searchable:
            matches.append(emp)

    return matches


def get_employee_by_id(employee_id):
    """
    Get specific employee by ID.

    Args:
        employee_id (str or int): Employee ID

    Returns:
        dict: Employee information, or None if not found

    Example:
        employee = get_employee_by_id("1")
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Prepared statement
    cursor.execute("SELECT * FROM employees WHERE id = ?", (int(employee_id),))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None
    return _decrypt_employee_row(row)


def list_all_employees():
    """
    Get all employees with decrypted data.

    Returns:
        list: List of employee dictionaries

    Example:
        employees = list_all_employees()
        for emp in employees:
            print(f"{emp['first_name']} {emp['last_name']} - {emp['city']}")
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM employees ORDER BY id")
    results = cursor.fetchall()
    conn.close()

    return [_decrypt_employee_row(row) for row in results]
