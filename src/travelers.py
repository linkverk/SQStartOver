# ═══════════════════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Traveler/customer management imports
#
# External modules: database, validation, auth, activity_log, uuid
# ═══════════════════════════════════════════════════════════════════════════

import uuid
from database import get_connection, encrypt_field, decrypt_field
from validation import (
    validate_name,
    validate_birthday,
    validate_gender,
    validate_house_number,
    validate_zipcode,
    validate_city,
    validate_email,
    validate_phone,
    validate_driving_license,
    ValidationError,
)
from auth import get_current_user, check_permission
from activity_log import log_activity


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: CREATE OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Add new travelers/customers to the system
#
# Key components:
# - add_traveler(): Create new customer record with full validation and encryption
# - _generate_unique_customer_id(): Generate unique customer ID with collision check
# ═══════════════════════════════════════════════════════════════════════════


def add_traveler(
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
):
    """
    Create new traveler record.

    Validates all inputs, encrypts sensitive fields (email, phone, license),
    uses prepared statements, and logs activity.

    Args:
        first_name (str): First name
        last_name (str): Last name
        birthday (str): Birthday (DD-MM-YYYY)
        gender (str): Gender (Male/Female)
        street_name (str): Street name
        house_number (str): House number
        zip_code (str): Zip code (DDDDXX)
        city (str): City
        email (str): Email address
        mobile_phone (str): Mobile phone (8 digits)
        driving_license (str): Driving license (XDDDDDDD)

    Returns:
        tuple: (success: bool, message: str, customer_id: str or None)

    Example:
        success, msg, cid = add_traveler("John", "Doe", "15-03-1990", "Male", ...)
    """
    # Check permission
    if not check_permission("manage_travelers"):
        return False, "Access denied. Insufficient permissions to add travelers", None

    current_user = get_current_user()

    # Validate all inputs
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
        driving_license = validate_driving_license(driving_license)
    except ValidationError as e:
        return False, f"Validation error: {e}", None

    # Generate unique customer ID with collision check
    try:
        customer_id = _generate_unique_customer_id()
    except RuntimeError as e:
        return False, f"Failed to generate customer ID: {e}", None

    # Encrypt sensitive fields
    encrypted_email = encrypt_field(email)
    encrypted_phone = encrypt_field(mobile_phone)
    encrypted_license = encrypt_field(driving_license)
    encrypted_street = encrypt_field(street_name)
    encrypted_house = encrypt_field(house_number)
    encrypted_zip = encrypt_field(zip_code)
    encrypted_city = encrypt_field(city)

    # Insert into database
    conn = get_connection()
    cursor = conn.cursor()

    # Prepared statement to prevent SQL injection
    cursor.execute(
        """
        INSERT INTO travelers (
            customer_id, first_name, last_name, birthday, gender,
            street_name, house_number, zip_code, city,
            email, mobile_phone, driving_license
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            customer_id,
            first_name,
            last_name,
            birthday,
            gender,
            encrypted_street,
            encrypted_house,
            encrypted_zip,
            encrypted_city,
            encrypted_email,
            encrypted_phone,
            encrypted_license,
        ),
    )

    conn.commit()
    conn.close()

    # Log activity
    if current_user:
        log_activity(
            current_user["username"],
            "New traveler added",
            f"Customer ID: {customer_id}, Name: {first_name} {last_name}",
        )

    return True, f"Traveler '{first_name} {last_name}' added successfully", customer_id


def _generate_unique_customer_id():
    """
    Generate unique customer ID with collision check.

    Generates a 10-digit ID from UUID and verifies it doesn't already exist
    in the database. Retries up to 10 times if collision occurs.

    Returns:
        str: Unique 10-digit customer ID

    Raises:
        RuntimeError: If unable to generate unique ID after 10 attempts
    """
    conn = get_connection()
    cursor = conn.cursor()

    max_attempts = 10
    for _ in range(max_attempts):
        # Generate potential customer ID
        customer_id = str(uuid.uuid4().int)[:10]

        # Check if it already exists
        cursor.execute(
            "SELECT customer_id FROM travelers WHERE customer_id = ?", (customer_id,)
        )

        if cursor.fetchone() is None:
            # ID is unique
            conn.close()
            return customer_id

    conn.close()
    raise RuntimeError(
        f"Failed to generate unique customer ID after {max_attempts} attempts"
    )


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: UPDATE OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Update existing traveler information
#
# Key components:
# - update_traveler(): Update traveler fields with validation and encryption
# ═══════════════════════════════════════════════════════════════════════════


def update_traveler(customer_id, **updates):
    """
    Update traveler information.

    Validates inputs, encrypts sensitive fields if updated,
    uses prepared statements, and logs activity.

    Args:
        customer_id (str): Customer ID
        **updates: Fields to update (first_name, last_name, email, etc.)

    Returns:
        tuple: (success: bool, message: str)

    Example:
        success, msg = update_traveler("1234567890", email="new@email.com")
    """
    # Check permission
    if not check_permission("manage_travelers"):
        return False, "Access denied. Insufficient permissions to update travelers"

    current_user = get_current_user()

    if not updates:
        return False, "No fields specified for update"

    # Get current traveler data
    conn = get_connection()
    cursor = conn.cursor()

    # Prepared statement
    cursor.execute("SELECT * FROM travelers WHERE customer_id = ?", (customer_id,))

    traveler = cursor.fetchone()

    if not traveler:
        conn.close()
        return False, f"Traveler with customer ID '{customer_id}' not found"

    # Validate and prepare updates
    update_fields = []
    params = []
    changes = []

    allowed_fields = {
        "first_name",
        "last_name",
        "birthday",
        "gender",
        "street_name",
        "house_number",
        "zip_code",
        "city",
        "email",
        "mobile_phone",
        "driving_license",
    }

    for field, value in updates.items():
        if field not in allowed_fields:
            conn.close()
            return False, f"Invalid field: {field}"

        try:
            # Validate based on field type
            if field in ["first_name", "last_name"]:
                value = validate_name(value, field.replace("_", " ").title())
            elif field == "birthday":
                value = validate_birthday(value)
            elif field == "gender":
                value = validate_gender(value)
            elif field == "street_name":
                value = validate_name(value, "Street name")
                value = encrypt_field(value)
            elif field == "house_number":
                value = validate_house_number(value)
                value = encrypt_field(value)
            elif field == "zip_code":
                value = validate_zipcode(value)
                value = encrypt_field(value)
            elif field == "city":
                value = validate_city(value)
                value = encrypt_field(value)
            elif field == "email":
                value = validate_email(value)
                value = encrypt_field(value)
            elif field == "mobile_phone":
                value = validate_phone(value)
                value = encrypt_field(value)
            elif field == "driving_license":
                value = validate_driving_license(value)
                value = encrypt_field(value)
        except ValidationError as e:
            conn.close()
            return False, f"Validation error for {field}: {e}"

        update_fields.append(f"{field} = ?")
        params.append(value)
        changes.append(field)

    params.append(customer_id)

    # Prepared statement for UPDATE
    cursor.execute(
        f"UPDATE travelers SET {', '.join(update_fields)} WHERE customer_id = ?",
        tuple(params),
    )

    conn.commit()
    conn.close()

    # Log activity
    if current_user:
        log_activity(
            current_user["username"],
            "Traveler updated",
            f"Customer ID: {customer_id}, Updated fields: {', '.join(changes)}",
        )

    return True, f"Traveler updated successfully"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: DELETE OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Delete traveler records
#
# Key components:
# - delete_traveler(): Remove traveler from system with confirmation
# ═══════════════════════════════════════════════════════════════════════════


def delete_traveler(customer_id):
    """
    Delete traveler record.

    Uses prepared statements and logs activity.

    Args:
        customer_id (str): Customer ID to delete

    Returns:
        tuple: (success: bool, message: str)

    Example:
        success, msg = delete_traveler("1234567890")
    """
    # Check permission
    if not check_permission("manage_travelers"):
        return False, "Access denied. Insufficient permissions to delete travelers"

    current_user = get_current_user()

    # Check if traveler exists
    conn = get_connection()
    cursor = conn.cursor()

    # Prepared statement
    cursor.execute(
        "SELECT first_name, last_name FROM travelers WHERE customer_id = ?",
        (customer_id,),
    )

    traveler = cursor.fetchone()

    if not traveler:
        conn.close()
        return False, f"Traveler with customer ID '{customer_id}' not found"

    first_name, last_name = traveler

    # Prepared statement for DELETE
    cursor.execute("DELETE FROM travelers WHERE customer_id = ?", (customer_id,))

    conn.commit()
    conn.close()

    # Log activity
    if current_user:
        log_activity(
            current_user["username"],
            "Traveler deleted",
            f"Customer ID: {customer_id}, Name: {first_name} {last_name}",
        )

    return True, f"Traveler '{first_name} {last_name}' deleted successfully"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: SEARCH & RETRIEVAL OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Search and retrieve traveler information
#
# Key components:
# - search_travelers(): Partial key search in names and customer ID
# - get_traveler_by_id(): Get specific traveler by customer ID
# - list_all_travelers(): Get all travelers with decrypted data
# ═══════════════════════════════════════════════════════════════════════════


def search_travelers(search_key):
    """
    Search travelers with partial key matching.

    Accepts partial keys in: customer_id, first_name, last_name.

    Args:
        search_key (str): Search term (e.g., "mik", "omso", "2328")

    Returns:
        list: Matching traveler dictionaries

    Example:
        results = search_travelers("john")
        # Finds: "John", "Johnny", etc.
    """
    if not search_key or len(search_key) < 2:
        return []

    conn = get_connection()
    cursor = conn.cursor()

    # Prepared statement with LIKE for partial matching
    search_pattern = f"%{search_key}%"

    cursor.execute(
        """
        SELECT * FROM travelers
        WHERE customer_id LIKE ?
           OR LOWER(first_name) LIKE LOWER(?)
           OR LOWER(last_name) LIKE LOWER(?)
        ORDER BY first_name, last_name
        """,
        (search_pattern, search_pattern, search_pattern),
    )

    results = cursor.fetchall()
    conn.close()

    travelers = []
    for row in results:
        travelers.append(
            {
                "id": row[0],
                "customer_id": row[1],
                "first_name": row[2],
                "last_name": row[3],
                "birthday": row[4],
                "gender": row[5],
                "street_name": decrypt_field(row[6]),
                "house_number": decrypt_field(row[7]),
                "zip_code": decrypt_field(row[8]),
                "city": decrypt_field(row[9]),
                "email": decrypt_field(row[10]),
                "mobile_phone": decrypt_field(row[11]),
                "driving_license": decrypt_field(row[12]),
                "registration_date": row[13],
            }
        )

    return travelers


def get_traveler_by_id(customer_id):
    """
    Get specific traveler by customer ID.

    Args:
        customer_id (str): Customer ID

    Returns:
        dict: Traveler information or None if not found

    Example:
        traveler = get_traveler_by_id("1234567890")
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Prepared statement
    cursor.execute("SELECT * FROM travelers WHERE customer_id = ?", (customer_id,))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "customer_id": row[1],
        "first_name": row[2],
        "last_name": row[3],
        "birthday": row[4],
        "gender": row[5],
        "street_name": decrypt_field(row[6]),
        "house_number": decrypt_field(row[7]),
        "zip_code": decrypt_field(row[8]),
        "city": decrypt_field(row[9]),
        "email": decrypt_field(row[10]),
        "mobile_phone": decrypt_field(row[11]),
        "driving_license": decrypt_field(row[12]),
        "registration_date": row[13],
    }


def list_all_travelers():
    """
    Get all travelers.

    Returns:
        list: List of traveler dictionaries

    Example:
        travelers = list_all_travelers()
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM travelers ORDER BY first_name, last_name")

    results = cursor.fetchall()
    conn.close()

    travelers = []
    for row in results:
        travelers.append(
            {
                "id": row[0],
                "customer_id": row[1],
                "first_name": row[2],
                "last_name": row[3],
                "birthday": row[4],
                "gender": row[5],
                "street_name": decrypt_field(row[6]),
                "house_number": decrypt_field(row[7]),
                "zip_code": decrypt_field(row[8]),
                "city": decrypt_field(row[9]),
                "email": decrypt_field(row[10]),
                "mobile_phone": decrypt_field(row[11]),
                "driving_license": decrypt_field(row[12]),
                "registration_date": row[13],
            }
        )

    return travelers
