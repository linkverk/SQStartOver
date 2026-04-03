# ═══════════════════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Input validation libraries
#
# External libraries:
# - re: Regular expressions for format validation
# - datetime: Date validation and range checking
# - activity_log: Security monitoring for null-byte attacks
# ═══════════════════════════════════════════════════════════════════════════

import re
from datetime import datetime, timedelta
from activity_log import log_activity


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: CUSTOM EXCEPTIONS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Custom exception for validation errors
#
# Key components:
# - ValidationError: Raised when input validation fails
# ═══════════════════════════════════════════════════════════════════════════


class ValidationError(Exception):
    """Custom exception for input validation failures."""
    pass


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Internal helper functions for validation
#
# Key components:
# - _check_null_bytes(): Check for null bytes in string input
#
# Note: Null bytes should never be present in non-binary input and can
#       indicate attack attempts (null-byte injection). All validators
#       call this function before processing input.
# ═══════════════════════════════════════════════════════════════════════════


def _check_null_bytes(value, field_name):
    """
    Check for null bytes in string input (null-byte injection protection).

    Args:
        value: The value to check
        field_name (str): Name of the field being validated (for logging)

    Raises:
        ValidationError: If null byte is detected
    """
    if isinstance(value, str) and "\0" in value:
        log_activity(
            username="SYSTEM",
            activity="Null-byte attack detected",
            additional_info=f"Field: {field_name}, Value: {repr(value[:50])}",
            suspicious=True,
        )
        raise ValidationError(f"{field_name} contains invalid null-byte character")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: USER CREDENTIAL VALIDATION
# ═══════════════════════════════════════════════════════════════════════════
# Description: Validate username and password formats
#
# Key components:
# - validate_username(): 8-10 chars, specific character rules, case-insensitive
# - validate_password(): 12-50 chars, complexity requirements
#
# Username rules:
# - Must be unique, 8-10 characters (except super_admin)
# - Must start with letter or underscore
# - Can contain: a-z, 0-9, _, ', .
# - Case-insensitive (stored as lowercase)
#
# Password rules:
# - 12-50 characters
# - At least 1 lowercase, 1 uppercase, 1 digit, 1 special character
# ═══════════════════════════════════════════════════════════════════════════


def validate_username(username):
    """
    Validate username format.

    Args:
        username (str): Username to validate

    Returns:
        str: Validated username (lowercase)

    Raises:
        ValidationError: If username is invalid
    """
    if not isinstance(username, str):
        raise ValidationError("Username must be a string")
    _check_null_bytes(username, "Username")
    username = username.lower().strip()

    if username == "super_admin":
        return username

    if len(username) < 8:
        raise ValidationError("Username must be at least 8 characters long")
    if len(username) > 10:
        raise ValidationError("Username must be at most 10 characters long")
    if not re.match(r"^[a-z_]", username):
        raise ValidationError("Username must start with a lowercase letter or underscore")
    if not re.match(r"^[a-z0-9_'.]+$", username):
        raise ValidationError("Username can only contain lowercase letters, digits, underscore, apostrophe, and period")
    return username


def validate_password(password):
    """
    Validate password strength.

    Args:
        password (str): Password to validate

    Returns:
        str: Validated password (unchanged)

    Raises:
        ValidationError: If password is invalid
    """
    if not isinstance(password, str):
        raise ValidationError("Password must be a string")
    _check_null_bytes(password, "Password")

    if len(password) < 12:
        raise ValidationError("Password must be at least 12 characters long")
    if len(password) > 50:
        raise ValidationError("Password must be at most 50 characters long")
    if not re.search(r"[a-z]", password):
        raise ValidationError("Password must contain at least 1 lowercase letter")
    if not re.search(r"[A-Z]", password):
        raise ValidationError("Password must contain at least 1 uppercase letter")
    if not re.search(r"\d", password):
        raise ValidationError("Password must contain at least 1 digit")
    if not re.search(r"[~!@#$%&_\-+=`|\\(){}[\]:;'<>,.?/]", password):
        raise ValidationError("Password must contain at least 1 special character (~!@#$%&_-+=`|\\(){}[]:;'<>,.?/)")
    return password


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: CONTACT INFORMATION VALIDATION
# ═══════════════════════════════════════════════════════════════════════════
# Description: Validate email and phone number formats
#
# Key components:
# - validate_email(): RFC-compliant email format, max 50 chars
# - validate_phone(): Dutch mobile format (+31-6-DDDDDDDD)
#
# Note: Phone numbers accept 8 digits and auto-format to +31-6-DDDDDDDD
# ═══════════════════════════════════════════════════════════════════════════


def validate_email(email):
    """
    Validate email format.

    Args:
        email (str): Email to validate

    Returns:
        str: Validated email (lowercase)

    Raises:
        ValidationError: If email is invalid
    """
    if not isinstance(email, str):
        raise ValidationError("Email must be a string")
    _check_null_bytes(email, "Email")
    email = email.strip().lower()
    if len(email) > 50:
        raise ValidationError("Email cannot be longer than 50 characters")
    email_pattern = r"^[a-z0-9._+-]+@[a-z0-9.-]+\.[a-z]{2,}$"
    if not re.match(email_pattern, email):
        raise ValidationError("Invalid email format")
    return email


def validate_phone(phone):
    """
    Validate and format Dutch mobile phone number.

    Accepts 8 digits (DDDDDDDD) or already formatted (+31-6-DDDDDDDD).
    Output: +31-6-DDDDDDDD

    Args:
        phone (str): Phone number

    Returns:
        str: Formatted phone (+31-6-DDDDDDDD)

    Raises:
        ValidationError: If phone is invalid
    """
    if not isinstance(phone, str):
        raise ValidationError("Phone number must be a string")
    _check_null_bytes(phone, "Phone")
    phone = phone.strip()
    if re.match(r"^\+31-6-\d{8}$", phone):
        return phone
    if not re.match(r"^\d{8}$", phone):
        raise ValidationError("Phone number must be exactly 8 digits")
    return f"+31-6-{phone}"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5: ADDRESS VALIDATION
# ═══════════════════════════════════════════════════════════════════════════
# Description: Validate address components (Dutch format)
#
# Key components:
# - validate_zipcode(): Dutch postal code (DDDDXX format)
# - validate_house_number(): House number (digits only per assignment)
# - validate_city(): City from predefined list of 10 cities
#
# Note: ZIP code format is DDDDXX (4 digits + 2 uppercase letters).
#       House numbers are digits only per assignment Table 3/4.
# ═══════════════════════════════════════════════════════════════════════════


def validate_zipcode(zipcode):
    """
    Validate Dutch zipcode format: DDDDXX (4 digits + 2 letters).

    Args:
        zipcode (str): Zipcode to validate

    Returns:
        str: Validated zipcode in UPPERCASE format

    Raises:
        ValidationError: If zipcode is invalid
    """
    if not isinstance(zipcode, str):
        raise ValidationError("Zipcode must be a string")
    _check_null_bytes(zipcode, "Zipcode")
    zipcode = zipcode.strip().upper().replace(" ", "")
    if not re.match(r"^\d{4}[A-Z]{2}$", zipcode):
        raise ValidationError("Invalid zipcode format. Expected: DDDDXX (e.g. 3011AB)")
    return zipcode


def validate_house_number(house_number):
    """
    Validate house number: digits only.

    Args:
        house_number (str): House number to validate

    Returns:
        str: Validated house number

    Raises:
        ValidationError: If house number is invalid
    """
    if not isinstance(house_number, str):
        raise ValidationError("House number must be a string")
    _check_null_bytes(house_number, "House number")
    house_number = house_number.strip()
    if not house_number:
        raise ValidationError("House number cannot be empty")
    if not re.match(r"^\d+$", house_number):
        raise ValidationError("House number must contain only digits")
    return house_number


VALID_CITIES = [
    "Amsterdam", "Rotterdam", "Utrecht", "Den Haag", "Eindhoven",
    "Groningen", "Tilburg", "Almere", "Breda", "Nijmegen",
]


def validate_city(city):
    """
    Validate city against predefined list of 10 Dutch cities.

    Args:
        city (str): City to validate

    Returns:
        str: Validated city

    Raises:
        ValidationError: If city is not in predefined list
    """
    if not isinstance(city, str):
        raise ValidationError("City must be a string")
    _check_null_bytes(city, "City")
    city = city.strip()
    if city not in VALID_CITIES:
        raise ValidationError(f"City must be one of: {', '.join(VALID_CITIES)}")
    return city


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6: PERSONAL INFORMATION VALIDATION
# ═══════════════════════════════════════════════════════════════════════════
# Description: Validate personal data (names, dates, gender, identity documents)
#
# Key components:
# - validate_name(): Names and street names (letters, spaces, hyphens, apostrophes)
# - validate_birthday(): Date in DD-MM-YYYY format with calendar validation
# - validate_gender(): Male or Female
# - validate_identity_doc_type(): Passport or ID-Card
# - validate_identity_doc_number(): XXDDDDDDD or XDDDDDDDD format
# - validate_bsn(): BSN number (exactly 9 digits)
#
# Note: Identity document formats per assignment Table 2.
# ═══════════════════════════════════════════════════════════════════════════


def validate_name(name, field_name="Name"):
    """
    Validate names (first name, last name, street name).

    Rules: 1-50 characters, only letters, spaces, hyphens, apostrophes.

    Args:
        name (str): Name to validate
        field_name (str): Field name for error messages

    Returns:
        str: Validated name

    Raises:
        ValidationError: If name is invalid
    """
    if not isinstance(name, str):
        raise ValidationError(f"{field_name} must be a string")
    _check_null_bytes(name, field_name)
    name = name.strip()
    if not name:
        raise ValidationError(f"{field_name} cannot be empty")
    if len(name) > 50:
        raise ValidationError(f"{field_name} cannot be longer than 50 characters")
    if not re.match(r"^[a-zA-Z\s\-']+$", name):
        raise ValidationError(f"{field_name} can only contain letters, spaces, hyphens, and apostrophes")
    return name


def validate_birthday(date_str):
    """
    Validate birthday format (DD-MM-YYYY) and check valid calendar date.

    Args:
        date_str (str): Birthday date string

    Returns:
        str: Validated birthday (DD-MM-YYYY)

    Raises:
        ValidationError: If birthday is invalid or in the future
    """
    if not isinstance(date_str, str):
        raise ValidationError("Birthday must be a string")
    _check_null_bytes(date_str, "Birthday")
    date_str = date_str.strip()
    if not re.match(r"^\d{2}-\d{2}-\d{4}$", date_str):
        raise ValidationError("Invalid birthday format. Expected: DD-MM-YYYY")
    try:
        day, month, year = map(int, date_str.split("-"))
        date_obj = datetime(year, month, day)
    except ValueError:
        raise ValidationError("Invalid birthday. Please enter a valid calendar date")
    today = datetime.now()
    if date_obj > today:
        raise ValidationError("Birthday cannot be in the future")
    earliest_allowed = datetime(today.year - 150, today.month, today.day)
    if date_obj < earliest_allowed:
        raise ValidationError("Birthday cannot be more than 150 years in the past")
    return date_str


def validate_gender(gender):
    """
    Validate gender value: Male or Female.

    Args:
        gender (str): Gender to validate

    Returns:
        str: Validated gender

    Raises:
        ValidationError: If gender is invalid
    """
    if not isinstance(gender, str):
        raise ValidationError("Gender must be a string")
    _check_null_bytes(gender, "Gender")
    gender = gender.strip()
    if gender not in ["Male", "Female"]:
        raise ValidationError("Gender must be 'Male' or 'Female'")
    return gender


def validate_identity_doc_type(doc_type):
    """
    Validate identity document type: Passport or ID-Card.

    Args:
        doc_type (str): Document type to validate

    Returns:
        str: Validated document type

    Raises:
        ValidationError: If document type is invalid
    """
    if not isinstance(doc_type, str):
        raise ValidationError("Identity document type must be a string")
    _check_null_bytes(doc_type, "Identity document type")
    doc_type = doc_type.strip()
    if doc_type not in ["Passport", "ID-Card"]:
        raise ValidationError("Identity document type must be 'Passport' or 'ID-Card'")
    return doc_type


def validate_identity_doc_number(doc_number):
    """
    Validate identity document number.

    Format: XXDDDDDDD (2 letters + 7 digits) or XDDDDDDDD (1 letter + 8 digits).

    Args:
        doc_number (str): Document number to validate

    Returns:
        str: Validated document number (uppercase)

    Raises:
        ValidationError: If document number is invalid
    """
    if not isinstance(doc_number, str):
        raise ValidationError("Identity document number must be a string")
    _check_null_bytes(doc_number, "Identity document number")
    doc_number = doc_number.strip().upper()
    if not (re.match(r"^[A-Z]{2}\d{7}$", doc_number) or re.match(r"^[A-Z]\d{8}$", doc_number)):
        raise ValidationError("Invalid identity document number format. Expected: XXDDDDDDD or XDDDDDDDD")
    return doc_number


def validate_bsn(bsn):
    """
    Validate BSN (Burger Service Nummer): exactly 9 digits.

    Args:
        bsn (str): BSN to validate

    Returns:
        str: Validated BSN

    Raises:
        ValidationError: If BSN is invalid
    """
    if not isinstance(bsn, str):
        raise ValidationError("BSN must be a string")
    _check_null_bytes(bsn, "BSN")
    bsn = bsn.strip()
    if not re.match(r"^\d{9}$", bsn):
        raise ValidationError("BSN must be exactly 9 digits")
    return bsn


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7: CLAIM VALIDATION
# ═══════════════════════════════════════════════════════════════════════════
# Description: Validate expense claim data
#
# Key components:
# - validate_claim_date(): ISO 8601 (YYYY-MM-DD), max 2 months back / 14 days ahead
# - validate_project_number(): 2-10 digit characters
# - validate_claim_type(): Travel or Home Office
# - validate_travel_distance(): Positive digits (km)
# - validate_salary_batch(): YYYY-MM format
# - validate_approval_status(): Pending, Approved, or Rejected
# - validate_employee_id(): Positive digits
#
# Note: Claim date range is relative to current system date per assignment.
# ═══════════════════════════════════════════════════════════════════════════


def validate_claim_date(date_str):
    """
    Validate claim date in ISO 8601 format (YYYY-MM-DD).

    Must not be older than 2 months or more than 14 days in the future.

    Args:
        date_str (str): Claim date string

    Returns:
        str: Validated claim date

    Raises:
        ValidationError: If claim date is invalid or out of range
    """
    if not isinstance(date_str, str):
        raise ValidationError("Claim date must be a string")
    _check_null_bytes(date_str, "Claim date")
    date_str = date_str.strip()
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", date_str):
        raise ValidationError("Invalid claim date format. Expected: YYYY-MM-DD")
    try:
        year, month, day = map(int, date_str.split("-"))
        date_obj = datetime(year, month, day)
    except ValueError:
        raise ValidationError("Invalid claim date. Please enter a valid calendar date")

    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    two_months_ago = today - timedelta(days=60)
    fourteen_days_ahead = today + timedelta(days=14)

    if date_obj.replace(hour=0, minute=0, second=0, microsecond=0) < two_months_ago:
        raise ValidationError("Claim date cannot be older than 2 months")
    if date_obj.replace(hour=0, minute=0, second=0, microsecond=0) > fourteen_days_ahead:
        raise ValidationError("Claim date cannot be more than 14 days in the future")
    return date_str


def validate_project_number(project_number):
    """
    Validate project number: 2-10 digit characters.

    Args:
        project_number (str): Project number to validate

    Returns:
        str: Validated project number

    Raises:
        ValidationError: If project number is invalid
    """
    if not isinstance(project_number, str):
        raise ValidationError("Project number must be a string")
    _check_null_bytes(project_number, "Project number")
    project_number = project_number.strip()
    if not re.match(r"^\d{2,10}$", project_number):
        raise ValidationError("Project number must be 2-10 digits")
    return project_number


def validate_claim_type(claim_type):
    """
    Validate claim type: Travel or Home Office.

    Args:
        claim_type (str): Claim type to validate

    Returns:
        str: Validated claim type

    Raises:
        ValidationError: If claim type is invalid
    """
    if not isinstance(claim_type, str):
        raise ValidationError("Claim type must be a string")
    _check_null_bytes(claim_type, "Claim type")
    claim_type = claim_type.strip()
    if claim_type not in ["Travel", "Home Office"]:
        raise ValidationError("Claim type must be 'Travel' or 'Home Office'")
    return claim_type


def validate_travel_distance(distance):
    """
    Validate travel distance: positive digits.

    Args:
        distance (str): Travel distance in km

    Returns:
        str: Validated travel distance

    Raises:
        ValidationError: If travel distance is invalid
    """
    if not isinstance(distance, str):
        raise ValidationError("Travel distance must be a string")
    _check_null_bytes(distance, "Travel distance")
    distance = distance.strip()
    if not re.match(r"^\d+$", distance):
        raise ValidationError("Travel distance must contain only digits")
    if int(distance) <= 0:
        raise ValidationError("Travel distance must be greater than 0")
    return distance


def validate_salary_batch(batch):
    """
    Validate salary batch: YYYY-MM format.

    Args:
        batch (str): Salary batch identifier

    Returns:
        str: Validated salary batch

    Raises:
        ValidationError: If salary batch format is invalid
    """
    if not isinstance(batch, str):
        raise ValidationError("Salary batch must be a string")
    _check_null_bytes(batch, "Salary batch")
    batch = batch.strip()
    if not re.match(r"^\d{4}-\d{2}$", batch):
        raise ValidationError("Invalid salary batch format. Expected: YYYY-MM (e.g. 2026-07)")
    try:
        year, month = map(int, batch.split("-"))
        if month < 1 or month > 12:
            raise ValueError
    except ValueError:
        raise ValidationError("Invalid salary batch. Month must be 01-12")
    return batch


def validate_approval_status(status):
    """
    Validate approval status: Pending, Approved, or Rejected.

    Args:
        status (str): Approval status

    Returns:
        str: Validated status

    Raises:
        ValidationError: If status is invalid
    """
    if not isinstance(status, str):
        raise ValidationError("Approval status must be a string")
    _check_null_bytes(status, "Approval status")
    status = status.strip()
    if status not in ["Pending", "Approved", "Rejected"]:
        raise ValidationError("Approval status must be 'Pending', 'Approved', or 'Rejected'")
    return status


def validate_employee_id(emp_id):
    """
    Validate employee ID: digits only.

    Args:
        emp_id (str): Employee ID

    Returns:
        str: Validated employee ID

    Raises:
        ValidationError: If employee ID is invalid
    """
    if not isinstance(emp_id, str):
        raise ValidationError("Employee ID must be a string")
    _check_null_bytes(emp_id, "Employee ID")
    emp_id = emp_id.strip()
    if not re.match(r"^\d+$", emp_id):
        raise ValidationError("Employee ID must contain only digits")
    return emp_id


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 8: GENERAL VALIDATORS
# ═══════════════════════════════════════════════════════════════════════════
# Description: General-purpose validation helpers
#
# Key components:
# - validate_nonempty(): Ensure input is not empty (for lookup fields)
# - validate_date(): Date in ISO YYYY-MM-DD format (general purpose)
# ═══════════════════════════════════════════════════════════════════════════


def validate_nonempty(value):
    """
    Validate that input is not empty.

    Args:
        value (str): The raw user input

    Returns:
        str: The input unchanged (stripped)

    Raises:
        ValidationError: If value is empty
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("Input cannot be empty")
    return value.strip()


def validate_date(date_str):
    """
    Validate date in ISO YYYY-MM-DD format.

    Args:
        date_str (str): Date string

    Returns:
        str: Validated date

    Raises:
        ValidationError: If date is invalid
    """
    if not isinstance(date_str, str):
        raise ValidationError("Date must be a string")
    _check_null_bytes(date_str, "Date")
    date_str = date_str.strip()
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", date_str):
        raise ValidationError("Invalid date format. Expected: YYYY-MM-DD")
    try:
        year, month, day = map(int, date_str.split("-"))
        datetime(year, month, day)
    except ValueError:
        raise ValidationError("Invalid date. Please enter a valid calendar date")
    return date_str
