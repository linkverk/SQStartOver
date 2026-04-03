# ═══════════════════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Expense claim management imports
#
# External modules: database, validation, auth, activity_log
# ═══════════════════════════════════════════════════════════════════════════

from database import get_connection, encrypt_field, decrypt_field
from validation import (
    validate_claim_date, validate_project_number, validate_claim_type,
    validate_travel_distance, validate_zipcode, validate_house_number,
    validate_salary_batch, validate_approval_status, ValidationError,
)
from auth import get_current_user, check_permission
from activity_log import log_activity


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: INTERNAL HELPERS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Internal helper functions for claim data processing
#
# Key components:
# - _decrypt_claim_row(): Decrypt all encrypted fields in a claim database row
#
# Note: All claim fields (except id, employee_id, created_at) are encrypted
#       with Fernet. This helper decrypts them for display and search.
# ═══════════════════════════════════════════════════════════════════════════


def _decrypt_claim_row(row):
    """
    Decrypt all encrypted fields in a claim database row.

    Args:
        row (tuple): Raw database row (14 columns)

    Returns:
        dict: Claim data with all fields decrypted
    """
    return {
        "id": row[0],
        "claim_date": decrypt_field(row[1]),
        "project_number": decrypt_field(row[2]),
        "employee_id": row[3],
        "claim_type": decrypt_field(row[4]),
        "travel_distance": decrypt_field(row[5]) if row[5] else "",
        "from_zip_code": decrypt_field(row[6]) if row[6] else "",
        "from_house_number": decrypt_field(row[7]) if row[7] else "",
        "to_zip_code": decrypt_field(row[8]) if row[8] else "",
        "to_house_number": decrypt_field(row[9]) if row[9] else "",
        "approved": decrypt_field(row[10]),
        "approved_by": decrypt_field(row[11]) if row[11] else "",
        "salary_batch": decrypt_field(row[12]) if row[12] else "",
        "created_at": row[13],
    }


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: ADD CLAIM
# ═══════════════════════════════════════════════════════════════════════════
# Description: Create new expense claims
#
# Key components:
# - add_claim(): Add Travel or Home Office claim
#
# Note: Employee ID is set automatically from the logged-in user's session.
#       If claim_type is 'Travel', travel-specific fields are required
#       (distance, from/to ZIP+housenumber). 'Home Office' needs no extras.
#       All fields are encrypted before storage. Initial status is 'Pending'.
# ═══════════════════════════════════════════════════════════════════════════


def add_claim(claim_date, project_number, claim_type, travel_distance=None,
              from_zip_code=None, from_house_number=None, to_zip_code=None,
              to_house_number=None):
    """
    Add a new claim. Employee ID is set automatically from session.

    Args:
        claim_date (str): Claim date (YYYY-MM-DD, max 2 months back / 14 days ahead)
        project_number (str): Project number (2-10 digits)
        claim_type (str): 'Travel' or 'Home Office'
        travel_distance (str): Km travelled (required for Travel)
        from_zip_code (str): Start ZIP code (required for Travel)
        from_house_number (str): Start house number (required for Travel)
        to_zip_code (str): Destination ZIP code (required for Travel)
        to_house_number (str): Destination house number (required for Travel)

    Returns:
        tuple: (success: bool, message: str)

    Example:
        success, msg = add_claim("2026-04-01", "12345", "Travel", "50",
                                  "3011AB", "42", "1017AB", "10")
    """
    current_user = get_current_user()
    if not current_user:
        return False, "You must be logged in to add claims"

    # Permission check: employees submit, managers/admins manage
    if current_user["role"] == "employee" and not check_permission("submit_claims"):
        return False, "Access denied"
    if current_user["role"] in ("manager", "super_admin") and not check_permission("manage_claims"):
        return False, "Access denied"

    employee_id = current_user.get("employee_id")
    if current_user["role"] == "employee" and not employee_id:
        return False, "Your account is not linked to an employee record"

    # Validate all inputs (whitelisting approach)
    try:
        claim_date = validate_claim_date(claim_date)
        project_number = validate_project_number(project_number)
        claim_type = validate_claim_type(claim_type)

        enc_travel_distance = ""
        enc_from_zip = ""
        enc_from_house = ""
        enc_to_zip = ""
        enc_to_house = ""

        if claim_type == "Travel":
            if not travel_distance:
                return False, "Travel distance is required for Travel claims"
            if not from_zip_code or not from_house_number:
                return False, "From address (ZIP + house number) is required for Travel claims"
            if not to_zip_code or not to_house_number:
                return False, "To address (ZIP + house number) is required for Travel claims"

            travel_distance = validate_travel_distance(travel_distance)
            from_zip_code = validate_zipcode(from_zip_code)
            from_house_number = validate_house_number(from_house_number)
            to_zip_code = validate_zipcode(to_zip_code)
            to_house_number = validate_house_number(to_house_number)

            enc_travel_distance = encrypt_field(travel_distance)
            enc_from_zip = encrypt_field(from_zip_code)
            enc_from_house = encrypt_field(from_house_number)
            enc_to_zip = encrypt_field(to_zip_code)
            enc_to_house = encrypt_field(to_house_number)

    except ValidationError as e:
        return False, f"Validation error: {e}"

    # Encrypt remaining fields
    enc_claim_date = encrypt_field(claim_date)
    enc_project_number = encrypt_field(project_number)
    enc_claim_type = encrypt_field(claim_type)
    enc_approved = encrypt_field("Pending")

    conn = get_connection()
    cursor = conn.cursor()

    # Prepared statement to prevent SQL injection
    cursor.execute(
        """
        INSERT INTO claims (claim_date, project_number, employee_id, claim_type,
            travel_distance, from_zip_code, from_house_number, to_zip_code,
            to_house_number, approved, approved_by, salary_batch)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (enc_claim_date, enc_project_number, employee_id, enc_claim_type,
         enc_travel_distance, enc_from_zip, enc_from_house, enc_to_zip,
         enc_to_house, enc_approved, "", ""),
    )
    claim_id = cursor.lastrowid
    conn.commit()
    conn.close()

    log_activity(current_user["username"], "New claim added",
                 f"Claim ID: {claim_id}, Type: {claim_type}, Date: {claim_date}")
    return True, f"Claim added successfully (ID: {claim_id})"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: UPDATE CLAIM
# ═══════════════════════════════════════════════════════════════════════════
# Description: Modify existing claims with role-based field restrictions
#
# Key components:
# - update_claim(): Update claim with role-based permissions
#
# Employee can update own claims (if not linked to salary-batch):
# - claim_date, project_number, claim_type, travel fields
#
# Manager / Super Admin can update:
# - project_number, travel_distance (modify claim details)
# - approved (Approved/Rejected — sets approved_by automatically)
# - salary_batch (link to salary processing)
# ═══════════════════════════════════════════════════════════════════════════


def update_claim(claim_id, **updates):
    """
    Update a claim with role-based field restrictions.

    Args:
        claim_id (str or int): Claim ID to update
        **updates: Fields to update

    Returns:
        tuple: (success: bool, message: str)

    Example:
        # Manager approves claim
        success, msg = update_claim(1, approved="Approved")
        # Employee updates own claim date
        success, msg = update_claim(1, claim_date="2026-04-05")
    """
    current_user = get_current_user()
    if not current_user:
        return False, "You must be logged in to update claims"

    conn = get_connection()
    cursor = conn.cursor()

    # Prepared statement
    cursor.execute("SELECT * FROM claims WHERE id = ?", (int(claim_id),))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False, f"Claim with ID '{claim_id}' not found"

    claim = _decrypt_claim_row(row)

    # Employee can only update their own claims
    if current_user["role"] == "employee":
        if claim["employee_id"] != current_user.get("employee_id"):
            conn.close()
            return False, "Access denied. You can only update your own claims"
        if claim["salary_batch"]:
            conn.close()
            return False, "Cannot modify claim that is already linked to a salary batch"

    # Determine allowed fields per role
    if current_user["role"] == "employee":
        allowed_fields = {"claim_date", "project_number", "claim_type",
                          "travel_distance", "from_zip_code", "from_house_number",
                          "to_zip_code", "to_house_number"}
    else:
        # Manager / Super Admin
        allowed_fields = {"project_number", "travel_distance", "approved", "salary_batch"}

    update_fields = []
    params = []
    changes = []

    for field, value in updates.items():
        if field not in allowed_fields:
            conn.close()
            return False, f"You cannot update field: {field}"

        # Validate using whitelisting
        try:
            if field == "claim_date":
                value = validate_claim_date(value)
            elif field == "project_number":
                value = validate_project_number(value)
            elif field == "claim_type":
                value = validate_claim_type(value)
            elif field == "travel_distance":
                value = validate_travel_distance(value)
            elif field in ("from_zip_code", "to_zip_code"):
                value = validate_zipcode(value)
            elif field in ("from_house_number", "to_house_number"):
                value = validate_house_number(value)
            elif field == "approved":
                value = validate_approval_status(value)
            elif field == "salary_batch":
                value = validate_salary_batch(value)
        except ValidationError as e:
            conn.close()
            return False, f"Validation error for {field}: {e}"

        encrypted_value = encrypt_field(value)
        update_fields.append(f"{field} = ?")
        params.append(encrypted_value)
        changes.append(field)

    # Auto-set approved_by when manager approves/rejects
    if "approved" in updates and current_user["role"] in ("manager", "super_admin"):
        update_fields.append("approved_by = ?")
        params.append(encrypt_field(current_user["username"]))

    if not update_fields:
        conn.close()
        return False, "No fields to update"

    params.append(int(claim_id))

    # Prepared statement for UPDATE
    cursor.execute(f"UPDATE claims SET {', '.join(update_fields)} WHERE id = ?",
                   tuple(params))
    conn.commit()
    conn.close()

    log_activity(current_user["username"], "Claim updated",
                 f"Claim ID: {claim_id}, Updated fields: {', '.join(changes)}")
    return True, "Claim updated successfully"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: DELETE CLAIM
# ═══════════════════════════════════════════════════════════════════════════
# Description: Delete expense claims
#
# Key components:
# - delete_claim(): Remove claim (Employee only if not batched)
#
# Note: Employee can only delete own claims that are not yet linked to
#       a salary batch. Uses prepared statements to prevent SQL injection.
# ═══════════════════════════════════════════════════════════════════════════


def delete_claim(claim_id):
    """
    Delete a claim.

    Employee can only delete own claims not linked to salary-batch.

    Args:
        claim_id (str or int): Claim ID to delete

    Returns:
        tuple: (success: bool, message: str)

    Example:
        success, msg = delete_claim(1)
    """
    current_user = get_current_user()
    if not current_user:
        return False, "You must be logged in to delete claims"

    conn = get_connection()
    cursor = conn.cursor()

    # Prepared statement
    cursor.execute("SELECT * FROM claims WHERE id = ?", (int(claim_id),))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False, f"Claim with ID '{claim_id}' not found"

    claim = _decrypt_claim_row(row)

    # Employee restrictions
    if current_user["role"] == "employee":
        if claim["employee_id"] != current_user.get("employee_id"):
            conn.close()
            return False, "Access denied. You can only delete your own claims"
        if claim["salary_batch"]:
            conn.close()
            return False, "Cannot delete claim that is already linked to a salary batch"

    # Prepared statement for DELETE
    cursor.execute("DELETE FROM claims WHERE id = ?", (int(claim_id),))
    conn.commit()
    conn.close()

    log_activity(current_user["username"], "Claim deleted", f"Claim ID: {claim_id}")
    return True, f"Claim {claim_id} deleted successfully"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5: SEARCH & RETRIEVAL OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Search and retrieve claim information
#
# Key components:
# - search_claims(): Partial key search across all decrypted claim fields
# - get_claim_by_id(): Get specific claim by ID
# - list_claims(): List all claims, optionally filtered by employee ID
#
# Note: Since all claim data is Fernet-encrypted (non-deterministic),
#       searching requires decrypting all records and filtering in Python.
#       This supports the partial key search requirement (Note 2 in assignment):
#       e.g., searching "1218", "18 A", or "AK" for zip code "1218AK".
#       Employee role can only see their own claims (employee_id_filter).
# ═══════════════════════════════════════════════════════════════════════════


def search_claims(search_key, employee_id_filter=None):
    """
    Search claims with partial key matching.

    Decrypts all claims and searches across all fields.
    Supports partial key matching per assignment Note 2.

    Args:
        search_key (str): Search term (partial match)
        employee_id_filter (int): If set, only show claims for that employee

    Returns:
        list: Matching claim dictionaries

    Example:
        results = search_claims("Travel")           # Find all travel claims
        results = search_claims("3011", employee_id_filter=1)  # Employee's claims with ZIP 3011
    """
    if not search_key or len(search_key) < 1:
        return []

    search_key_lower = search_key.lower().strip()

    conn = get_connection()
    cursor = conn.cursor()

    if employee_id_filter:
        # Prepared statement with employee filter
        cursor.execute("SELECT * FROM claims WHERE employee_id = ? ORDER BY id DESC",
                       (int(employee_id_filter),))
    else:
        cursor.execute("SELECT * FROM claims ORDER BY id DESC")

    results = cursor.fetchall()
    conn.close()

    matches = []
    for row in results:
        claim = _decrypt_claim_row(row)
        # Build searchable string from all decrypted fields
        searchable = " ".join([
            str(claim["id"]), claim["claim_date"], claim["project_number"],
            str(claim["employee_id"]), claim["claim_type"], claim["travel_distance"],
            claim["from_zip_code"], claim["from_house_number"],
            claim["to_zip_code"], claim["to_house_number"],
            claim["approved"], claim["approved_by"], claim["salary_batch"],
        ]).lower()
        if search_key_lower in searchable:
            matches.append(claim)

    return matches


def get_claim_by_id(claim_id):
    """
    Get specific claim by ID.

    Args:
        claim_id (str or int): Claim ID

    Returns:
        dict: Claim information, or None if not found

    Example:
        claim = get_claim_by_id(1)
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Prepared statement
    cursor.execute("SELECT * FROM claims WHERE id = ?", (int(claim_id),))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None
    return _decrypt_claim_row(row)


def list_claims(employee_id_filter=None):
    """
    List all claims, optionally filtered by employee ID.

    Args:
        employee_id_filter (int): If set, only show claims for that employee

    Returns:
        list: List of claim dictionaries

    Example:
        all_claims = list_claims()
        my_claims = list_claims(employee_id_filter=1)
    """
    conn = get_connection()
    cursor = conn.cursor()

    if employee_id_filter:
        # Prepared statement with employee filter
        cursor.execute("SELECT * FROM claims WHERE employee_id = ? ORDER BY id DESC",
                       (int(employee_id_filter),))
    else:
        cursor.execute("SELECT * FROM claims ORDER BY id DESC")

    results = cursor.fetchall()
    conn.close()

    return [_decrypt_claim_row(row) for row in results]
