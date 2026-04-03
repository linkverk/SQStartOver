# ═══════════════════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Scooter fleet management imports
#
# External modules: database, validation, auth, activity_log
# ═══════════════════════════════════════════════════════════════════════════

from database import get_connection, encrypt_username, decrypt_username
from validation import (
    ValidationError,
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
)
from auth import get_current_user, check_permission
from activity_log import log_activity


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: CREATE OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Add new scooters to fleet inventory
#
# Key components:
# - add_scooter(): Create new scooter record with validation and encryption
# ═══════════════════════════════════════════════════════════════════════════


def add_scooter(
    serial_number,
    brand,
    model,
    top_speed,
    battery_capacity,
    state_of_charge,
    target_range_soc_min,
    target_range_soc_max,
    latitude,
    longitude,
    out_of_service_status,
    mileage,
    last_maintenance_date=None,
):
    """
    Create new scooter record.

    Validates inputs using validation.py functions, encrypts serial number,
    uses prepared statements, and logs activity.

    Args:
        serial_number (str): Serial number (will be encrypted)
        brand (str): Manufacturer name
        model (str): Model name/number
        top_speed (float): Maximum speed in km/h
        battery_capacity (int): Total battery capacity in Wh
        state_of_charge (int): Current battery charge (0-100%)
        target_range_soc_min (int): Minimum recommended SoC (0-100%)
        target_range_soc_max (int): Maximum recommended SoC (0-100%)
        latitude (float): GPS latitude coordinate
        longitude (float): GPS longitude coordinate
        out_of_service_status (bool): True if out of service
        mileage (float): Total distance traveled in km
        last_maintenance_date (str, optional): Last maintenance date (YYYY-MM-DD)

    Returns:
        tuple: (success: bool, message: str)

    Example:
        success, msg = add_scooter("ABC1234567", "Segway", "ES2", 25, 500, 100, 20, 80, 51.92481, 4.46910, False, 0)
    """
    # Check permission
    if not check_permission("manage_scooters"):
        return False, "Access denied. Insufficient permissions to add scooters"

    current_user = get_current_user()

    # Validate inputs using validation.py functions
    try:
        serial_number = validate_serial_number(serial_number)
        brand = validate_brand(brand)
        model = validate_model(model)
        top_speed = validate_top_speed(top_speed)
        battery_capacity = validate_battery_capacity(battery_capacity)
        state_of_charge = validate_state_of_charge(state_of_charge)
        target_range_soc_min, target_range_soc_max = validate_target_range_soc(
            target_range_soc_min, target_range_soc_max
        )
        latitude, longitude = validate_gps_location(latitude, longitude)
        out_of_service_status = validate_out_of_service_status(out_of_service_status)
        mileage = validate_mileage(mileage)

        if last_maintenance_date:
            last_maintenance_date = validate_date(last_maintenance_date)

    except ValidationError as e:
        return False, f"Validation error: {e}"

    encrypted_serial = encrypt_username(serial_number)

    # Check if serial number already exists
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id FROM scooters WHERE serial_number = ?", (encrypted_serial,)
    )

    if cursor.fetchone():
        conn.close()
        return False, f"Scooter with serial number '{serial_number}' already exists"

    # Prepared statement for INSERT
    cursor.execute(
        """
        INSERT INTO scooters (
            serial_number, brand, model, top_speed, battery_capacity,
            state_of_charge, target_range_soc_min, target_range_soc_max,
            latitude, longitude, out_of_service_status, mileage, last_maintenance_date
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            encrypted_serial,
            brand,
            model,
            top_speed,
            battery_capacity,
            state_of_charge,
            target_range_soc_min,
            target_range_soc_max,
            latitude,
            longitude,
            1 if out_of_service_status else 0,
            mileage,
            last_maintenance_date,
        ),
    )

    conn.commit()
    conn.close()

    # Log activity
    if current_user:
        log_activity(
            current_user["username"],
            "New scooter added",
            f"Serial: {serial_number}, Brand: {brand}, Model: {model}",
        )

    return True, f"Scooter '{serial_number}' added successfully"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: UPDATE OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Update scooter information with role-based field restrictions
#
# Key components:
# - update_scooter(): Update with role-based permissions (Service Engineers limited)
#
# Note: Service Engineers can only update battery, status, location, service date
# ═══════════════════════════════════════════════════════════════════════════


def update_scooter(serial_number, **updates):
    """
    Update scooter information with role-based field restrictions.

    Service Engineers can ONLY update:
    - state_of_charge (Current battery %)
    - target_range_soc_min, target_range_soc_max (Target SoC range)
    - latitude, longitude (GPS location)
    - out_of_service_status (Availability status)
    - mileage (Total distance)
    - last_maintenance_date (Last maintenance)

    Super Admin / System Admin can update ALL fields including:
    - serial_number, brand, model, top_speed, battery_capacity
    - + all Service Engineer fields

    Args:
        serial_number (str): Serial number
        **updates: Fields to update

    Returns:
        tuple: (success: bool, message: str)

    Example:
        success, msg = update_scooter("ABC1234567", state_of_charge=85, latitude=51.92481, longitude=4.46910)
    """
    # Check permission
    if not check_permission("manage_scooters"):
        return False, "Access denied. Insufficient permissions to update scooters"

    current_user = get_current_user()

    if not updates:
        return False, "No fields specified for update"

    # Define allowed fields per role
    service_engineer_fields = {
        "state_of_charge",
        "target_range_soc_min",
        "target_range_soc_max",
        "latitude",
        "longitude",
        "out_of_service_status",
        "mileage",
        "last_maintenance_date",
    }
    all_fields = {
        "serial_number",
        "brand",
        "model",
        "top_speed",
        "battery_capacity",
        "state_of_charge",
        "target_range_soc_min",
        "target_range_soc_max",
        "latitude",
        "longitude",
        "out_of_service_status",
        "mileage",
        "last_maintenance_date",
    }

    # Check field permissions based on role
    user_role = None
    if current_user:
        user_role = current_user["role"]
        if user_role == "service_engineer":
            allowed_fields = service_engineer_fields
        else:
            allowed_fields = all_fields
    else:
        allowed_fields = all_fields

    # Validate requested fields against permissions
    for field in updates.keys():
        if field not in allowed_fields:
            if user_role == "service_engineer":
                return (
                    False,
                    f"Access denied. Service Engineers cannot update field: {field}",
                )
            else:
                return False, f"Invalid field: {field}"

    # Get current scooter
    conn = get_connection()
    cursor = conn.cursor()

    encrypted_serial = encrypt_username(serial_number)

    cursor.execute(
        "SELECT * FROM scooters WHERE serial_number = ?", (encrypted_serial,)
    )

    scooter = cursor.fetchone()

    if not scooter:
        conn.close()
        return False, f"Scooter with serial number '{serial_number}' not found"

    # Validate and prepare updates
    update_fields = []
    params = []
    changes = []
    latitude_update = None
    longitude_update = None

    for field, value in updates.items():
        try:
            # Validate based on field type
            if field == "serial_number":
                value = validate_serial_number(value)
                value = encrypt_username(value)
            elif field == "brand":
                value = validate_brand(value)
            elif field == "model":
                value = validate_model(value)
            elif field == "top_speed":
                value = validate_top_speed(value)
            elif field == "battery_capacity":
                value = validate_battery_capacity(value)
            elif field == "state_of_charge":
                value = validate_state_of_charge(value)
            elif field == "target_range_soc_min":
                value = validate_state_of_charge(value)
            elif field == "target_range_soc_max":
                value = validate_state_of_charge(value)
            elif field == "latitude":
                latitude_update = value
                continue
            elif field == "longitude":
                longitude_update = value
                continue
            elif field == "out_of_service_status":
                value = validate_out_of_service_status(value)
                value = 1 if value else 0
            elif field == "mileage":
                value = validate_mileage(value)
            elif field == "last_maintenance_date":
                value = validate_date(value)

        except ValidationError as e:
            conn.close()
            return False, f"Validation error for {field}: {e}"

        update_fields.append(f"{field} = ?")
        params.append(value)
        changes.append(field)

    # Handle GPS location validation (must validate together)
    if latitude_update is not None or longitude_update is not None:
        try:
            if latitude_update is None or longitude_update is None:
                conn.close()
                return False, "Both latitude and longitude must be provided together"

            lat, lon = validate_gps_location(latitude_update, longitude_update)
            update_fields.append("latitude = ?")
            params.append(lat)
            update_fields.append("longitude = ?")
            params.append(lon)
            changes.extend(["latitude", "longitude"])
        except ValidationError as e:
            conn.close()
            return False, f"Validation error for GPS location: {e}"

    # Validate target_range_soc if both min and max are being updated
    if "target_range_soc_min" in updates and "target_range_soc_max" in updates:
        try:
            validate_target_range_soc(
                updates["target_range_soc_min"], updates["target_range_soc_max"]
            )
        except ValidationError as e:
            conn.close()
            return False, f"Validation error for target range SoC: {e}"

    params.append(encrypted_serial)

    # Prepared statement for UPDATE
    cursor.execute(
        f"UPDATE scooters SET {', '.join(update_fields)} WHERE serial_number = ?",
        tuple(params),
    )

    conn.commit()
    conn.close()

    # Log activity
    if current_user:
        log_activity(
            current_user["username"],
            "Scooter updated",
            f"Serial: {serial_number}, Updated fields: {', '.join(changes)}",
        )

    return True, f"Scooter updated successfully"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: DELETE OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Delete scooter records
#
# Key components:
# - delete_scooter(): Remove scooter (Super/System Admin only, not engineers)
# ═══════════════════════════════════════════════════════════════════════════


def delete_scooter(serial_number):
    """
    Delete scooter record (Super Admin or System Admin only).

    Uses prepared statements and logs activity.

    Args:
        serial_number (str): Serial number to delete

    Returns:
        tuple: (success: bool, message: str)

    Example:
        success, msg = delete_scooter("SC123456")
    """
    # Check permission (Service Engineers cannot delete)
    current_user = get_current_user()

    if current_user and current_user["role"] == "service_engineer":
        return False, "Access denied. Service Engineers cannot delete scooters"

    if not check_permission("manage_scooters"):
        return False, "Access denied. Insufficient permissions to delete scooters"

    # Check if scooter exists
    conn = get_connection()
    cursor = conn.cursor()

    encrypted_serial = encrypt_username(serial_number)

    # Prepared statement
    cursor.execute(
        "SELECT brand, model FROM scooters WHERE serial_number = ?",
        (encrypted_serial,),
    )

    scooter = cursor.fetchone()

    if not scooter:
        conn.close()
        return False, f"Scooter with serial number '{serial_number}' not found"

    brand, model = scooter

    # Prepared statement for DELETE
    cursor.execute("DELETE FROM scooters WHERE serial_number = ?", (encrypted_serial,))

    conn.commit()
    conn.close()

    # Log activity
    if current_user:
        log_activity(
            current_user["username"],
            "Scooter deleted",
            f"Serial: {serial_number}, Brand: {brand}, Model: {model}",
        )

    return True, f"Scooter '{serial_number}' deleted successfully"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: SEARCH & RETRIEVAL OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Search and retrieve scooter information
#
# Key components:
# - search_scooters(): Partial key search in brand, model, GPS coordinates
# - get_scooter_by_serial(): Get specific scooter by serial number
# - list_all_scooters(): Get all scooters with decrypted serial numbers
#
# Note: Cannot search by serial number (encrypted)
# ═══════════════════════════════════════════════════════════════════════════


def search_scooters(search_key):
    """
    Search scooters with partial key matching.

    Accepts partial keys in: type, location, status.
    Note: Cannot search by serial_number (encrypted).

    Args:
        search_key (str): Search term

    Returns:
        list: Matching scooter dictionaries

    Example:
        results = search_scooters("Model X")
    """
    if not search_key or len(search_key) < 2:
        return []

    conn = get_connection()
    cursor = conn.cursor()

    # Prepared statement with LIKE for partial matching
    search_pattern = f"%{search_key}%"

    cursor.execute(
        """
        SELECT * FROM scooters
        WHERE LOWER(brand) LIKE LOWER(?)
           OR LOWER(model) LIKE LOWER(?)
           OR CAST(latitude AS TEXT) LIKE ?
           OR CAST(longitude AS TEXT) LIKE ?
        ORDER BY brand, model
        """,
        (search_pattern, search_pattern, search_pattern, search_pattern),
    )

    results = cursor.fetchall()
    conn.close()

    scooters = []
    for row in results:
        scooters.append(
            {
                "id": row[0],
                "serial_number": decrypt_username(row[1]),
                "brand": row[2],
                "model": row[3],
                "top_speed": row[4],
                "battery_capacity": row[5],
                "state_of_charge": row[6],
                "target_range_soc_min": row[7],
                "target_range_soc_max": row[8],
                "latitude": row[9],
                "longitude": row[10],
                "out_of_service_status": row[11],
                "mileage": row[12],
                "last_maintenance_date": row[13],
                "in_service_date": row[14],
            }
        )

    return scooters


def get_scooter_by_serial(serial_number):
    """
    Get specific scooter by serial number.

    Args:
        serial_number (str): Serial number

    Returns:
        dict: Scooter information or None if not found

    Example:
        scooter = get_scooter_by_serial("SC123456")
    """
    conn = get_connection()
    cursor = conn.cursor()

    encrypted_serial = encrypt_username(serial_number)

    # Prepared statement
    cursor.execute(
        "SELECT * FROM scooters WHERE serial_number = ?", (encrypted_serial,)
    )

    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "serial_number": decrypt_username(row[1]),
        "brand": row[2],
        "model": row[3],
        "top_speed": row[4],
        "battery_capacity": row[5],
        "state_of_charge": row[6],
        "target_range_soc_min": row[7],
        "target_range_soc_max": row[8],
        "latitude": row[9],
        "longitude": row[10],
        "out_of_service_status": row[11],
        "mileage": row[12],
        "last_maintenance_date": row[13],
        "in_service_date": row[14],
    }


def list_all_scooters():
    """
    Get all scooters.

    Returns:
        list: List of scooter dictionaries

    Example:
        scooters = list_all_scooters()
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scooters ORDER BY brand, model")

    results = cursor.fetchall()
    conn.close()

    scooters = []
    for row in results:
        scooters.append(
            {
                "id": row[0],
                "serial_number": decrypt_username(row[1]),
                "brand": row[2],
                "model": row[3],
                "top_speed": row[4],
                "battery_capacity": row[5],
                "state_of_charge": row[6],
                "target_range_soc_min": row[7],
                "target_range_soc_max": row[8],
                "latitude": row[9],
                "longitude": row[10],
                "out_of_service_status": row[11],
                "mileage": row[12],
                "last_maintenance_date": row[13],
                "in_service_date": row[14],
            }
        )

    return scooters
