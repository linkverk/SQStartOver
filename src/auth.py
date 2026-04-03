# ═══════════════════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Authentication and authorization system imports
#
# External modules: database, validation, activity_log
# ═══════════════════════════════════════════════════════════════════════════

from database import (
    get_connection, encrypt_username, decrypt_username,
    hash_password, verify_password,
)
from validation import validate_username, validate_password, ValidationError
from activity_log import log_activity


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: SESSION MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════
# Description: User session state and basic session operations
#
# Key components:
# - current_session: Global session state dictionary
# - _failed_login_attempts: Track failed logins for brute-force detection
# - get_current_user(): Retrieve current user session data
# - is_logged_in(): Check if user is authenticated
# - login(): Authenticate user and create session
# - _record_failed_attempt(): Track and detect brute-force attacks
# - logout(): End session and clear user data
#
# Note: Session is in-memory only (resets on application restart)
# ═══════════════════════════════════════════════════════════════════════════

current_session = {
    "logged_in": False,
    "user_id": None,
    "username": None,
    "role": None,
    "role_name": None,
    "first_name": None,
    "last_name": None,
    "employee_id": None,
    "must_change_password": False,
}

_failed_login_attempts = []


def get_current_user():
    """
    Get current session data for the logged-in user.

    Returns:
        dict: Session data copy, or None if not logged in
    """
    if current_session["logged_in"]:
        return current_session.copy()
    return None


def is_logged_in():
    """
    Check if a user is currently authenticated.

    Returns:
        bool: True if user is logged in
    """
    return current_session["logged_in"]


def login(username, password):
    """
    Authenticate user and create session.

    Validates credentials, verifies password hash, tracks failed attempts
    for brute-force detection, and starts session on success.

    Args:
        username (str): Username (plain text)
        password (str): Password (plain text)

    Returns:
        tuple: (success: bool, message: str)
    """
    import time

    conn = get_connection()
    cursor = conn.cursor()

    encrypted_username = encrypt_username(username)
    cursor.execute(
        """
        SELECT id, username, password_hash, role, first_name, last_name,
               employee_id, must_change_password
        FROM users WHERE username = ?
        """,
        (encrypted_username,),
    )
    user = cursor.fetchone()
    conn.close()

    if not user:
        _record_failed_attempt(username)
        log_activity("unknown", "Unsuccessful login",
                     f"username: '{username}' not found", suspicious=True)
        return False, "Invalid username or password"

    (user_id, encrypted_username_db, password_hash_db, role,
     first_name, last_name, employee_id, must_change_password) = user
    username_db = decrypt_username(encrypted_username_db)

    if not verify_password(password, username_db, password_hash_db):
        _record_failed_attempt(username_db)
        log_activity("unknown", "Unsuccessful login",
                     f"username: '{username_db}' used with wrong password", suspicious=True)
        return False, "Invalid username or password"

    # Login successful — clear failed attempts and create session
    _failed_login_attempts.clear()

    current_session["logged_in"] = True
    current_session["user_id"] = user_id
    current_session["username"] = username_db
    current_session["role"] = role
    current_session["role_name"] = get_role_name(role)
    current_session["first_name"] = first_name
    current_session["last_name"] = last_name
    current_session["employee_id"] = employee_id
    current_session["must_change_password"] = bool(must_change_password)

    log_activity(username_db, "Logged in")
    return True, f"Welcome {first_name} {last_name}!"


def _record_failed_attempt(username):
    """
    Record failed login attempt and flag brute-force if multiple attempts.

    Triggers suspicious activity log when 3+ failures occur within 60 seconds.

    Args:
        username (str): Username used in failed attempt
    """
    import time
    _failed_login_attempts.append({"username": username, "time": time.time()})
    recent = [a for a in _failed_login_attempts if time.time() - a["time"] < 60]
    if len(recent) >= 3:
        log_activity(
            "unknown", "Brute-force attempt detected",
            f"Multiple usernames/passwords tried in a row ({len(recent)} attempts in 60s)",
            suspicious=True,
        )


def logout():
    """
    Logout current user and clear all session data.

    Returns:
        tuple: (success: bool, message: str)
    """
    if not current_session["logged_in"]:
        return False, "No user is currently logged in"

    username = current_session["username"]
    log_activity(username, "Logged out")

    current_session["logged_in"] = False
    current_session["user_id"] = None
    current_session["username"] = None
    current_session["role"] = None
    current_session["role_name"] = None
    current_session["first_name"] = None
    current_session["last_name"] = None
    current_session["employee_id"] = None
    current_session["must_change_password"] = False

    return True, f"User {username} logged out successfully"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: ROLE-BASED ACCESS CONTROL (RBAC)
# ═══════════════════════════════════════════════════════════════════════════
# Description: Permission system and role-based authorization
#
# Key components:
# - PERMISSIONS: Permission matrix for all three roles
# - check_permission(): Check if current user has specific permission
# - require_permission(): Verify permission with error message
# - get_role_name(): Convert role ID to human-readable name
#
# Roles:
# - Super Admin: Full system access, manages Managers, generates restore codes
# - Manager: Manages employees and claims, approves/rejects, backup/restore with code
# - Employee: Submits and manages own claims, updates own password
#
# Note: Super Admin password is hard-coded and cannot be changed via the UI.
# ═══════════════════════════════════════════════════════════════════════════

PERMISSIONS = {
    "super_admin": {
        "manage_managers": True,
        "manage_employees": True,
        "manage_claims": True,
        "approve_claims": True,
        "view_logs": True,
        "create_backup": True,
        "restore_backup": True,
        "manage_restore_codes": True,
        "update_own_password": False,
        "submit_claims": False,
    },
    "manager": {
        "manage_managers": False,
        "manage_employees": True,
        "manage_claims": True,
        "approve_claims": True,
        "view_logs": True,
        "create_backup": True,
        "restore_backup": True,
        "manage_restore_codes": False,
        "update_own_password": True,
        "submit_claims": False,
    },
    "employee": {
        "manage_managers": False,
        "manage_employees": False,
        "manage_claims": False,
        "approve_claims": False,
        "view_logs": False,
        "create_backup": False,
        "restore_backup": False,
        "manage_restore_codes": False,
        "update_own_password": True,
        "submit_claims": True,
    },
}


def check_permission(permission_name):
    """
    Check if current user has a specific permission based on their role.

    Args:
        permission_name (str): Permission to check (e.g., "manage_employees")

    Returns:
        bool: True if user has permission
    """
    if not current_session["logged_in"]:
        return False
    role = current_session["role"]
    if role in PERMISSIONS:
        return PERMISSIONS[role].get(permission_name, False)
    return False


def require_permission(permission_name):
    """
    Verify user has required permission, returning error message if not.

    Args:
        permission_name (str): Required permission

    Returns:
        tuple: (has_permission: bool, error_message: str or None)
    """
    if not current_session["logged_in"]:
        return False, "You must be logged in to perform this action"
    if not check_permission(permission_name):
        return (False,
                f"Access denied. Your role ({current_session['role_name']}) "
                f"does not have permission: {permission_name}")
    return True, None


def get_role_name(role):
    """
    Convert role identifier to human-readable name.

    Args:
        role (str): Role identifier (super_admin, manager, employee)

    Returns:
        str: Display-friendly role name
    """
    role_names = {
        "super_admin": "Super Administrator",
        "manager": "Manager",
        "employee": "Employee",
    }
    return role_names.get(role, role)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: PASSWORD MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════
# Description: Password update for currently logged-in user
#
# Key components:
# - update_password(): Change password with old password verification
#
# Note: Verifies old password, validates new password format, checks that
#       new password differs from old, and updates database. Resets the
#       must_change_password flag after successful change.
# ═══════════════════════════════════════════════════════════════════════════


def update_password(old_password, new_password):
    """
    Update password for currently logged-in user.

    Verifies old password, validates new password format, and updates database.

    Args:
        old_password (str): Current password for verification
        new_password (str): New password

    Returns:
        tuple: (success: bool, message: str)
    """
    if not current_session["logged_in"]:
        return False, "You must be logged in to update password"

    user_id = current_session["user_id"]
    username = current_session["username"]

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
    result = cursor.fetchone()

    if not result:
        conn.close()
        return False, "User not found in database"

    current_password_hash = result[0]

    if not verify_password(old_password, username, current_password_hash):
        conn.close()
        log_activity(username, "Password change failed",
                     "Incorrect current password", suspicious=True)
        return False, "Incorrect current password"

    try:
        new_password = validate_password(new_password)
    except ValidationError as e:
        conn.close()
        return False, f"Invalid new password: {e}"

    if old_password == new_password:
        conn.close()
        return False, "New password must be different from current password"

    new_password_hash = hash_password(new_password, username)
    cursor.execute(
        "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
        (new_password_hash, user_id),
    )
    conn.commit()
    conn.close()

    current_session["must_change_password"] = False
    log_activity(username, "Password updated")
    return True, "Password updated successfully"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: USER LOOKUP FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════
# Description: Retrieve user information from the database
#
# Key components:
# - get_user_by_username(): Look up user by username
# - list_users_by_role(): Get all users, optionally filtered by role
#
# Note: Usernames are decrypted on retrieval for display purposes.
# ═══════════════════════════════════════════════════════════════════════════


def get_user_by_username(username):
    """
    Look up user information by username.

    Args:
        username (str): Username to search for

    Returns:
        dict: User information, or None if not found
    """
    try:
        username = validate_username(username)
    except ValidationError:
        return None

    conn = get_connection()
    cursor = conn.cursor()
    encrypted_username = encrypt_username(username)
    cursor.execute(
        """SELECT id, username, role, first_name, last_name, employee_id, created_at
           FROM users WHERE username = ?""",
        (encrypted_username,),
    )
    result = cursor.fetchone()
    conn.close()

    if not result:
        return None

    user_id, enc_username, role, first_name, last_name, employee_id, created_at = result
    return {
        "id": user_id,
        "username": decrypt_username(enc_username),
        "role": role,
        "role_name": get_role_name(role),
        "first_name": first_name,
        "last_name": last_name,
        "employee_id": employee_id,
        "created_at": created_at,
    }


def list_users_by_role(role=None):
    """
    Get list of users, optionally filtered by role.

    Args:
        role (str): Optional role filter (super_admin, manager, employee)

    Returns:
        list: User dictionaries with decrypted data
    """
    conn = get_connection()
    cursor = conn.cursor()

    if role:
        cursor.execute(
            """SELECT id, username, role, first_name, last_name, employee_id, created_at
               FROM users WHERE role = ? ORDER BY created_at DESC""",
            (role,),
        )
    else:
        cursor.execute(
            """SELECT id, username, role, first_name, last_name, employee_id, created_at
               FROM users ORDER BY created_at DESC"""
        )

    results = cursor.fetchall()
    conn.close()

    users = []
    for row in results:
        user_id, enc_username, role_val, first_name, last_name, employee_id, created_at = row
        users.append({
            "id": user_id,
            "username": decrypt_username(enc_username),
            "role": role_val,
            "role_name": get_role_name(role_val),
            "first_name": first_name,
            "last_name": last_name,
            "employee_id": employee_id,
            "created_at": created_at,
        })
    return users
