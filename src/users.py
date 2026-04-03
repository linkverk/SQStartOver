# ═══════════════════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════════════════

import secrets
import string
from database import get_connection, encrypt_username, decrypt_username, hash_password
from validation import validate_username, validate_name, ValidationError
from auth import get_current_user, check_permission, get_role_name
from activity_log import log_activity


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: USER CREATION
# ═══════════════════════════════════════════════════════════════════════════


def create_manager(username, first_name, last_name, password=None):
    """Create new Manager account (Super Admin only)."""
    if not check_permission("manage_managers"):
        return False, "Access denied. Only Super Administrator can create Managers", None

    current_user = get_current_user()
    try:
        username = validate_username(username)
        first_name = validate_name(first_name, "First name")
        last_name = validate_name(last_name, "Last name")
    except ValidationError as e:
        return False, f"Validation error: {e}", None

    temp_password = None
    if password is None:
        temp_password = _generate_temporary_password()
        password = temp_password

    conn = get_connection()
    cursor = conn.cursor()
    encrypted_username = encrypt_username(username)
    cursor.execute("SELECT id FROM users WHERE username = ?", (encrypted_username,))
    if cursor.fetchone():
        conn.close()
        return False, f"Username '{username}' already exists", None

    password_hash = hash_password(password, username)
    cursor.execute(
        "INSERT INTO users (username, password_hash, role, first_name, last_name, must_change_password) VALUES (?, ?, ?, ?, ?, ?)",
        (encrypted_username, password_hash, "manager", first_name, last_name, 1),
    )
    conn.commit()
    conn.close()

    if current_user:
        log_activity(current_user["username"], "New manager created", f"username: {username}, name: {first_name} {last_name}")

    if temp_password:
        return True, f"Manager '{username}' created successfully", temp_password
    return True, f"Manager '{username}' created successfully", None


def create_employee_user(username, first_name, last_name, employee_id=None, password=None):
    """Create new Employee user account (Super Admin or Manager)."""
    if not check_permission("manage_employees"):
        return False, "Access denied. Insufficient permissions to create Employee accounts", None

    current_user = get_current_user()
    try:
        username = validate_username(username)
        first_name = validate_name(first_name, "First name")
        last_name = validate_name(last_name, "Last name")
    except ValidationError as e:
        return False, f"Validation error: {e}", None

    temp_password = None
    if password is None:
        temp_password = _generate_temporary_password()
        password = temp_password

    conn = get_connection()
    cursor = conn.cursor()
    encrypted_username = encrypt_username(username)
    cursor.execute("SELECT id FROM users WHERE username = ?", (encrypted_username,))
    if cursor.fetchone():
        conn.close()
        return False, f"Username '{username}' already exists", None

    password_hash = hash_password(password, username)
    cursor.execute(
        "INSERT INTO users (username, password_hash, role, first_name, last_name, employee_id, must_change_password) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (encrypted_username, password_hash, "employee", first_name, last_name, employee_id, 1),
    )
    conn.commit()
    conn.close()

    if current_user:
        log_activity(current_user["username"], "New employee user created", f"username: {username}, name: {first_name} {last_name}")

    if temp_password:
        return True, f"Employee user '{username}' created successfully", temp_password
    return True, f"Employee user '{username}' created successfully", None


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: USER DELETION
# ═══════════════════════════════════════════════════════════════════════════


def delete_user(username):
    """Delete user account (role-based permissions)."""
    current_user = get_current_user()
    if not current_user:
        return False, "You must be logged in to delete users"

    try:
        username = validate_username(username)
    except ValidationError as e:
        return False, f"Invalid username: {e}"

    if username.lower() == "super_admin":
        return False, "Cannot delete Super Administrator account"

    # Self-deletion rules
    is_self_deletion = username.lower() == current_user["username"].lower()
    if is_self_deletion:
        if current_user["role"] == "super_admin":
            return False, "Super Administrator cannot delete their own account"
        if current_user["role"] == "employee":
            return False, "Employees cannot delete their own account"
        # Manager CAN delete their own account

    conn = get_connection()
    cursor = conn.cursor()
    encrypted_username = encrypt_username(username)
    cursor.execute("SELECT id, role, first_name, last_name FROM users WHERE username = ?", (encrypted_username,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return False, f"User '{username}' not found"

    user_id, target_role, first_name, last_name = user

    if target_role == "manager":
        if not check_permission("manage_managers"):
            conn.close()
            return False, "Access denied. Only Super Administrator can delete Managers"
    elif target_role == "employee":
        if not check_permission("manage_employees"):
            conn.close()
            return False, "Access denied. Insufficient permissions to delete Employee users"

    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    log_activity(current_user["username"], "User deleted", f"User '{username}' ({get_role_name(target_role)}) deleted")
    return True, f"User '{username}' deleted successfully"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: PASSWORD MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════


def reset_user_password(username):
    """Reset user password to a temporary password."""
    current_user = get_current_user()
    if not current_user:
        return False, "You must be logged in to reset passwords", None

    try:
        username = validate_username(username)
    except ValidationError as e:
        return False, f"Invalid username: {e}", None

    if username.lower() == "super_admin":
        return False, "Cannot reset Super Administrator password (hardcoded)", None

    conn = get_connection()
    cursor = conn.cursor()
    encrypted_username = encrypt_username(username)
    cursor.execute("SELECT id, role FROM users WHERE username = ?", (encrypted_username,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return False, f"User '{username}' not found", None

    user_id, target_role = user

    if target_role == "manager":
        if not check_permission("manage_managers"):
            conn.close()
            return False, "Access denied. Only Super Administrator can reset Manager passwords", None
    elif target_role == "employee":
        if not check_permission("manage_employees"):
            conn.close()
            return False, "Access denied. Insufficient permissions to reset Employee passwords", None

    temp_password = _generate_temporary_password()
    new_password_hash = hash_password(temp_password, username)
    cursor.execute("UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?", (new_password_hash, user_id))
    conn.commit()
    conn.close()

    log_activity(current_user["username"], "Password reset", f"For user: {username} ({get_role_name(target_role)})")
    return True, f"Password reset successfully for '{username}'", temp_password


def _generate_temporary_password():
    """Generate secure temporary password (12 chars, meets all requirements)."""
    password_chars = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("~!@#$%&_-+="),
    ]
    all_chars = string.ascii_letters + string.digits + "~!@#$%&_-+="
    password_chars.extend(secrets.choice(all_chars) for _ in range(8))
    password_list = list(password_chars)
    secrets.SystemRandom().shuffle(password_list)
    return "".join(password_list)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: PROFILE UPDATES
# ═══════════════════════════════════════════════════════════════════════════


def update_user_profile(username, first_name=None, last_name=None):
    """Update user profile (first name, last name)."""
    current_user = get_current_user()
    if not current_user:
        return False, "You must be logged in to update user profiles"

    if first_name is None and last_name is None:
        return False, "Must specify at least first_name or last_name to update"

    try:
        username = validate_username(username)
    except ValidationError as e:
        return False, f"Invalid username: {e}"

    try:
        if first_name is not None:
            first_name = validate_name(first_name, "First name")
        if last_name is not None:
            last_name = validate_name(last_name, "Last name")
    except ValidationError as e:
        return False, f"Validation error: {e}"

    conn = get_connection()
    cursor = conn.cursor()
    encrypted_username = encrypt_username(username)
    cursor.execute("SELECT id, role, first_name, last_name FROM users WHERE username = ?", (encrypted_username,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return False, f"User '{username}' not found"

    user_id, target_role, old_first_name, old_last_name = user

    if target_role == "manager":
        if not check_permission("manage_managers"):
            conn.close()
            return False, "Access denied. Only Super Administrator can update Manager profiles"
    elif target_role == "employee":
        if not check_permission("manage_employees"):
            conn.close()
            return False, "Access denied. Insufficient permissions to update Employee profiles"

    update_fields = []
    params = []
    if first_name is not None:
        update_fields.append("first_name = ?")
        params.append(first_name)
    if last_name is not None:
        update_fields.append("last_name = ?")
        params.append(last_name)
    params.append(user_id)

    cursor.execute(f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?", tuple(params))
    conn.commit()
    conn.close()

    changes = []
    if first_name is not None:
        changes.append(f"first_name: '{old_first_name}' → '{first_name}'")
    if last_name is not None:
        changes.append(f"last_name: '{old_last_name}' → '{last_name}'")

    log_activity(current_user["username"], "User profile updated", f"User: {username}, Changes: {', '.join(changes)}")
    return True, f"Profile updated successfully for '{username}'"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5: USER LISTING
# ═══════════════════════════════════════════════════════════════════════════


def list_all_users():
    """List all users with their roles."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, role, first_name, last_name, created_at FROM users ORDER BY created_at DESC")
    results = cursor.fetchall()
    conn.close()

    users = []
    for row in results:
        enc_username, role, first_name, last_name, created_at = row
        users.append({
            "username": decrypt_username(enc_username),
            "role": role,
            "role_name": get_role_name(role),
            "first_name": first_name,
            "last_name": last_name,
            "created_at": created_at,
        })
    return users
