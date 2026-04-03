# ═══════════════════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════════════════

import zipfile
import secrets
import string
from pathlib import Path
from datetime import datetime
from database import get_connection, encrypt_field, decrypt_field
from auth import get_current_user, check_permission
from activity_log import log_activity

BACKUP_DIR = Path(__file__).parent / "backups"
DATA_DIR = Path(__file__).parent / "data"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: BACKUP OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════


def create_backup():
    """Create ZIP backup of database + encryption keys + logs."""
    if not check_permission("create_backup"):
        return False, "Access denied. Insufficient permissions to create backup", None

    current_user = get_current_user()
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"backup_{timestamp}.zip"
    backup_path = BACKUP_DIR / backup_filename

    try:
        with zipfile.ZipFile(backup_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            db_path = DATA_DIR / "declaratieapp.db"
            if db_path.exists():
                zipf.write(db_path, "declaratieapp.db")
            aes_key_path = DATA_DIR / "aes_key.bin"
            if aes_key_path.exists():
                zipf.write(aes_key_path, "aes_key.bin")
            fernet_key_path = DATA_DIR / "fernet_key.bin"
            if fernet_key_path.exists():
                zipf.write(fernet_key_path, "fernet_key.bin")
            log_path = DATA_DIR / "system.log"
            if log_path.exists():
                zipf.write(log_path, "system.log")

        if current_user:
            log_activity(current_user["username"], "Backup created", f"Filename: {backup_filename}")
        return True, f"Backup created successfully: {backup_filename}", backup_filename
    except Exception as e:
        return False, f"Error creating backup: {e}", None


def list_backups():
    """List all available backup files."""
    if not BACKUP_DIR.exists():
        return []
    backups = []
    for backup_file in BACKUP_DIR.glob("backup_*.zip"):
        stat = backup_file.stat()
        backups.append({
            "filename": backup_file.name,
            "size": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        })
    backups.sort(key=lambda x: x["created"], reverse=True)
    return backups


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: RESTORE OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════


def restore_backup(backup_filename, restore_code=None):
    """
    Restore from ZIP backup.
    Super Admin: can restore any backup directly (no code needed).
    Manager: requires a valid one-use restore code linked to this backup and this manager.
    Note: Super Admin cannot use restore codes (only generate them).
    """
    current_user = get_current_user()
    if not current_user:
        return False, "You must be logged in to restore backup"

    is_super_admin = current_user["role"] == "super_admin"
    is_manager = current_user["role"] == "manager"

    if not is_super_admin and not is_manager:
        return False, "Access denied. Only Super Admin and Managers can restore backups"

    # Super Admin restores directly (no code)
    if is_super_admin:
        if restore_code:
            return False, "Super Administrator cannot use restore codes. Restore directly or generate codes for Managers."

    # Manager needs restore code
    if is_manager:
        if not restore_code:
            return False, "Managers require a restore code to restore backups"

        code_valid, code_backup, code_target = _validate_restore_code(restore_code)
        if not code_valid:
            log_activity(current_user["username"], "Restore attempt failed", "Invalid restore code", suspicious=True)
            return False, "Invalid or expired restore code"
        if code_backup != backup_filename:
            return False, f"Restore code is valid for '{code_backup}', not '{backup_filename}'"
        if code_target != current_user["username"]:
            log_activity(current_user["username"], "Restore attempt failed",
                         f"Code not intended for this user", suspicious=True)
            return False, "This restore code is not assigned to your account"

    backup_path = BACKUP_DIR / backup_filename
    if not backup_path.exists():
        return False, f"Backup file '{backup_filename}' not found"

    try:
        # Mark code as used BEFORE restoring (for managers)
        if is_manager and restore_code:
            _mark_code_as_used(restore_code)

        with zipfile.ZipFile(backup_path, "r") as zipf:
            if "declaratieapp.db" in zipf.namelist():
                zipf.extract("declaratieapp.db", DATA_DIR)
            if "aes_key.bin" in zipf.namelist():
                zipf.extract("aes_key.bin", DATA_DIR)
            if "fernet_key.bin" in zipf.namelist():
                zipf.extract("fernet_key.bin", DATA_DIR)
            if "system.log" in zipf.namelist():
                zipf.extract("system.log", DATA_DIR)

        log_activity(current_user["username"], "Backup restored", f"Filename: {backup_filename}")
        return True, f"Backup restored successfully from: {backup_filename}"
    except Exception as e:
        return False, f"Error restoring backup: {e}"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: RESTORE CODE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════


def generate_restore_code(backup_filename, target_username):
    """Generate one-use restore code for a specific Manager + backup (Super Admin only)."""
    if not check_permission("manage_restore_codes"):
        return False, "Access denied. Only Super Administrator can generate restore codes", None

    current_user = get_current_user()
    backup_path = BACKUP_DIR / backup_filename
    if not backup_path.exists():
        return False, f"Backup file '{backup_filename}' not found", None

    code = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(12))

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS restore_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            backup_filename TEXT NOT NULL,
            target_username TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    encrypted_code = encrypt_field(code)
    encrypted_backup = encrypt_field(backup_filename)
    encrypted_target = encrypt_field(target_username)

    cursor.execute(
        "INSERT INTO restore_codes (code, backup_filename, target_username) VALUES (?, ?, ?)",
        (encrypted_code, encrypted_backup, encrypted_target),
    )
    conn.commit()
    conn.close()

    if current_user:
        log_activity(current_user["username"], "Restore code generated",
                     f"For user: {target_username}, Backup: {backup_filename}")
    return True, "Restore code generated successfully", code


def revoke_restore_code(restore_code):
    """Revoke an unused restore code (Super Admin only)."""
    if not check_permission("manage_restore_codes"):
        return False, "Access denied. Only Super Administrator can revoke restore codes"

    current_user = get_current_user()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='restore_codes'")
    if not cursor.fetchone():
        conn.close()
        return False, "No restore codes exist"

    cursor.execute("SELECT id, code, backup_filename, target_username FROM restore_codes WHERE used = 0")
    results = cursor.fetchall()
    if not results:
        conn.close()
        return False, "No active restore codes found"

    code_id = None
    for row in results:
        row_id, encrypted_code, enc_backup, enc_target = row
        if decrypt_field(encrypted_code) == restore_code:
            code_id = row_id
            enc_backup_found = enc_backup
            enc_target_found = enc_target
            break

    if not code_id:
        conn.close()
        return False, "Restore code not found"

    cursor.execute("DELETE FROM restore_codes WHERE id = ?", (code_id,))
    conn.commit()
    conn.close()

    backup_name = decrypt_field(enc_backup_found)
    target_user = decrypt_field(enc_target_found)

    if current_user:
        log_activity(current_user["username"], "Restore code revoked",
                     f"For user: {target_user}, Backup: {backup_name}")
    return True, "Restore code revoked successfully"


def list_restore_codes():
    """List all active restore codes (Super Admin only)."""
    if not check_permission("manage_restore_codes"):
        return []

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='restore_codes'")
    if not cursor.fetchone():
        conn.close()
        return []

    cursor.execute("SELECT code, backup_filename, target_username, created_at FROM restore_codes WHERE used = 0 ORDER BY created_at DESC")
    results = cursor.fetchall()
    conn.close()

    codes = []
    for row in results:
        encrypted_code, encrypted_backup, encrypted_target, created_at = row
        codes.append({
            "code": decrypt_field(encrypted_code),
            "backup_filename": decrypt_field(encrypted_backup),
            "target_username": decrypt_field(encrypted_target),
            "created_at": created_at,
        })
    return codes


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: INTERNAL HELPERS
# ═══════════════════════════════════════════════════════════════════════════


def _validate_restore_code(restore_code):
    """Validate restore code. Returns (is_valid, backup_filename, target_username)."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='restore_codes'")
    if not cursor.fetchone():
        conn.close()
        return False, None, None

    cursor.execute("SELECT backup_filename, target_username, code FROM restore_codes WHERE used = 0")
    results = cursor.fetchall()
    conn.close()

    for row in results:
        encrypted_backup, encrypted_target, encrypted_code = row
        if decrypt_field(encrypted_code) == restore_code:
            return True, decrypt_field(encrypted_backup), decrypt_field(encrypted_target)

    return False, None, None


def _mark_code_as_used(restore_code):
    """Mark restore code as used."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, code FROM restore_codes WHERE used = 0")
    results = cursor.fetchall()

    for row_id, encrypted_code in results:
        try:
            if decrypt_field(encrypted_code) == restore_code:
                cursor.execute("UPDATE restore_codes SET used = 1 WHERE id = ?", (row_id,))
                break
        except Exception:
            continue

    conn.commit()
    conn.close()
