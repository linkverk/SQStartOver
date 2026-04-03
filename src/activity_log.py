# ═══════════════════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════════════════

import csv
from datetime import datetime
from pathlib import Path
from cryptography.fernet import Fernet


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: CONSTANTS & FILE PATHS
# ═══════════════════════════════════════════════════════════════════════════

DATA_DIR = Path(__file__).parent / "data"
LOG_FILE = DATA_DIR / "system.log"
FERNET_KEY_FILE = DATA_DIR / "fernet_key.bin"
LAST_CHECK_FILE = DATA_DIR / "last_log_check.txt"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: ENCRYPTION HELPERS
# ═══════════════════════════════════════════════════════════════════════════


def _get_log_cipher():
    """Get Fernet cipher for log encryption."""
    if not FERNET_KEY_FILE.exists():
        raise FileNotFoundError(f"Fernet key file not found at {FERNET_KEY_FILE}! Run database.py first.")
    with open(FERNET_KEY_FILE, "rb") as f:
        key = f.read()
    return Fernet(key)


def _encrypt_log_content(content):
    """Encrypt log content with Fernet."""
    cipher = _get_log_cipher()
    return cipher.encrypt(content.encode())


def _decrypt_log_content(encrypted_content):
    """Decrypt log content with Fernet."""
    cipher = _get_log_cipher()
    return cipher.decrypt(encrypted_content).decode()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: LOGGING FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════


def log_activity(username, activity, additional_info="", suspicious=False):
    """
    Log an activity to encrypted log file.
    Structure: No. | Date | Time | Username | Activity | Additional Info | Suspicious
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    log_number = 1
    if LOG_FILE.exists():
        try:
            with open(LOG_FILE, "rb") as f:
                encrypted_content = f.read()
            decrypted_content = _decrypt_log_content(encrypted_content)
            lines = decrypted_content.strip().split("\n")
            if len(lines) > 1:
                last_line = lines[-1]
                log_number = int(last_line.split(",")[0].strip('"')) + 1
        except Exception:
            log_number = 1

    now = datetime.now()
    date_str = now.strftime("%d-%m-%Y")
    time_str = now.strftime("%H:%M:%S")
    suspicious_str = "Yes" if suspicious else "No"

    log_entry = [str(log_number), date_str, time_str, username, activity, additional_info, suspicious_str]

    existing_content = ""
    if LOG_FILE.exists():
        try:
            with open(LOG_FILE, "rb") as f:
                encrypted_content = f.read()
            existing_content = _decrypt_log_content(encrypted_content)
        except Exception:
            existing_content = "No.,Date,Time,Username,Activity,Additional Info,Suspicious\n"
    else:
        existing_content = "No.,Date,Time,Username,Activity,Additional Info,Suspicious\n"

    log_line = ",".join(f'"{field}"' for field in log_entry)
    new_content = existing_content + log_line + "\n"

    encrypted_content = _encrypt_log_content(new_content)
    with open(LOG_FILE, "wb") as f:
        f.write(encrypted_content)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: LOG RETRIEVAL FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════


def get_all_logs():
    """Retrieve all logs (decrypted) for admin viewing."""
    if not LOG_FILE.exists():
        return []
    try:
        with open(LOG_FILE, "rb") as f:
            encrypted_content = f.read()
        decrypted_content = _decrypt_log_content(encrypted_content)
        lines = decrypted_content.strip().split("\n")
        if len(lines) <= 1:
            return []
        logs = []
        reader = csv.DictReader(lines)
        for row in reader:
            logs.append({
                "no": int(row["No."]),
                "date": row["Date"],
                "time": row["Time"],
                "username": row["Username"],
                "activity": row["Activity"],
                "additional_info": row["Additional Info"],
                "suspicious": row["Suspicious"],
            })
        return logs
    except Exception as e:
        print(f"Error reading logs: {e}")
        return []


def get_suspicious_logs():
    """Get only suspicious logs."""
    all_logs = get_all_logs()
    return [log for log in all_logs if log["suspicious"] == "Yes"]


def get_unread_suspicious_count():
    """Count unread suspicious activities since last check."""
    last_checked = 0
    if LAST_CHECK_FILE.exists():
        try:
            with open(LAST_CHECK_FILE, "r") as f:
                last_checked = int(f.read().strip())
        except Exception:
            last_checked = 0
    suspicious_logs = get_suspicious_logs()
    unread_count = sum(1 for log in suspicious_logs if log["no"] > last_checked)
    return unread_count


def check_suspicious_activities():
    """Check for unread suspicious activities (alias)."""
    return get_unread_suspicious_count()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5: LOG MANAGEMENT FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════


def mark_logs_as_read():
    """Mark all current logs as read."""
    logs = get_all_logs()
    if not logs:
        return
    highest_log_no = max(log["no"] for log in logs)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(LAST_CHECK_FILE, "w") as f:
        f.write(str(highest_log_no))


def clear_logs():
    """Clear all logs."""
    try:
        if LOG_FILE.exists():
            LOG_FILE.unlink()
        if LAST_CHECK_FILE.exists():
            LAST_CHECK_FILE.unlink()
        return True, "All logs cleared successfully"
    except Exception as e:
        return False, f"Error clearing logs: {e}"


def display_logs(logs, show_suspicious_only=False):
    """Display logs in formatted table."""
    if show_suspicious_only:
        logs = [log for log in logs if log["suspicious"] == "Yes"]
    if not logs:
        print("No logs found.")
        return

    col_widths = {"no": 5, "date": 12, "time": 10, "username": 15, "activity": 30, "additional_info": 55, "suspicious": 10}
    total_width = sum(col_widths.values()) + (len(col_widths) - 1) * 3

    print("\n" + "=" * total_width)
    print(
        f"{'No.':<{col_widths['no']}} | "
        f"{'Date':<{col_widths['date']}} | "
        f"{'Time':<{col_widths['time']}} | "
        f"{'Username':<{col_widths['username']}} | "
        f"{'Activity':<{col_widths['activity']}} | "
        f"{'Additional Info':<{col_widths['additional_info']}} | "
        f"{'Suspicious':<{col_widths['suspicious']}}"
    )
    print("=" * total_width)

    for log in logs:
        print(
            f"{log['no']:<{col_widths['no']}} | "
            f"{log['date']:<{col_widths['date']}} | "
            f"{log['time']:<{col_widths['time']}} | "
            f"{log['username']:<{col_widths['username']}} | "
            f"{log['activity']:<{col_widths['activity']}} | "
            f"{log['additional_info']:<{col_widths['additional_info']}} | "
            f"{log['suspicious']:<{col_widths['suspicious']}}"
        )

    print("=" * total_width)
    print(f"Total logs: {len(logs)}")
    suspicious_count = sum(1 for log in logs if log["suspicious"] == "Yes")
    if suspicious_count > 0:
        print(f"⚠️  Suspicious activities: {suspicious_count}")
