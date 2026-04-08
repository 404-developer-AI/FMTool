"""Activity logging for FMTool — writes and queries the activity_log table."""

import json
import sqlite3
from datetime import datetime, timezone


def _get_conn(db_path):
    """Get a database connection for logging."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def log_activity(db_path, action_type, category, item_name=None, item_id=None,
                 details=None, result="success", error_message=None):
    """Insert one row into activity_log.

    Args:
        db_path: Path to SQLite database.
        action_type: One of api_call, dry_run, migrate, skip, reset,
                     create_service, create_host, check_duplicates,
                     rollback, cleanup, import.
        category: One of aliases, firewall_rules, nat_rules, services,
                  hosts, system.
        item_name: Human-readable name of the item (optional).
        item_id: Database row ID from the relevant table (optional).
        details: Extra context — string or dict (will be JSON-serialized).
        result: One of success, fail, error.
        error_message: Error string when result is fail/error (optional).
    """
    if isinstance(details, (dict, list)):
        details = json.dumps(details)
    timestamp = datetime.now(timezone.utc).isoformat()
    conn = _get_conn(db_path)
    try:
        conn.execute(
            """INSERT INTO activity_log
               (timestamp, action_type, category, item_name, item_id, details, result, error_message)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (timestamp, action_type, category, item_name, item_id,
             details, result, error_message),
        )
        conn.commit()
    finally:
        conn.close()


def get_activity_log(db_path, category=None, action_type=None, result=None,
                     search=None, date_from=None, date_to=None,
                     page=1, per_page=50, sort_col="timestamp", sort_dir="desc"):
    """Return paginated, filtered log entries + total count.

    Returns:
        dict: {"entries": [list of dicts], "total": int, "page": int, "per_page": int}
    """
    allowed_sort_cols = {"timestamp", "action_type", "category", "item_name", "result"}
    if sort_col not in allowed_sort_cols:
        sort_col = "timestamp"
    if sort_dir not in ("asc", "desc"):
        sort_dir = "desc"

    conditions = []
    params = []

    if category:
        conditions.append("category = ?")
        params.append(category)
    if action_type:
        conditions.append("action_type = ?")
        params.append(action_type)
    if result:
        conditions.append("result = ?")
        params.append(result)
    if search:
        conditions.append("(item_name LIKE ? OR details LIKE ? OR error_message LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like])
    if date_from:
        conditions.append("timestamp >= ?")
        params.append(date_from)
    if date_to:
        conditions.append("timestamp <= ?")
        params.append(date_to)

    where = ""
    if conditions:
        where = "WHERE " + " AND ".join(conditions)

    conn = _get_conn(db_path)
    try:
        count_row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM activity_log {where}", params
        ).fetchone()
        total = count_row["cnt"]

        offset = (page - 1) * per_page
        rows = conn.execute(
            f"SELECT * FROM activity_log {where} ORDER BY {sort_col} {sort_dir} LIMIT ? OFFSET ?",
            params + [per_page, offset],
        ).fetchall()

        entries = [dict(r) for r in rows]
    finally:
        conn.close()

    return {"entries": entries, "total": total, "page": page, "per_page": per_page}


def get_item_log(db_path, category, item_id=None, item_name=None):
    """Return log entries for a specific item and its dependencies.

    For firewall_rules / nat_rules, also includes related services/hosts logs.

    Returns:
        list of dicts
    """
    conditions = []
    params = []

    # Primary filter: exact item match
    item_conditions = []
    if item_id is not None:
        item_conditions.append("(category = ? AND item_id = ?)")
        params.extend([category, item_id])
    if item_name:
        item_conditions.append("(category = ? AND item_name = ?)")
        params.extend([category, item_name])

    if not item_conditions:
        return []

    # For rules, also fetch related service/host creation logs
    # by searching for the item_name in details field
    if category in ("firewall_rules", "nat_rules") and item_name:
        item_conditions.append(
            "(category IN ('services', 'hosts') AND details LIKE ?)"
        )
        params.append(f"%{item_name}%")

    conditions.append("(" + " OR ".join(item_conditions) + ")")
    where = "WHERE " + " AND ".join(conditions)

    conn = _get_conn(db_path)
    try:
        rows = conn.execute(
            f"SELECT * FROM activity_log {where} ORDER BY timestamp DESC",
            params,
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
