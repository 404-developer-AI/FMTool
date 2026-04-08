"""Activity Log routes for FMTool."""

from flask import Blueprint, current_app, jsonify, render_template, request
from app.services.activity_logger import get_activity_log, get_item_log

activity_bp = Blueprint("activity_log", __name__)


@activity_bp.route("/activity-log")
def activity_log_page():
    """Render the Activity Log page."""
    return render_template("activity_log.html")


@activity_bp.route("/activity-log/data")
def activity_log_data():
    """AJAX: Return filtered/paginated log entries as JSON."""
    db_path = current_app.config["DATABASE_PATH"]

    category = request.args.get("category") or None
    action_type = request.args.get("action_type") or None
    result = request.args.get("result") or None
    search = request.args.get("search") or None
    date_from = request.args.get("date_from") or None
    date_to = request.args.get("date_to") or None
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))
    sort_col = request.args.get("sort", "timestamp")
    sort_dir = request.args.get("dir", "desc")

    data = get_activity_log(
        db_path,
        category=category,
        action_type=action_type,
        result=result,
        search=search,
        date_from=date_from,
        date_to=date_to,
        page=page,
        per_page=per_page,
        sort_col=sort_col,
        sort_dir=sort_dir,
    )
    return jsonify(data)


@activity_bp.route("/activity-log/item/<category>/<int:item_id>")
def item_log(category, item_id):
    """AJAX: Return log entries for one item (for per-item modal)."""
    db_path = current_app.config["DATABASE_PATH"]
    item_name = request.args.get("name") or None
    entries = get_item_log(db_path, category, item_id=item_id, item_name=item_name)
    return jsonify({"entries": entries})
