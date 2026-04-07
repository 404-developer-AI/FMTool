from flask import Blueprint, abort, current_app, render_template

from app.models.database import DETAIL_TABLES, get_table_items

overview_bp = Blueprint("overview", __name__)


@overview_bp.route("/overview/<category>")
def detail(category):
    if category not in DETAIL_TABLES:
        abort(404)

    config = DETAIL_TABLES[category]
    db_path = current_app.config["DATABASE_PATH"]
    items = get_table_items(db_path, category)

    return render_template(
        "detail.html",
        category=category,
        label=config["label"],
        columns=config["columns"],
        has_status=config["has_status"],
        items=items,
    )
