from flask import Blueprint, current_app, render_template

from app.models.database import get_import_summary

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    db_path = current_app.config["DATABASE_PATH"]
    summary = get_import_summary(db_path)
    return render_template("index.html", summary=summary)
