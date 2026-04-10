"""Export routes: CSV and PDF migration report downloads."""

from flask import Blueprint, Response, current_app, request

from app.services.export_engine import (
    REPORT_CATEGORIES,
    build_filename,
    build_report_data,
    generate_csv,
    generate_pdf,
)

export_bp = Blueprint("export", __name__)

VALID_SCOPES = {"global", *REPORT_CATEGORIES.keys()}
VALID_MODES = {"snapshot", "range"}


def _parse_params():
    scope = request.args.get("scope", "global")
    if scope not in VALID_SCOPES:
        scope = "global"
    mode = request.args.get("mode", "snapshot")
    if mode not in VALID_MODES:
        mode = "snapshot"
    date_from = request.args.get("date_from") or None
    date_to = request.args.get("date_to") or None
    if mode == "range" and (not date_from or not date_to):
        # Fall back gracefully
        mode = "snapshot"
        date_from = None
        date_to = None
    return scope, mode, date_from, date_to


@export_bp.route("/export/csv", methods=["GET"])
def export_csv():
    scope, mode, date_from, date_to = _parse_params()
    db_path = current_app.config["DATABASE_PATH"]
    branding_folder = current_app.config["BRANDING_FOLDER"]

    report = build_report_data(
        db_path, branding_folder, scope=scope, mode=mode,
        date_from=date_from, date_to=date_to,
    )
    body = generate_csv(report)
    filename = build_filename(scope, "csv")

    return Response(
        body,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@export_bp.route("/export/pdf", methods=["GET"])
def export_pdf():
    scope, mode, date_from, date_to = _parse_params()
    db_path = current_app.config["DATABASE_PATH"]
    branding_folder = current_app.config["BRANDING_FOLDER"]

    report = build_report_data(
        db_path, branding_folder, scope=scope, mode=mode,
        date_from=date_from, date_to=date_to,
    )
    body = generate_pdf(report)
    filename = build_filename(scope, "pdf")

    return Response(
        body,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
