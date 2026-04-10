"""Application settings routes (report branding, etc.)."""

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from app.services.branding import (
    delete_logo_file,
    get_logo_path,
    get_report_settings,
    save_logo,
    save_report_settings,
)

settings_bp = Blueprint("settings", __name__)


@settings_bp.route("/settings/reports", methods=["GET"])
def report_settings_page():
    db_path = current_app.config["DATABASE_PATH"]
    settings = get_report_settings(db_path)
    has_logo = bool(get_logo_path(db_path, current_app.config["BRANDING_FOLDER"]))
    return render_template(
        "report_settings.html",
        settings=settings,
        has_logo=has_logo,
    )


@settings_bp.route("/settings/reports", methods=["POST"])
def save_report_settings_route():
    db_path = current_app.config["DATABASE_PATH"]
    company_name = request.form.get("company_name", "")
    report_title = request.form.get("report_title", "")
    save_report_settings(db_path, company_name, report_title)
    flash("Report settings saved", "success")
    return redirect(url_for("settings.report_settings_page"))


@settings_bp.route("/settings/reports/logo", methods=["POST"])
def upload_logo_route():
    db_path = current_app.config["DATABASE_PATH"]
    branding_folder = current_app.config["BRANDING_FOLDER"]
    file = request.files.get("logo")
    ok, message = save_logo(db_path, branding_folder, file)
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"success": ok, "message": message})
    flash(message, "success" if ok else "error")
    return redirect(url_for("settings.report_settings_page"))


@settings_bp.route("/settings/reports/logo/delete", methods=["POST"])
def delete_logo_route():
    db_path = current_app.config["DATABASE_PATH"]
    branding_folder = current_app.config["BRANDING_FOLDER"]
    delete_logo_file(db_path, branding_folder)
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"success": True})
    flash("Logo removed", "success")
    return redirect(url_for("settings.report_settings_page"))


@settings_bp.route("/settings/branding/logo", methods=["GET"])
def serve_logo():
    """Serve the current logo file for UI preview."""
    db_path = current_app.config["DATABASE_PATH"]
    branding_folder = current_app.config["BRANDING_FOLDER"]
    path = get_logo_path(db_path, branding_folder)
    if not path:
        return "", 404
    return send_file(path)
