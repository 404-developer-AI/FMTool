"""Upload routes for pfSense backup import."""

import hashlib
import os

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from werkzeug.utils import secure_filename

from app.models.database import (
    cleanup_all,
    get_import_summary,
    get_last_import,
    store_import,
)
from app.services.parser import ParseError, parse_pfsense_backup

upload_bp = Blueprint("upload", __name__)


@upload_bp.route("/import")
def upload_page():
    """Render the upload page with import summary."""
    db_path = current_app.config["DATABASE_PATH"]
    summary = get_import_summary(db_path)
    return render_template("upload.html", summary=summary)


@upload_bp.route("/import", methods=["POST"])
def upload_file():
    """Handle pfSense XML backup upload."""
    db_path = current_app.config["DATABASE_PATH"]
    upload_folder = current_app.config["UPLOAD_FOLDER"]

    # Validate file
    if "file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for("upload.upload_page"))

    file = request.files["file"]
    if file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("upload.upload_page"))

    if not file.filename.lower().endswith(".xml"):
        flash("Only XML files are accepted.", "error")
        return redirect(url_for("upload.upload_page"))

    # Save file
    filename = secure_filename(file.filename)
    filepath = os.path.join(upload_folder, filename)
    file.save(filepath)

    # Compute hash
    with open(filepath, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    # Parse
    try:
        parsed_data = parse_pfsense_backup(filepath)
    except ParseError as e:
        os.remove(filepath)
        flash(f"Parse error: {e}", "error")
        return redirect(url_for("upload.upload_page"))

    # Check same vs new backup
    new_hostname = parsed_data["metadata"]["hostname"]
    new_domain = parsed_data["metadata"]["domain"]
    last_import = get_last_import(db_path)

    if last_import:
        old_host = last_import.get("hostname", "")
        old_domain = last_import.get("domain", "")
        if (old_host and old_domain and
                (old_host != new_hostname or old_domain != new_domain)):
            # Different firewall — need confirmation
            return jsonify({
                "confirm_needed": True,
                "message": (
                    f"This backup is from a different firewall "
                    f"({new_hostname}.{new_domain}) than the current import "
                    f"({old_host}.{old_domain}). "
                    f"All existing data will be deleted. Continue?"
                ),
                "filename": filename,
            })

    # Store
    try:
        import_id = store_import(db_path, filename, file_hash, parsed_data)
    except Exception as e:
        flash(f"Database error: {e}", "error")
        return redirect(url_for("upload.upload_page"))

    summary = get_import_summary(db_path)
    total = summary["total"] if summary else 0
    flash(f"Import successful: {total} items from {new_hostname}.{new_domain}", "success")
    return redirect(url_for("upload.upload_page"))


@upload_bp.route("/import/confirm-new", methods=["POST"])
def confirm_new_backup():
    """Handle confirmed import of a different firewall backup."""
    db_path = current_app.config["DATABASE_PATH"]
    upload_folder = current_app.config["UPLOAD_FOLDER"]

    filename = request.form.get("filename", "")
    filepath = os.path.join(upload_folder, secure_filename(filename))

    if not os.path.exists(filepath):
        flash("Upload file not found. Please upload again.", "error")
        return redirect(url_for("upload.upload_page"))

    # Cleanup existing data
    cleanup_all(db_path, upload_folder)

    # Re-save the file (cleanup may have removed it)
    # The file should still exist since we check above
    # but if cleanup removed it, we need to handle that
    if not os.path.exists(filepath):
        flash("File was removed during cleanup. Please upload again.", "error")
        return redirect(url_for("upload.upload_page"))

    # Compute hash
    with open(filepath, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    # Parse and store
    try:
        parsed_data = parse_pfsense_backup(filepath)
        import_id = store_import(db_path, filename, file_hash, parsed_data)
    except (ParseError, Exception) as e:
        flash(f"Import error: {e}", "error")
        return redirect(url_for("upload.upload_page"))

    meta = parsed_data["metadata"]
    summary = get_import_summary(db_path)
    total = summary["total"] if summary else 0
    flash(f"Import successful: {total} items from {meta['hostname']}.{meta['domain']}", "success")
    return redirect(url_for("upload.upload_page"))


@upload_bp.route("/import/cleanup", methods=["POST"])
def cleanup():
    """Delete all imported data and uploaded files."""
    db_path = current_app.config["DATABASE_PATH"]
    upload_folder = current_app.config["UPLOAD_FOLDER"]
    cleanup_all(db_path, upload_folder)
    flash("All imported data has been deleted.", "success")
    return redirect(url_for("upload.upload_page"))
