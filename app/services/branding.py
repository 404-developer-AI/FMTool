"""Report branding: logo upload and report settings persistence."""

import os

from werkzeug.utils import secure_filename

from app.models.database import get_setting, set_setting, get_all_settings

ALLOWED_LOGO_EXTENSIONS = {"png", "jpg", "jpeg"}
MAX_LOGO_SIZE = 2 * 1024 * 1024  # 2 MB

DEFAULT_REPORT_TITLE = "pfSense to Sophos XGS Migration Report"

SETTING_COMPANY_NAME = "company_name"
SETTING_REPORT_TITLE = "report_title"
SETTING_LOGO_FILENAME = "logo_filename"


def get_report_settings(db_path):
    """Return current report settings with defaults applied."""
    all_settings = get_all_settings(db_path)
    return {
        "company_name": all_settings.get(SETTING_COMPANY_NAME, "") or "",
        "report_title": all_settings.get(SETTING_REPORT_TITLE) or DEFAULT_REPORT_TITLE,
        "logo_filename": all_settings.get(SETTING_LOGO_FILENAME) or "",
    }


def save_report_settings(db_path, company_name, report_title):
    set_setting(db_path, SETTING_COMPANY_NAME, (company_name or "").strip())
    set_setting(db_path, SETTING_REPORT_TITLE, (report_title or "").strip() or DEFAULT_REPORT_TITLE)


def _logo_ext_allowed(filename):
    if "." not in filename:
        return False
    return filename.rsplit(".", 1)[1].lower() in ALLOWED_LOGO_EXTENSIONS


def save_logo(db_path, branding_folder, file_storage):
    """Save an uploaded logo file. Returns (ok, message)."""
    if not file_storage or not file_storage.filename:
        return False, "No file provided"

    filename = secure_filename(file_storage.filename)
    if not _logo_ext_allowed(filename):
        return False, "Logo must be .png, .jpg or .jpeg"

    file_storage.stream.seek(0, os.SEEK_END)
    size = file_storage.stream.tell()
    file_storage.stream.seek(0)
    if size > MAX_LOGO_SIZE:
        return False, f"Logo too large (max {MAX_LOGO_SIZE // 1024} KB)"
    if size == 0:
        return False, "Empty file"

    os.makedirs(branding_folder, exist_ok=True)

    # Remove any existing logo regardless of extension to avoid stale files
    delete_logo_file(db_path, branding_folder)

    ext = filename.rsplit(".", 1)[1].lower()
    target_name = f"logo.{ext}"
    target_path = os.path.join(branding_folder, target_name)
    file_storage.save(target_path)

    # Verify the file is a readable image; reject otherwise to avoid breaking PDF export.
    try:
        from PIL import Image as PILImage
        with PILImage.open(target_path) as img:
            img.load()
    except Exception:
        try:
            os.remove(target_path)
        except OSError:
            pass
        return False, "File is not a valid image"

    set_setting(db_path, SETTING_LOGO_FILENAME, target_name)
    return True, "Logo uploaded"


def delete_logo_file(db_path, branding_folder):
    """Delete current logo file + clear setting. Idempotent."""
    current = get_setting(db_path, SETTING_LOGO_FILENAME)
    if current:
        path = os.path.join(branding_folder, current)
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass
    set_setting(db_path, SETTING_LOGO_FILENAME, "")


def get_logo_path(db_path, branding_folder):
    """Return absolute path to current logo file, or None if not set/missing."""
    current = get_setting(db_path, SETTING_LOGO_FILENAME)
    if not current:
        return None
    path = os.path.join(branding_folder, current)
    if not os.path.exists(path):
        return None
    return path
