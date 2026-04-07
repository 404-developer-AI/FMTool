"""Sophos XGS connection and settings routes."""

from flask import Blueprint, current_app, jsonify, render_template

from app.services.sophos_client import (
    SophosConnectionError,
    is_configured,
    test_connection,
    get_sophos_objects_summary,
    SOPHOS_OBJECT_LABELS,
)

sophos_bp = Blueprint("sophos", __name__)


@sophos_bp.route("/sophos")
def sophos_page():
    """Render the Sophos settings and setup page."""
    configured = is_configured(current_app.config)
    host = current_app.config.get("SOPHOS_HOST", "")
    port = current_app.config.get("SOPHOS_PORT", 4444)
    return render_template(
        "sophos.html",
        configured=configured,
        host=host,
        port=port,
        object_labels=SOPHOS_OBJECT_LABELS,
    )


@sophos_bp.route("/sophos/test", methods=["POST"])
def connection_test():
    """AJAX endpoint: test Sophos API connection."""
    result = test_connection(current_app.config)
    return jsonify(result)


@sophos_bp.route("/sophos/objects", methods=["POST"])
def fetch_objects():
    """AJAX endpoint: fetch existing Sophos object counts."""
    try:
        summary = get_sophos_objects_summary(current_app.config)
        return jsonify({"success": True, "objects": summary})
    except SophosConnectionError as e:
        return jsonify({"success": False, "message": str(e)})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error fetching objects: {e}"})


@sophos_bp.route("/sophos/status")
def connection_status():
    """AJAX endpoint: connection status for dashboard card."""
    config = current_app.config
    if not is_configured(config):
        return jsonify({"configured": False, "connected": False})

    result = test_connection(config)
    return jsonify({
        "configured": True,
        "connected": result["success"],
        "message": result.get("message", ""),
        "firmware_version": result.get("firmware_version"),
        "serial_number": result.get("serial_number"),
        "model": result.get("model"),
    })
