"""Migration routes for pfSense to Sophos XGS."""

from flask import Blueprint, current_app, jsonify, render_template, request
from app.models.database import (
    get_table_items, get_aliases_by_ids, update_migration_status,
)
from app.services.sophos_client import (
    is_configured, get_client, get_existing_object_names,
    SophosConnectionError,
)
from app.services.migration_engine import (
    plan_alias_migration, execute_alias_migration,
    plan_to_dict, result_to_dict,
)

migrate_bp = Blueprint("migrate", __name__)


@migrate_bp.route("/migrate/aliases")
def migrate_aliases():
    """Render the alias migration page."""
    db_path = current_app.config["DATABASE_PATH"]
    aliases = get_table_items(db_path, "aliases")
    configured = is_configured(current_app.config)
    return render_template(
        "migrate_aliases.html",
        aliases=aliases,
        configured=configured,
    )


@migrate_bp.route("/migrate/aliases/check-duplicates", methods=["POST"])
def check_duplicates():
    """AJAX: Check which aliases already exist on Sophos by name."""
    if not is_configured(current_app.config):
        return jsonify({"success": False, "message": "Sophos API not configured"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    aliases = get_table_items(db_path, "aliases")
    if not aliases:
        return jsonify({"success": True, "duplicates": []})

    try:
        existing_names = get_existing_object_names(current_app.config)
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to fetch Sophos objects: {e}"}), 500

    from app.services.migration_engine import sanitize_sophos_name

    # Build case-insensitive lookup sets
    existing_lower = {}
    for category, names in existing_names.items():
        for name in names:
            existing_lower[name.lower()] = category

    duplicates = []
    for alias in aliases:
        if alias.get("migration_status") in ("migrated", "skipped"):
            continue
        sophos_name = sanitize_sophos_name(alias["name"])
        if sophos_name.lower() in existing_lower:
            category = existing_lower[sophos_name.lower()]
            duplicates.append({
                "alias_id": alias["id"],
                "alias_name": alias["name"],
                "sophos_type": category,
            })

    # Persist: mark duplicates as "migrated" in DB
    if duplicates:
        dup_ids = [d["alias_id"] for d in duplicates]
        update_migration_status(db_path, "aliases", dup_ids, "migrated")

    return jsonify({"success": True, "duplicates": duplicates})


@migrate_bp.route("/migrate/aliases/plan", methods=["POST"])
def plan_aliases():
    """AJAX: Generate dry-run migration plan for selected aliases."""
    data = request.get_json()
    if not data or "alias_ids" not in data:
        return jsonify({"success": False, "message": "No alias IDs provided"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    alias_ids = data["alias_ids"]
    fqdn_overrides = data.get("fqdn_overrides", {})

    aliases = get_aliases_by_ids(db_path, alias_ids)
    if not aliases:
        return jsonify({"success": False, "message": "No aliases found"}), 404

    if not is_configured(current_app.config):
        return jsonify({"success": False, "message": "Sophos API not configured"}), 400

    try:
        existing_names = get_existing_object_names(current_app.config)
    except SophosConnectionError as e:
        return jsonify({"success": False, "message": str(e)}), 500
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to fetch Sophos objects: {e}"}), 500

    plans = []
    for alias in aliases:
        fqdn_override = fqdn_overrides.get(alias["name"])
        plan = plan_alias_migration(alias, existing_names, fqdn_override=fqdn_override)
        plans.append(plan_to_dict(plan))

    return jsonify({"success": True, "plans": plans})


@migrate_bp.route("/migrate/aliases/execute", methods=["POST"])
def execute_aliases():
    """AJAX: Execute migration for selected aliases."""
    data = request.get_json()
    if not data or "alias_ids" not in data:
        return jsonify({"success": False, "message": "No alias IDs provided"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    alias_ids = data["alias_ids"]
    fqdn_overrides = data.get("fqdn_overrides", {})

    aliases = get_aliases_by_ids(db_path, alias_ids)
    if not aliases:
        return jsonify({"success": False, "message": "No aliases found"}), 404

    if not is_configured(current_app.config):
        return jsonify({"success": False, "message": "Sophos API not configured"}), 400

    try:
        client = get_client(current_app.config)
        existing_names = get_existing_object_names(current_app.config)
    except SophosConnectionError as e:
        return jsonify({"success": False, "message": str(e)}), 500
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to connect to Sophos: {e}"}), 500

    results = []
    for alias in aliases:
        fqdn_override = fqdn_overrides.get(alias["name"])
        plan = plan_alias_migration(alias, existing_names, fqdn_override=fqdn_override)
        result = execute_alias_migration(client, plan)
        # Update migration status in database
        update_migration_status(db_path, "aliases", [alias["id"]], result.status)
        results.append(result_to_dict(result))

    return jsonify({"success": True, "results": results})


@migrate_bp.route("/migrate/aliases/skip", methods=["POST"])
def skip_aliases():
    """AJAX: Mark selected aliases as skipped."""
    data = request.get_json()
    if not data or "alias_ids" not in data:
        return jsonify({"success": False, "message": "No alias IDs provided"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    alias_ids = data["alias_ids"]
    updated = update_migration_status(db_path, "aliases", alias_ids, "skipped")
    return jsonify({"success": True, "updated": updated})


@migrate_bp.route("/migrate/virtual-ips")
def migrate_virtual_ips():
    """Render the Virtual IPs documentation page."""
    db_path = current_app.config["DATABASE_PATH"]
    vips = get_table_items(db_path, "virtual_ips")
    return render_template("migrate_virtualips.html", vips=vips)


@migrate_bp.route("/migrate/virtual-ips/skip", methods=["POST"])
def skip_virtual_ips():
    """AJAX: Mark all Virtual IPs as skipped."""
    db_path = current_app.config["DATABASE_PATH"]
    vips = get_table_items(db_path, "virtual_ips")
    vip_ids = [v["id"] for v in vips]
    updated = update_migration_status(db_path, "virtual_ips", vip_ids, "skipped")
    return jsonify({"success": True, "updated": updated})
