"""Migration routes for pfSense to Sophos XGS."""

from flask import Blueprint, current_app, jsonify, render_template, request
from app.models.database import (
    get_table_items, get_aliases_by_ids, get_firewall_rules_by_ids,
    update_migration_status,
    get_zone_mappings, save_zone_mapping, delete_zone_mapping,
    get_network_alias_mappings, save_network_alias_mapping, delete_network_alias_mapping,
)
from app.services.sophos_client import (
    is_configured, get_client, get_existing_object_names,
    get_existing_fw_rule_names, get_zone_names, get_existing_services_with_details,
    get_interface_details, SophosConnectionError,
)
from app.services.migration_engine import (
    plan_alias_migration, execute_alias_migration,
    plan_to_dict, result_to_dict,
    plan_fwrule_migration, execute_fwrule_migration,
    planned_rule_to_dict, rule_result_to_dict,
    sanitize_sophos_name,
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


# --- Firewall Rules Migration ---


@migrate_bp.route("/migrate/firewall-rules")
def migrate_firewall_rules():
    """Render the firewall rules migration page."""
    db_path = current_app.config["DATABASE_PATH"]
    rules = get_table_items(db_path, "firewall_rules")
    configured = is_configured(current_app.config)
    zone_maps = get_zone_mappings(db_path)
    network_maps = get_network_alias_mappings(db_path)

    # Get unique pfSense interfaces from imported rules
    pf_interfaces = sorted({r["interface"] for r in rules if r.get("interface")})

    # Get unique network references (type=network) for mapping suggestions
    pf_network_refs = set()
    for r in rules:
        if r.get("source_type") == "network" and r.get("source_value"):
            pf_network_refs.add(r["source_value"])
        if r.get("destination_type") == "network" and r.get("destination_value"):
            pf_network_refs.add(r["destination_value"])
    pf_network_refs = sorted(pf_network_refs)

    return render_template(
        "migrate_firewallrules.html",
        rules=rules,
        configured=configured,
        zone_mappings=zone_maps,
        network_mappings=network_maps,
        pf_interfaces=pf_interfaces,
        pf_network_refs=pf_network_refs,
    )


@migrate_bp.route("/migrate/firewall-rules/check-duplicates", methods=["POST"])
def check_fwrule_duplicates():
    """AJAX: Check which firewall rules already exist on Sophos by name."""
    if not is_configured(current_app.config):
        return jsonify({"success": False, "message": "Sophos API not configured"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    rules = get_table_items(db_path, "firewall_rules")
    if not rules:
        return jsonify({"success": True, "duplicates": []})

    try:
        existing_names = get_existing_fw_rule_names(current_app.config)
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to fetch Sophos rules: {e}"}), 500

    existing_lower = {n.lower(): n for n in existing_names}

    duplicates = []
    for rule in rules:
        if rule.get("migration_status") in ("migrated", "skipped"):
            continue
        descr = rule.get("descr") or ""
        tracker = rule.get("tracker") or str(rule["id"])
        name_base = descr if descr else f"pf_rule_{tracker}"
        sophos_name = sanitize_sophos_name(name_base)
        if sophos_name and sophos_name.lower() in existing_lower:
            duplicates.append({
                "rule_id": rule["id"],
                "rule_name": sophos_name,
            })

    if duplicates:
        dup_ids = [d["rule_id"] for d in duplicates]
        update_migration_status(db_path, "firewall_rules", dup_ids, "migrated")

    return jsonify({"success": True, "duplicates": duplicates})


@migrate_bp.route("/migrate/firewall-rules/plan", methods=["POST"])
def plan_firewall_rules():
    """AJAX: Generate dry-run migration plan for selected firewall rules."""
    data = request.get_json()
    if not data or "rule_ids" not in data:
        return jsonify({"success": False, "message": "No rule IDs provided"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    rule_ids = data["rule_ids"]

    rules = get_firewall_rules_by_ids(db_path, rule_ids)
    if not rules:
        return jsonify({"success": False, "message": "No rules found"}), 404

    if not is_configured(current_app.config):
        return jsonify({"success": False, "message": "Sophos API not configured"}), 400

    try:
        existing_rule_names = get_existing_fw_rule_names(current_app.config)
        existing_services = get_existing_services_with_details(current_app.config)
        existing_object_names = get_existing_object_names(current_app.config)
    except SophosConnectionError as e:
        return jsonify({"success": False, "message": str(e)}), 500
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to fetch Sophos data: {e}"}), 500

    # Load mappings
    zone_maps = {m["pfsense_interface"]: m["sophos_zone"] for m in get_zone_mappings(db_path)}
    network_maps = {m["pfsense_value"]: m["sophos_object"] for m in get_network_alias_mappings(db_path)}

    # Get migrated alias names
    aliases = get_table_items(db_path, "aliases")
    migrated_alias_names = {a["name"] for a in aliases if a.get("migration_status") == "migrated"}

    # Bulk overrides from UI
    dst_zone_override = data.get("dst_zone") or None
    dst_network_override = data.get("dst_network") or None

    # Sort rules by ID to maintain order
    rules.sort(key=lambda r: r["id"])

    plans = []
    prev_name = None
    for rule in rules:
        plan = plan_fwrule_migration(
            rule, zone_maps, network_maps,
            existing_rule_names, existing_services,
            migrated_alias_names, existing_object_names,
            prev_rule_name=prev_name,
            dst_zone_override=dst_zone_override,
            dst_network_override=dst_network_override,
        )
        plans.append(planned_rule_to_dict(plan))
        if plan.action == "create":
            prev_name = plan.rule_name

    return jsonify({"success": True, "plans": plans})


@migrate_bp.route("/migrate/firewall-rules/execute", methods=["POST"])
def execute_firewall_rules():
    """AJAX: Execute migration for selected firewall rules."""
    data = request.get_json()
    if not data or "rule_ids" not in data:
        return jsonify({"success": False, "message": "No rule IDs provided"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    rule_ids = data["rule_ids"]
    dst_zone_override = data.get("dst_zone") or None
    dst_network_override = data.get("dst_network") or None

    rules = get_firewall_rules_by_ids(db_path, rule_ids)
    if not rules:
        return jsonify({"success": False, "message": "No rules found"}), 404

    if not is_configured(current_app.config):
        return jsonify({"success": False, "message": "Sophos API not configured"}), 400

    try:
        client = get_client(current_app.config)
        existing_rule_names = get_existing_fw_rule_names(current_app.config)
        existing_services = get_existing_services_with_details(current_app.config)
        existing_object_names = get_existing_object_names(current_app.config)
    except SophosConnectionError as e:
        return jsonify({"success": False, "message": str(e)}), 500
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to connect to Sophos: {e}"}), 500

    zone_maps = {m["pfsense_interface"]: m["sophos_zone"] for m in get_zone_mappings(db_path)}
    network_maps = {m["pfsense_value"]: m["sophos_object"] for m in get_network_alias_mappings(db_path)}
    aliases = get_table_items(db_path, "aliases")
    migrated_alias_names = {a["name"] for a in aliases if a.get("migration_status") == "migrated"}

    rules.sort(key=lambda r: r["id"])

    results = []
    prev_name = None
    for rule in rules:
        plan = plan_fwrule_migration(
            rule, zone_maps, network_maps,
            existing_rule_names, existing_services,
            migrated_alias_names, existing_object_names,
            prev_rule_name=prev_name,
            dst_zone_override=dst_zone_override,
            dst_network_override=dst_network_override,
        )
        result = execute_fwrule_migration(client, plan)
        update_migration_status(db_path, "firewall_rules", [rule["id"]], result.status)
        results.append(rule_result_to_dict(result))
        if result.success and plan.action == "create":
            prev_name = plan.rule_name

    return jsonify({"success": True, "results": results})


@migrate_bp.route("/migrate/firewall-rules/skip", methods=["POST"])
def skip_firewall_rules():
    """AJAX: Mark selected firewall rules as skipped."""
    data = request.get_json()
    if not data or "rule_ids" not in data:
        return jsonify({"success": False, "message": "No rule IDs provided"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    rule_ids = data["rule_ids"]
    updated = update_migration_status(db_path, "firewall_rules", rule_ids, "skipped")
    return jsonify({"success": True, "updated": updated})


# --- Mapping CRUD ---


@migrate_bp.route("/migrate/firewall-rules/mappings", methods=["GET"])
def get_mappings():
    """Return zone and network alias mappings as JSON."""
    db_path = current_app.config["DATABASE_PATH"]
    return jsonify({
        "zone_mappings": get_zone_mappings(db_path),
        "network_mappings": get_network_alias_mappings(db_path),
    })


@migrate_bp.route("/migrate/firewall-rules/mappings/zones", methods=["POST"])
def save_zone_mapping_route():
    """Save or update a zone mapping."""
    data = request.get_json()
    if not data or not data.get("pfsense_interface") or not data.get("sophos_zone"):
        return jsonify({"success": False, "message": "Missing fields"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    save_zone_mapping(db_path, data["pfsense_interface"], data["sophos_zone"])
    return jsonify({"success": True})


@migrate_bp.route("/migrate/firewall-rules/mappings/zones/delete", methods=["POST"])
def delete_zone_mapping_route():
    """Delete a zone mapping."""
    data = request.get_json()
    if not data or not data.get("id"):
        return jsonify({"success": False, "message": "Missing mapping ID"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    deleted = delete_zone_mapping(db_path, data["id"])
    return jsonify({"success": True, "deleted": deleted})


@migrate_bp.route("/migrate/firewall-rules/mappings/network-aliases", methods=["POST"])
def save_network_alias_mapping_route():
    """Save or update a network alias mapping."""
    data = request.get_json()
    if not data or not data.get("pfsense_value") or not data.get("sophos_object"):
        return jsonify({"success": False, "message": "Missing fields"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    save_network_alias_mapping(db_path, data["pfsense_value"], data["sophos_object"])
    return jsonify({"success": True})


@migrate_bp.route("/migrate/firewall-rules/mappings/network-aliases/delete", methods=["POST"])
def delete_network_alias_mapping_route():
    """Delete a network alias mapping."""
    data = request.get_json()
    if not data or not data.get("id"):
        return jsonify({"success": False, "message": "Missing mapping ID"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    deleted = delete_network_alias_mapping(db_path, data["id"])
    return jsonify({"success": True, "deleted": deleted})


@migrate_bp.route("/migrate/firewall-rules/create-services", methods=["POST"])
def create_missing_services():
    """AJAX: Create missing services on Sophos.

    Expects JSON: {"services": [{"name": "pf_svc_tcp_25011", "protocol": "TCP", "port": "25011"}, ...]}
    """
    data = request.get_json()
    if not data or not data.get("services"):
        return jsonify({"success": False, "message": "No services provided"}), 400

    if not is_configured(current_app.config):
        return jsonify({"success": False, "message": "Sophos API not configured"}), 400

    try:
        client = get_client(current_app.config)
    except SophosConnectionError as e:
        return jsonify({"success": False, "message": str(e)}), 500

    from app.services.sophos_client import _retry_on_rate_limit

    results = []
    for svc in data["services"]:
        name = svc.get("name", "")
        protocol = svc.get("protocol", "TCP")
        port = svc.get("port", "")
        if not name or not port:
            results.append({"name": name, "success": False, "error": "Missing name or port"})
            continue
        try:
            _retry_on_rate_limit(
                client.create_service,
                name=name,
                service_type="TCPorUDP",
                service_list=[{"dst_port": port, "protocol": protocol}],
            )
            results.append({"name": name, "success": True})
        except Exception as e:
            results.append({"name": name, "success": False, "error": str(e)})

    created = sum(1 for r in results if r["success"])
    failed = sum(1 for r in results if not r["success"])
    return jsonify({"success": True, "results": results, "created": created, "failed": failed})


@migrate_bp.route("/migrate/firewall-rules/sophos-zones", methods=["POST"])
def fetch_sophos_zones():
    """AJAX: Fetch zone names from Sophos for dropdown population."""
    if not is_configured(current_app.config):
        return jsonify({"success": False, "message": "Sophos API not configured"}), 400

    try:
        zones = get_zone_names(current_app.config)
        return jsonify({"success": True, "zones": zones})
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to fetch zones: {e}"}), 500


@migrate_bp.route("/migrate/firewall-rules/sophos-interfaces", methods=["POST"])
def fetch_sophos_interfaces():
    """AJAX: Fetch Sophos interface details (name, zone, IP, aliases) for dropdown."""
    if not is_configured(current_app.config):
        return jsonify({"success": False, "message": "Sophos API not configured"}), 400

    try:
        interfaces = get_interface_details(current_app.config)
        return jsonify({"success": True, "interfaces": interfaces})
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to fetch interfaces: {e}"}), 500
