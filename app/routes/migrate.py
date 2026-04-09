"""Migration routes for pfSense to Sophos XGS."""

import json

from flask import Blueprint, Response, current_app, jsonify, render_template, request
from app.models.database import (
    get_db, get_table_items, get_aliases_by_ids, get_firewall_rules_by_ids,
    get_nat_rules_by_ids, get_nat_destination_lookup, update_migration_status,
    get_zone_mappings, save_zone_mapping, delete_zone_mapping,
    get_network_alias_mappings, save_network_alias_mapping, delete_network_alias_mapping,
    insert_sophos_object, insert_sophos_objects_bulk,
    get_sophos_objects_for_items, delete_sophos_object_rows,
)
from app.services.sophos_client import (
    is_configured, get_client, get_existing_object_names,
    get_existing_fw_rule_names, get_existing_nat_rule_names,
    get_zone_names, get_existing_services_with_details,
    get_interface_details, parallel_fetch_sophos_data,
    SophosConnectionError, _retry_on_rate_limit,
)
from app.services.sophos_cache import cache_invalidate
from app.services.migration_engine import (
    plan_alias_migration, execute_alias_migration,
    plan_to_dict, result_to_dict,
    plan_fwrule_migration, execute_fwrule_migration,
    planned_rule_to_dict, rule_result_to_dict,
    plan_nat_migration, execute_nat_migration,
    planned_nat_to_dict, nat_result_to_dict,
    sanitize_sophos_name,
)
from app.services.activity_logger import log_activity
from app.services.rollback_engine import (
    plan_rollback, plan_to_dict as rollback_plan_to_dict, execute_rollback,
)

migrate_bp = Blueprint("migrate", __name__)

# Map migration_engine sophos_type strings to SDK xml_tag names for sophos_objects tracking
SOPHOS_TYPE_MAP = {
    "ip_host": "IPHost",
    "ip_host_group": "IPHostGroup",
    "fqdn_host": "FQDNHost",
    "service": "Service",
    "service_group": "ServiceGroup",
}

# Map URL category slugs to database table names
CATEGORY_TABLE_MAP = {
    "aliases": "aliases",
    "firewall-rules": "firewall_rules",
    "nat-rules": "nat_rules",
}


def _sse_event(data):
    """Format a dict as an SSE data line."""
    return f"data: {json.dumps(data)}\n\n"


def _build_sophos_ip_lookup(interfaces):
    """Build IP → #InterfaceName lookup from Sophos interface details."""
    lookup = {}
    for iface in interfaces:
        name = iface.get("name", "")
        if not name:
            continue
        ref = f"#{name}"
        ip = iface.get("ip", "")
        if ip:
            lookup[ip] = ref
        for alias in iface.get("alias_ips", []):
            alias_ip = alias.get("ip", "")
            alias_name = alias.get("name", "")
            if alias_ip and alias_name:
                lookup[alias_ip] = f"#{alias_name}"
    return lookup


# --- Alias Migration ---


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

    if duplicates:
        dup_ids = [d["alias_id"] for d in duplicates]
        update_migration_status(db_path, "aliases", dup_ids, "migrated")
        for d in duplicates:
            log_activity(db_path, "check_duplicates", "aliases",
                         d["alias_name"], d["alias_id"],
                         {"sophos_type": d["sophos_type"]}, "success")

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

    log_activity(db_path, "dry_run", "aliases", details={"count": len(plans)})
    return jsonify({"success": True, "plans": plans})


@migrate_bp.route("/migrate/aliases/execute", methods=["POST"])
def execute_aliases():
    """SSE: Execute migration for selected aliases with real-time progress."""
    data = request.get_json()
    if not data or "alias_ids" not in data:
        return jsonify({"success": False, "message": "No alias IDs provided"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    app_config = dict(current_app.config)
    alias_ids = data["alias_ids"]
    fqdn_overrides = data.get("fqdn_overrides", {})

    aliases = get_aliases_by_ids(db_path, alias_ids)
    if not aliases:
        return jsonify({"success": False, "message": "No aliases found"}), 404

    if not is_configured(app_config):
        return jsonify({"success": False, "message": "Sophos API not configured"}), 400

    def generate():
        try:
            yield _sse_event({"type": "phase", "phase": "fetching", "message": "Fetching Sophos data..."})
            client = get_client(app_config)
            existing_names = get_existing_object_names(app_config)

            total = len(aliases)
            migrated = 0
            failed = 0

            for i, alias in enumerate(aliases):
                yield _sse_event({"type": "progress", "index": i, "total": total,
                                  "item_id": alias["id"], "item_name": alias["name"],
                                  "status": "migrating"})

                fqdn_override = fqdn_overrides.get(alias["name"])
                plan = plan_alias_migration(alias, existing_names, fqdn_override=fqdn_override)
                result = execute_alias_migration(client, plan)
                update_migration_status(db_path, "aliases", [alias["id"]], result.status)

                log_activity(db_path, "migrate", "aliases", alias["name"], alias["id"],
                             json.dumps(result_to_dict(result)),
                             "success" if result.success else "fail",
                             result.error if hasattr(result, "error") else None)

                if result.success:
                    migrated += 1
                    cache_invalidate("existing_object_names")
                    # Track created Sophos objects for rollback
                    if plan.action == "create" and plan.objects:
                        _track_alias_objects(db_path, alias["id"], plan)
                else:
                    failed += 1

                yield _sse_event({"type": "progress", "index": i, "total": total,
                                  "item_id": alias["id"], "item_name": alias["name"],
                                  "status": result.status, "success": result.success,
                                  "error": getattr(result, "error", None)})

            yield _sse_event({"type": "done", "total": total,
                              "migrated": migrated, "failed": failed})
        except Exception as e:
            yield _sse_event({"type": "error", "message": str(e)})

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _track_alias_objects(db_path, alias_id, plan):
    """Track Sophos objects created during alias migration for rollback."""
    # Insert member objects first
    member_ids = {}
    parent_id = None

    for obj in plan.objects:
        sophos_type = SOPHOS_TYPE_MAP.get(obj.sophos_type, obj.sophos_type)
        if obj.is_member:
            row_id = insert_sophos_object(
                db_path, "aliases", alias_id, obj.sophos_name,
                sophos_type, is_member=True)
            member_ids[obj.sophos_name] = row_id
        else:
            # This is the parent (group or standalone object)
            parent_id = insert_sophos_object(
                db_path, "aliases", alias_id, obj.sophos_name,
                sophos_type, is_member=False)

    # Link members to parent if both exist
    if parent_id and member_ids:
        conn = get_db(db_path)
        placeholders = ",".join("?" * len(member_ids))
        conn.execute(
            f"UPDATE sophos_objects SET parent_sophos_id = ? WHERE id IN ({placeholders})",
            [parent_id] + list(member_ids.values()),
        )
        conn.commit()
        conn.close()


@migrate_bp.route("/migrate/aliases/skip", methods=["POST"])
def skip_aliases():
    """AJAX: Mark selected aliases as skipped."""
    data = request.get_json()
    if not data or "alias_ids" not in data:
        return jsonify({"success": False, "message": "No alias IDs provided"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    alias_ids = data["alias_ids"]
    updated = update_migration_status(db_path, "aliases", alias_ids, "skipped")

    aliases = get_aliases_by_ids(db_path, alias_ids)
    for alias in aliases:
        log_activity(db_path, "skip", "aliases", alias["name"], alias["id"])

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
    log_activity(db_path, "skip", "system", details={"table": "virtual_ips", "count": updated})
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

    nat_lookup = get_nat_destination_lookup(db_path)
    for rule in rules:
        assoc = rule.get("associated_rule_id") or ""
        rule["nat_destination"] = nat_lookup.get(assoc, "")

    pf_interfaces = sorted({r["interface"] for r in rules if r.get("interface")})

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
        for d in duplicates:
            log_activity(db_path, "check_duplicates", "firewall_rules",
                         d["rule_name"], d["rule_id"], result="success")

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
        sophos_data = parallel_fetch_sophos_data(
            current_app.config, "fw_rule_names", "services", "object_names", "interfaces")
    except SophosConnectionError as e:
        return jsonify({"success": False, "message": str(e)}), 500
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to fetch Sophos data: {e}"}), 500

    existing_rule_names = sophos_data.get("fw_rule_names", set())
    existing_services = sophos_data.get("services", [])
    existing_object_names = sophos_data.get("object_names", {})
    sophos_interfaces = sophos_data.get("interfaces", [])
    sophos_ip_lookup = _build_sophos_ip_lookup(sophos_interfaces)

    zone_maps = {m["pfsense_interface"]: m["sophos_zone"] for m in get_zone_mappings(db_path)}
    network_maps = {m["pfsense_value"]: m["sophos_object"] for m in get_network_alias_mappings(db_path)}

    aliases = get_table_items(db_path, "aliases")
    migrated_alias_names = {a["name"] for a in aliases if a.get("migration_status") == "migrated"}

    dst_zone_override = data.get("dst_zone") or None
    dst_network_override = data.get("dst_network") or None

    nat_lookup = get_nat_destination_lookup(db_path)

    rules.sort(key=lambda r: r["id"])

    plans = []
    prev_name = None
    for rule in rules:
        nat_dest = nat_lookup.get(rule.get("associated_rule_id", ""), "")
        plan = plan_fwrule_migration(
            rule, zone_maps, network_maps,
            existing_rule_names, existing_services,
            migrated_alias_names, existing_object_names,
            prev_rule_name=prev_name,
            dst_zone_override=dst_zone_override,
            dst_network_override=dst_network_override,
            nat_destination=nat_dest,
            sophos_ip_lookup=sophos_ip_lookup,
        )
        plans.append(planned_rule_to_dict(plan))
        if plan.action == "create":
            prev_name = plan.rule_name

    log_activity(db_path, "dry_run", "firewall_rules", details={"count": len(plans)})
    return jsonify({"success": True, "plans": plans})


@migrate_bp.route("/migrate/firewall-rules/execute", methods=["POST"])
def execute_firewall_rules():
    """SSE: Execute migration for selected firewall rules with real-time progress."""
    data = request.get_json()
    if not data or "rule_ids" not in data:
        return jsonify({"success": False, "message": "No rule IDs provided"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    app_config = dict(current_app.config)
    rule_ids = data["rule_ids"]
    dst_zone_override = data.get("dst_zone") or None
    dst_network_override = data.get("dst_network") or None

    rules = get_firewall_rules_by_ids(db_path, rule_ids)
    if not rules:
        return jsonify({"success": False, "message": "No rules found"}), 404

    if not is_configured(app_config):
        return jsonify({"success": False, "message": "Sophos API not configured"}), 400

    # Pre-fetch DB data while still in request context
    zone_maps = {m["pfsense_interface"]: m["sophos_zone"] for m in get_zone_mappings(db_path)}
    network_maps = {m["pfsense_value"]: m["sophos_object"] for m in get_network_alias_mappings(db_path)}
    aliases = get_table_items(db_path, "aliases")
    migrated_alias_names = {a["name"] for a in aliases if a.get("migration_status") == "migrated"}
    nat_lookup = get_nat_destination_lookup(db_path)
    rules.sort(key=lambda r: r["id"])

    def generate():
        try:
            yield _sse_event({"type": "phase", "phase": "fetching", "message": "Fetching Sophos data..."})
            client = get_client(app_config)
            sophos_data = parallel_fetch_sophos_data(
                app_config, "fw_rule_names", "services", "object_names", "interfaces")

            existing_rule_names = sophos_data.get("fw_rule_names", set())
            existing_services = sophos_data.get("services", [])
            existing_object_names = sophos_data.get("object_names", {})
            sophos_interfaces = sophos_data.get("interfaces", [])
            sophos_ip_lookup = _build_sophos_ip_lookup(sophos_interfaces)

            total = len(rules)
            migrated = 0
            failed = 0
            prev_name = None

            for i, rule in enumerate(rules):
                rule_descr = rule.get("descr") or f"rule_{rule['id']}"
                yield _sse_event({"type": "progress", "index": i, "total": total,
                                  "item_id": rule["id"], "item_name": rule_descr,
                                  "status": "migrating"})

                nat_dest = nat_lookup.get(rule.get("associated_rule_id", ""), "")
                plan = plan_fwrule_migration(
                    rule, zone_maps, network_maps,
                    existing_rule_names, existing_services,
                    migrated_alias_names, existing_object_names,
                    prev_rule_name=prev_name,
                    dst_zone_override=dst_zone_override,
                    dst_network_override=dst_network_override,
                    nat_destination=nat_dest,
                    sophos_ip_lookup=sophos_ip_lookup,
                )
                result = execute_fwrule_migration(client, plan)
                update_migration_status(db_path, "firewall_rules", [rule["id"]], result.status)

                log_activity(db_path, "migrate", "firewall_rules", rule_descr, rule["id"],
                             json.dumps(rule_result_to_dict(result)),
                             "success" if result.success else "fail",
                             result.error if hasattr(result, "error") else None)

                if result.success:
                    migrated += 1
                    cache_invalidate("existing_fw_rule_names")
                    if plan.action == "create":
                        prev_name = plan.rule_name
                        insert_sophos_object(
                            db_path, "firewall_rules", rule["id"],
                            result.rule_name, "FirewallRule")
                else:
                    failed += 1

                yield _sse_event({"type": "progress", "index": i, "total": total,
                                  "item_id": rule["id"], "item_name": rule_descr,
                                  "status": result.status, "success": result.success,
                                  "error": getattr(result, "error", None)})

            yield _sse_event({"type": "done", "total": total,
                              "migrated": migrated, "failed": failed})
        except Exception as e:
            yield _sse_event({"type": "error", "message": str(e)})

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@migrate_bp.route("/migrate/firewall-rules/skip", methods=["POST"])
def skip_firewall_rules():
    """AJAX: Mark selected firewall rules as skipped."""
    data = request.get_json()
    if not data or "rule_ids" not in data:
        return jsonify({"success": False, "message": "No rule IDs provided"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    rule_ids = data["rule_ids"]
    updated = update_migration_status(db_path, "firewall_rules", rule_ids, "skipped")

    rules = get_firewall_rules_by_ids(db_path, rule_ids)
    for rule in rules:
        log_activity(db_path, "skip", "firewall_rules",
                     rule.get("descr") or f"rule_{rule['id']}", rule["id"])

    return jsonify({"success": True, "updated": updated})


@migrate_bp.route("/migrate/firewall-rules/reset", methods=["POST"])
def reset_firewall_rules():
    """AJAX: Reset selected firewall rules back to pending status."""
    data = request.get_json()
    if not data or "rule_ids" not in data:
        return jsonify({"success": False, "message": "No rule IDs provided"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    rule_ids = data["rule_ids"]
    updated = update_migration_status(db_path, "firewall_rules", rule_ids, "pending")

    rules = get_firewall_rules_by_ids(db_path, rule_ids)
    for rule in rules:
        log_activity(db_path, "reset", "firewall_rules",
                     rule.get("descr") or f"rule_{rule['id']}", rule["id"])

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
    """SSE: Create missing services on Sophos with real-time progress."""
    data = request.get_json()
    if not data or not data.get("services"):
        return jsonify({"success": False, "message": "No services provided"}), 400

    if not is_configured(current_app.config):
        return jsonify({"success": False, "message": "Sophos API not configured"}), 400

    app_config = dict(current_app.config)
    db_path = current_app.config["DATABASE_PATH"]
    services = data["services"]

    try:
        client = get_client(app_config)
    except SophosConnectionError as e:
        return jsonify({"success": False, "message": str(e)}), 500

    def generate():
        total = len(services)
        created = 0
        failed_count = 0

        for i, svc in enumerate(services):
            name = svc.get("name", "")
            protocol = svc.get("protocol", "TCP")
            port = svc.get("port", "")
            ports = svc.get("ports", None)

            yield _sse_event({"type": "progress", "index": i, "total": total,
                              "item_id": None, "item_name": name, "status": "creating"})

            if not name or (not port and not ports):
                failed_count += 1
                log_activity(db_path, "create_service", "services", name,
                             result="fail", error_message="Missing name or port")
                yield _sse_event({"type": "progress", "index": i, "total": total,
                                  "item_name": name, "status": "failed", "success": False,
                                  "error": "Missing name or port"})
                continue

            try:
                if ports:
                    service_list = [{"dst_port": p, "protocol": protocol} for p in ports]
                else:
                    service_list = [{"dst_port": port, "protocol": protocol}]

                _retry_on_rate_limit(
                    client.create_service,
                    name=name,
                    service_type="TCPorUDP",
                    service_list=service_list,
                )
                created += 1
                cache_invalidate("existing_services_with_details", "existing_object_names")
                log_activity(db_path, "create_service", "services", name, result="success")
                # Track for rollback — linked to the rule if provided
                rule_id = svc.get("rule_id", 0)
                insert_sophos_object(
                    db_path, "firewall_rules", rule_id,
                    name, "Service", is_member=True)
                yield _sse_event({"type": "progress", "index": i, "total": total,
                                  "item_name": name, "status": "created", "success": True})
            except Exception as e:
                failed_count += 1
                log_activity(db_path, "create_service", "services", name,
                             result="fail", error_message=str(e))
                yield _sse_event({"type": "progress", "index": i, "total": total,
                                  "item_name": name, "status": "failed", "success": False,
                                  "error": str(e)})

        yield _sse_event({"type": "done", "total": total, "created": created, "failed": failed_count})

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


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
    """AJAX: Fetch Sophos interface details for dropdown."""
    if not is_configured(current_app.config):
        return jsonify({"success": False, "message": "Sophos API not configured"}), 400

    try:
        interfaces = get_interface_details(current_app.config)
        return jsonify({"success": True, "interfaces": interfaces})
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to fetch interfaces: {e}"}), 500


# --- NAT Rules Migration ---


@migrate_bp.route("/migrate/nat-rules")
def migrate_nat_rules():
    """Render the NAT rules migration page."""
    db_path = current_app.config["DATABASE_PATH"]
    rules = get_table_items(db_path, "nat_rules")
    configured = is_configured(current_app.config)

    pf_interfaces = sorted({r["interface"] for r in rules if r.get("interface")})

    return render_template(
        "migrate_nat.html",
        rules=rules,
        configured=configured,
        pf_interfaces=pf_interfaces,
    )


@migrate_bp.route("/migrate/nat-rules/check-duplicates", methods=["POST"])
def check_nat_duplicates():
    """AJAX: Check which NAT rules already exist on Sophos by name."""
    if not is_configured(current_app.config):
        return jsonify({"success": False, "message": "Sophos API not configured"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    rules = get_table_items(db_path, "nat_rules")
    if not rules:
        return jsonify({"success": True, "duplicates": []})

    try:
        existing_names = get_existing_nat_rule_names(current_app.config)
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to fetch Sophos NAT rules: {e}"}), 500

    existing_lower = {n.lower(): n for n in existing_names}

    duplicates = []
    for rule in rules:
        if rule.get("migration_status") in ("migrated", "skipped"):
            continue
        descr = rule.get("descr") or ""
        name_base = descr if descr else f"pf_nat_{rule['id']}"
        sophos_name = sanitize_sophos_name(name_base)
        if sophos_name and sophos_name.lower() in existing_lower:
            duplicates.append({
                "rule_id": rule["id"],
                "rule_name": sophos_name,
            })

    if duplicates:
        dup_ids = [d["rule_id"] for d in duplicates]
        update_migration_status(db_path, "nat_rules", dup_ids, "migrated")
        for d in duplicates:
            log_activity(db_path, "check_duplicates", "nat_rules",
                         d["rule_name"], d["rule_id"], result="success")

    return jsonify({"success": True, "duplicates": duplicates})


@migrate_bp.route("/migrate/nat-rules/plan", methods=["POST"])
def plan_nat_rules():
    """AJAX: Generate dry-run migration plan for selected NAT rules."""
    data = request.get_json()
    if not data or "rule_ids" not in data:
        return jsonify({"success": False, "message": "No rule IDs provided"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    rule_ids = data["rule_ids"]

    rules = get_nat_rules_by_ids(db_path, rule_ids)
    if not rules:
        return jsonify({"success": False, "message": "No rules found"}), 404

    if not is_configured(current_app.config):
        return jsonify({"success": False, "message": "Sophos API not configured"}), 400

    try:
        sophos_data = parallel_fetch_sophos_data(
            current_app.config, "nat_rule_names", "services", "object_names", "interfaces")
    except SophosConnectionError as e:
        return jsonify({"success": False, "message": str(e)}), 500
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to fetch Sophos data: {e}"}), 500

    existing_nat_names = sophos_data.get("nat_rule_names", set())
    existing_services = sophos_data.get("services", [])
    existing_object_names = sophos_data.get("object_names", {})
    sophos_interfaces = sophos_data.get("interfaces", [])
    sophos_ip_lookup = _build_sophos_ip_lookup(sophos_interfaces)

    aliases = get_table_items(db_path, "aliases")
    migrated_alias_names = {a["name"] for a in aliases if a.get("migration_status") == "migrated"}
    alias_address_lookup = {a["name"]: a.get("address", "") for a in aliases if a.get("address")}

    orig_dest_override = data.get("orig_dest") or None

    rules.sort(key=lambda r: r["id"])

    plans = []
    prev_name = None
    for rule in rules:
        plan = plan_nat_migration(
            rule, existing_nat_names, existing_services,
            existing_object_names, migrated_alias_names,
            sophos_ip_lookup, prev_rule_name=prev_name,
            alias_address_lookup=alias_address_lookup,
            orig_dest_override=orig_dest_override,
        )
        plans.append(planned_nat_to_dict(plan))
        if plan.action == "create":
            prev_name = plan.rule_name

    log_activity(db_path, "dry_run", "nat_rules", details={"count": len(plans)})
    return jsonify({"success": True, "plans": plans})


@migrate_bp.route("/migrate/nat-rules/execute", methods=["POST"])
def execute_nat_rules():
    """SSE: Execute migration for selected NAT rules with real-time progress."""
    data = request.get_json()
    if not data or "rule_ids" not in data:
        return jsonify({"success": False, "message": "No rule IDs provided"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    app_config = dict(current_app.config)
    rule_ids = data["rule_ids"]
    orig_dest_override = data.get("orig_dest") or None

    rules = get_nat_rules_by_ids(db_path, rule_ids)
    if not rules:
        return jsonify({"success": False, "message": "No rules found"}), 404

    if not is_configured(app_config):
        return jsonify({"success": False, "message": "Sophos API not configured"}), 400

    # Pre-fetch DB data while still in request context
    aliases = get_table_items(db_path, "aliases")
    migrated_alias_names = {a["name"] for a in aliases if a.get("migration_status") == "migrated"}
    alias_address_lookup = {a["name"]: a.get("address", "") for a in aliases if a.get("address")}
    rules.sort(key=lambda r: r["id"])

    def generate():
        try:
            yield _sse_event({"type": "phase", "phase": "fetching", "message": "Fetching Sophos data..."})
            client = get_client(app_config)
            sophos_data = parallel_fetch_sophos_data(
                app_config, "nat_rule_names", "services", "object_names", "interfaces")

            existing_nat_names = sophos_data.get("nat_rule_names", set())
            existing_services = sophos_data.get("services", [])
            existing_object_names = sophos_data.get("object_names", {})
            sophos_interfaces = sophos_data.get("interfaces", [])
            sophos_ip_lookup = _build_sophos_ip_lookup(sophos_interfaces)

            total = len(rules)
            migrated = 0
            failed = 0
            prev_name = None

            for i, rule in enumerate(rules):
                rule_descr = rule.get("descr") or f"nat_{rule['id']}"
                yield _sse_event({"type": "progress", "index": i, "total": total,
                                  "item_id": rule["id"], "item_name": rule_descr,
                                  "status": "migrating"})

                plan = plan_nat_migration(
                    rule, existing_nat_names, existing_services,
                    existing_object_names, migrated_alias_names,
                    sophos_ip_lookup, prev_rule_name=prev_name,
                    alias_address_lookup=alias_address_lookup,
                    orig_dest_override=orig_dest_override,
                )
                result = execute_nat_migration(client, plan)
                update_migration_status(db_path, "nat_rules", [rule["id"]], result.status)

                log_activity(db_path, "migrate", "nat_rules", rule_descr, rule["id"],
                             json.dumps(nat_result_to_dict(result)),
                             "success" if result.success else "fail",
                             result.error if hasattr(result, "error") else None)

                if result.success:
                    migrated += 1
                    cache_invalidate("existing_nat_rule_names")
                    if plan.action == "create":
                        prev_name = plan.rule_name
                        insert_sophos_object(
                            db_path, "nat_rules", rule["id"],
                            result.rule_name, "NATRule")
                else:
                    failed += 1

                yield _sse_event({"type": "progress", "index": i, "total": total,
                                  "item_id": rule["id"], "item_name": rule_descr,
                                  "status": result.status, "success": result.success,
                                  "error": getattr(result, "error", None)})

            yield _sse_event({"type": "done", "total": total,
                              "migrated": migrated, "failed": failed})
        except Exception as e:
            yield _sse_event({"type": "error", "message": str(e)})

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@migrate_bp.route("/migrate/nat-rules/skip", methods=["POST"])
def skip_nat_rules():
    """AJAX: Mark selected NAT rules as skipped."""
    data = request.get_json()
    if not data or "rule_ids" not in data:
        return jsonify({"success": False, "message": "No rule IDs provided"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    rule_ids = data["rule_ids"]
    updated = update_migration_status(db_path, "nat_rules", rule_ids, "skipped")

    rules = get_nat_rules_by_ids(db_path, rule_ids)
    for rule in rules:
        log_activity(db_path, "skip", "nat_rules",
                     rule.get("descr") or f"nat_{rule['id']}", rule["id"])

    return jsonify({"success": True, "updated": updated})


@migrate_bp.route("/migrate/nat-rules/reset", methods=["POST"])
def reset_nat_rules():
    """AJAX: Reset selected NAT rules back to pending status."""
    data = request.get_json()
    if not data or "rule_ids" not in data:
        return jsonify({"success": False, "message": "No rule IDs provided"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    rule_ids = data["rule_ids"]
    updated = update_migration_status(db_path, "nat_rules", rule_ids, "pending")

    rules = get_nat_rules_by_ids(db_path, rule_ids)
    for rule in rules:
        log_activity(db_path, "reset", "nat_rules",
                     rule.get("descr") or f"nat_{rule['id']}", rule["id"])

    return jsonify({"success": True, "updated": updated})


@migrate_bp.route("/migrate/nat-rules/create-services", methods=["POST"])
def create_nat_missing_services():
    """SSE: Create missing services on Sophos for NAT rule migration."""
    data = request.get_json()
    if not data or not data.get("services"):
        return jsonify({"success": False, "message": "No services provided"}), 400

    if not is_configured(current_app.config):
        return jsonify({"success": False, "message": "Sophos API not configured"}), 400

    app_config = dict(current_app.config)
    db_path = current_app.config["DATABASE_PATH"]
    services = data["services"]

    try:
        client = get_client(app_config)
    except SophosConnectionError as e:
        return jsonify({"success": False, "message": str(e)}), 500

    def generate():
        total = len(services)
        created = 0
        failed_count = 0

        for i, svc in enumerate(services):
            name = svc.get("name", "")
            protocol = svc.get("protocol", "TCP")
            port = svc.get("port", "")
            ports = svc.get("ports", None)

            yield _sse_event({"type": "progress", "index": i, "total": total,
                              "item_name": name, "status": "creating"})

            if not name or (not port and not ports):
                failed_count += 1
                log_activity(db_path, "create_service", "services", name,
                             result="fail", error_message="Missing name or port")
                yield _sse_event({"type": "progress", "index": i, "total": total,
                                  "item_name": name, "status": "failed", "success": False,
                                  "error": "Missing name or port"})
                continue

            try:
                if ports:
                    service_list = [{"dst_port": p, "protocol": protocol} for p in ports]
                else:
                    service_list = [{"dst_port": port, "protocol": protocol}]

                _retry_on_rate_limit(
                    client.create_service,
                    name=name,
                    service_type="TCPorUDP",
                    service_list=service_list,
                )
                created += 1
                cache_invalidate("existing_services_with_details", "existing_object_names")
                log_activity(db_path, "create_service", "services", name, result="success")
                rule_id = svc.get("rule_id", 0)
                insert_sophos_object(
                    db_path, "nat_rules", rule_id,
                    name, "Service", is_member=True)
                yield _sse_event({"type": "progress", "index": i, "total": total,
                                  "item_name": name, "status": "created", "success": True})
            except Exception as e:
                failed_count += 1
                log_activity(db_path, "create_service", "services", name,
                             result="fail", error_message=str(e))
                yield _sse_event({"type": "progress", "index": i, "total": total,
                                  "item_name": name, "status": "failed", "success": False,
                                  "error": str(e)})

        yield _sse_event({"type": "done", "total": total, "created": created, "failed": failed_count})

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@migrate_bp.route("/migrate/nat-rules/create-hosts", methods=["POST"])
def create_nat_missing_hosts():
    """SSE: Create missing IP host objects on Sophos for NAT rule migration."""
    data = request.get_json()
    if not data or not data.get("hosts"):
        return jsonify({"success": False, "message": "No hosts provided"}), 400

    if not is_configured(current_app.config):
        return jsonify({"success": False, "message": "Sophos API not configured"}), 400

    app_config = dict(current_app.config)
    db_path = current_app.config["DATABASE_PATH"]
    hosts = data["hosts"]

    try:
        client = get_client(app_config)
    except SophosConnectionError as e:
        return jsonify({"success": False, "message": str(e)}), 500

    def generate():
        total = len(hosts)
        created = 0
        failed_count = 0

        for i, host in enumerate(hosts):
            name = host.get("name", "")
            ip = host.get("ip", "")

            yield _sse_event({"type": "progress", "index": i, "total": total,
                              "item_name": name, "status": "creating"})

            if not name or not ip:
                failed_count += 1
                log_activity(db_path, "create_host", "hosts", name,
                             result="fail", error_message="Missing name or IP")
                yield _sse_event({"type": "progress", "index": i, "total": total,
                                  "item_name": name, "status": "failed", "success": False,
                                  "error": "Missing name or IP"})
                continue

            try:
                _retry_on_rate_limit(
                    client.create_ip_host,
                    name=name,
                    ip_address=ip,
                    host_type="IP",
                )
                created += 1
                cache_invalidate("existing_object_names")
                log_activity(db_path, "create_host", "hosts", name,
                             details={"ip": ip}, result="success")
                rule_id = host.get("rule_id", 0)
                insert_sophos_object(
                    db_path, "nat_rules", rule_id,
                    name, "IPHost", is_member=True)
                yield _sse_event({"type": "progress", "index": i, "total": total,
                                  "item_name": name, "status": "created", "success": True})
            except Exception as e:
                failed_count += 1
                log_activity(db_path, "create_host", "hosts", name,
                             result="fail", error_message=str(e))
                yield _sse_event({"type": "progress", "index": i, "total": total,
                                  "item_name": name, "status": "failed", "success": False,
                                  "error": str(e)})

        yield _sse_event({"type": "done", "total": total, "created": created, "failed": failed_count})

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@migrate_bp.route("/migrate/nat-rules/sophos-interfaces", methods=["POST"])
def fetch_nat_sophos_interfaces():
    """AJAX: Fetch Sophos interface details for NAT rule mapping."""
    if not is_configured(current_app.config):
        return jsonify({"success": False, "message": "Sophos API not configured"}), 400

    try:
        interfaces = get_interface_details(current_app.config)
        return jsonify({"success": True, "interfaces": interfaces})
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to fetch interfaces: {e}"}), 500


# --- Rollback routes (generic for all categories) ---


def _get_item_names(db_path, source_table, item_ids):
    """Get display names for items by category."""
    if source_table == "aliases":
        items = get_aliases_by_ids(db_path, item_ids)
        return {item["id"]: item["name"] for item in items}
    elif source_table == "firewall_rules":
        items = get_firewall_rules_by_ids(db_path, item_ids)
        return {item["id"]: item.get("descr") or f"rule_{item['id']}" for item in items}
    elif source_table == "nat_rules":
        items = get_nat_rules_by_ids(db_path, item_ids)
        return {item["id"]: item.get("descr") or f"nat_{item['id']}" for item in items}
    return {}


@migrate_bp.route("/migrate/<category>/rollback/plan", methods=["POST"])
def rollback_plan_route(category):
    """AJAX: Preview what will be deleted during rollback."""
    source_table = CATEGORY_TABLE_MAP.get(category)
    if not source_table:
        return jsonify({"success": False, "message": f"Invalid category: {category}"}), 400

    data = request.get_json()
    if not data or "item_ids" not in data:
        return jsonify({"success": False, "message": "No item IDs provided"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    item_ids = data["item_ids"]
    cascade = data.get("cascade", False)

    item_names = _get_item_names(db_path, source_table, item_ids)
    plans = plan_rollback(db_path, source_table, item_ids, item_names, cascade=cascade)

    return jsonify({
        "success": True,
        "plans": [rollback_plan_to_dict(p) for p in plans],
    })


@migrate_bp.route("/migrate/<category>/rollback/execute", methods=["POST"])
def rollback_execute_route(category):
    """SSE: Execute rollback — delete Sophos objects and reset status to pending."""
    source_table = CATEGORY_TABLE_MAP.get(category)
    if not source_table:
        return jsonify({"success": False, "message": f"Invalid category: {category}"}), 400

    data = request.get_json()
    if not data or "item_ids" not in data:
        return jsonify({"success": False, "message": "No item IDs provided"}), 400

    if not is_configured(current_app.config):
        return jsonify({"success": False, "message": "Sophos API not configured"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    app_config = dict(current_app.config)
    item_ids = data["item_ids"]
    cascade = data.get("cascade", False)

    item_names = _get_item_names(db_path, source_table, item_ids)
    plans = plan_rollback(db_path, source_table, item_ids, item_names, cascade=cascade)

    def generate():
        try:
            yield _sse_event({"type": "phase", "phase": "preparing",
                              "message": "Preparing rollback..."})

            total = len(plans)
            deleted_count = 0
            failed_count = 0

            for i, plan in enumerate(plans):
                item_name = plan.item_name
                source_id = plan.source_id

                yield _sse_event({"type": "progress", "index": i, "total": total,
                                  "item_id": source_id, "item_name": item_name,
                                  "status": "deleting"})

                if not plan.primary_objects and not (cascade and plan.member_objects):
                    # Nothing to delete
                    failed_count += 1
                    warning = plan.warnings[0] if plan.warnings else "No objects to delete"
                    log_activity(db_path, "rollback", source_table, item_name, source_id,
                                 json.dumps({"warnings": plan.warnings}),
                                 "fail", warning)
                    yield _sse_event({"type": "progress", "index": i, "total": total,
                                      "item_id": source_id, "item_name": item_name,
                                      "status": "failed", "success": False,
                                      "error": warning})
                    continue

                # Execute deletion
                obj_deleted = []
                obj_failed = []

                for sophos_name, sophos_type, success, error in execute_rollback(
                        app_config, plan, db_path, cascade=cascade):
                    if success:
                        obj_deleted.append(sophos_name)
                    else:
                        obj_failed.append({"name": sophos_name, "error": error})

                # Determine overall success: at least primary objects deleted
                primary_names = {o["sophos_name"] for o in plan.primary_objects}
                primary_deleted = primary_names.issubset(set(obj_deleted))

                if primary_deleted:
                    update_migration_status(db_path, source_table, [source_id], "pending")
                    deleted_count += 1
                    status = "deleted"
                else:
                    failed_count += 1
                    status = "failed"

                log_activity(
                    db_path, "rollback", source_table, item_name, source_id,
                    json.dumps({"objects_deleted": obj_deleted,
                                "objects_failed": obj_failed,
                                "cascade": cascade}),
                    "success" if primary_deleted else "fail",
                    obj_failed[0]["error"] if obj_failed else None,
                )

                yield _sse_event({"type": "progress", "index": i, "total": total,
                                  "item_id": source_id, "item_name": item_name,
                                  "status": status,
                                  "success": primary_deleted,
                                  "objects_deleted": obj_deleted,
                                  "objects_failed": obj_failed,
                                  "error": obj_failed[0]["error"] if obj_failed and not primary_deleted else None})

            # Invalidate relevant caches
            if source_table == "aliases":
                cache_invalidate("existing_object_names")
            elif source_table == "firewall_rules":
                cache_invalidate("existing_fw_rule_names")
            elif source_table == "nat_rules":
                cache_invalidate("existing_nat_rule_names")

            yield _sse_event({"type": "done", "total": total,
                              "deleted": deleted_count, "failed": failed_count})
        except Exception as e:
            yield _sse_event({"type": "error", "message": str(e)})

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
