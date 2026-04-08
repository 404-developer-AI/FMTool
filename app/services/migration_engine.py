"""Migration engine: maps pfSense aliases to Sophos XGS objects."""

import ipaddress
import logging
import re
from dataclasses import dataclass, field

from app.services.sophos_client import _retry_on_rate_limit

logger = logging.getLogger(__name__)

MAX_SOPHOS_NAME_LENGTH = 60


@dataclass
class PlannedObject:
    sophos_type: str        # ip_host, ip_host_group, fqdn_host, service, service_group
    sophos_name: str
    method: str             # SDK method name
    kwargs: dict
    is_member: bool = False


@dataclass
class MigrationPlan:
    alias_id: int
    alias_name: str
    alias_type: str
    action: str             # create, skip, exists, manual
    reason: str
    objects: list = field(default_factory=list)
    warnings: list = field(default_factory=list)


@dataclass
class MigrationResult:
    alias_id: int
    success: bool
    status: str             # migrated, failed, skipped
    objects_created: list = field(default_factory=list)
    error: str = None


def sanitize_sophos_name(name):
    """Clean a pfSense alias name for Sophos naming rules.

    - Replace spaces with underscores
    - Strip characters not in [a-zA-Z0-9_-]
    - Prefix with pf_ if starts with digit
    - Truncate to 60 characters
    """
    name = name.replace(" ", "_")
    name = re.sub(r"[^a-zA-Z0-9_\-]", "", name)
    if name and name[0].isdigit():
        name = "pf_" + name
    return name[:MAX_SOPHOS_NAME_LENGTH]


def plan_alias_migration(alias_row, existing_names, fqdn_override=None):
    """Generate a migration plan for a single pfSense alias.

    Args:
        alias_row: dict from aliases table
        existing_names: dict of sets from get_existing_object_names()
        fqdn_override: optional FQDN string for url/urltable aliases

    Returns:
        MigrationPlan
    """
    alias_id = alias_row["id"]
    alias_name = alias_row["name"]
    alias_type = alias_row.get("type", "")
    address = alias_row.get("address", "") or ""
    descr = alias_row.get("descr", "") or ""

    plan = MigrationPlan(
        alias_id=alias_id,
        alias_name=alias_name,
        alias_type=alias_type,
        action="create",
        reason="",
    )

    sophos_name = sanitize_sophos_name(alias_name)
    if not sophos_name:
        plan.action = "skip"
        plan.reason = "Alias name is empty after sanitization"
        return plan

    if not address and alias_type not in ("url", "urltable"):
        plan.action = "skip"
        plan.reason = "No address defined"
        return plan

    # MAC aliases: not supported
    if alias_type == "mac":
        plan.action = "skip"
        plan.reason = "MAC aliases are not supported on Sophos XGS"
        return plan

    # URL/urltable aliases: manual handling
    if alias_type in ("url", "urltable"):
        if fqdn_override:
            plan.action = "create"
            plan.reason = f"Manual FQDN mapping: {fqdn_override}"
            plan.objects.append(PlannedObject(
                sophos_type="fqdn_host",
                sophos_name=sophos_name,
                method="create_fqdn_host",
                kwargs={"name": sophos_name, "fqdn": fqdn_override, "description": descr},
            ))
            _check_duplicate(plan, existing_names, "fqdn_hosts", sophos_name)
            return plan
        else:
            plan.action = "manual"
            plan.reason = "URL alias — enter an FQDN to create, or skip"
            return plan

    # Parse addresses
    addresses = _parse_addresses(address)

    # Host aliases
    if alias_type == "host":
        _plan_host_alias(plan, sophos_name, addresses, descr, existing_names)
    elif alias_type == "network":
        _plan_network_alias(plan, sophos_name, addresses, descr, existing_names)
    elif alias_type == "port":
        _plan_port_alias(plan, sophos_name, addresses, descr, existing_names)
    else:
        plan.action = "skip"
        plan.reason = f"Unknown alias type: {alias_type}"

    return plan


def _plan_host_alias(plan, sophos_name, addresses, descr, existing_names):
    """Plan migration for a host-type alias."""
    ips = []
    fqdns = []
    nested = []

    for addr in addresses:
        if _is_ip_address(addr):
            ips.append(addr)
        elif _is_cidr(addr):
            # Host alias containing a network — treat as IP host with network type
            ips.append(addr)
        elif _looks_like_fqdn(addr):
            fqdns.append(addr)
        else:
            nested.append(addr)

    if nested:
        plan.warnings.append(
            f"Contains references to other aliases: {', '.join(nested)}. "
            "Migrate those aliases first."
        )

    total_items = len(ips) + len(fqdns)

    if total_items == 0 and not nested:
        plan.action = "skip"
        plan.reason = "No valid addresses found"
        return

    if total_items == 1 and not nested:
        # Single address — create one object
        if ips:
            addr = ips[0]
            if _is_cidr(addr):
                ip, bits = addr.split("/")
                mask = _cidr_to_mask(int(bits))
                plan.objects.append(PlannedObject(
                    sophos_type="ip_host",
                    sophos_name=sophos_name,
                    method="create_ip_host",
                    kwargs={"name": sophos_name, "ip_address": ip, "mask": mask, "host_type": "Network"},
                ))
                _check_duplicate(plan, existing_names, "ip_hosts", sophos_name)
            else:
                plan.objects.append(PlannedObject(
                    sophos_type="ip_host",
                    sophos_name=sophos_name,
                    method="create_ip_host",
                    kwargs={"name": sophos_name, "ip_address": addr, "host_type": "IP"},
                ))
                _check_duplicate(plan, existing_names, "ip_hosts", sophos_name)
        else:
            plan.objects.append(PlannedObject(
                sophos_type="fqdn_host",
                sophos_name=sophos_name,
                method="create_fqdn_host",
                kwargs={"name": sophos_name, "fqdn": fqdns[0], "description": descr},
            ))
            _check_duplicate(plan, existing_names, "fqdn_hosts", sophos_name)
        plan.reason = "Single host object"
        return

    # Multiple addresses — create individual objects + group
    member_names = []

    for i, addr in enumerate(ips, 1):
        member_name = _member_name(sophos_name, i, len(ips) + len(fqdns))
        if _is_cidr(addr):
            ip, bits = addr.split("/")
            mask = _cidr_to_mask(int(bits))
            plan.objects.append(PlannedObject(
                sophos_type="ip_host",
                sophos_name=member_name,
                method="create_ip_host",
                kwargs={"name": member_name, "ip_address": ip, "mask": mask, "host_type": "Network"},
                is_member=True,
            ))
        else:
            plan.objects.append(PlannedObject(
                sophos_type="ip_host",
                sophos_name=member_name,
                method="create_ip_host",
                kwargs={"name": member_name, "ip_address": addr, "host_type": "IP"},
                is_member=True,
            ))
        member_names.append(member_name)

    for i, fqdn in enumerate(fqdns, len(ips) + 1):
        member_name = _member_name(sophos_name, i, len(ips) + len(fqdns))
        plan.objects.append(PlannedObject(
            sophos_type="fqdn_host",
            sophos_name=member_name,
            method="create_fqdn_host",
            kwargs={"name": member_name, "fqdn": fqdn, "description": descr},
            is_member=True,
        ))
        member_names.append(member_name)

    # Create the group
    plan.objects.append(PlannedObject(
        sophos_type="ip_host_group",
        sophos_name=sophos_name,
        method="create_ip_hostgroup",
        kwargs={"name": sophos_name, "host_list": member_names, "description": descr},
    ))
    _check_duplicate(plan, existing_names, "ip_host_groups", sophos_name)
    plan.reason = f"Host group with {len(member_names)} members"


def _plan_network_alias(plan, sophos_name, addresses, descr, existing_names):
    """Plan migration for a network-type alias."""
    if len(addresses) == 1:
        addr = addresses[0]
        if "/" in addr:
            ip, bits = addr.split("/")
            mask = _cidr_to_mask(int(bits))
        else:
            ip = addr
            mask = "255.255.255.255"
            plan.warnings.append(f"Network alias without CIDR notation, using /32: {addr}")

        plan.objects.append(PlannedObject(
            sophos_type="ip_host",
            sophos_name=sophos_name,
            method="create_ip_host",
            kwargs={"name": sophos_name, "ip_address": ip, "mask": mask, "host_type": "Network"},
        ))
        _check_duplicate(plan, existing_names, "ip_hosts", sophos_name)
        plan.reason = "Single network object"
        return

    # Multiple networks — individual hosts + group
    member_names = []
    for i, addr in enumerate(addresses, 1):
        member_name = _member_name(sophos_name, i, len(addresses))
        if "/" in addr:
            ip, bits = addr.split("/")
            mask = _cidr_to_mask(int(bits))
        else:
            ip = addr
            mask = "255.255.255.255"
            plan.warnings.append(f"Network without CIDR notation, using /32: {addr}")

        plan.objects.append(PlannedObject(
            sophos_type="ip_host",
            sophos_name=member_name,
            method="create_ip_host",
            kwargs={"name": member_name, "ip_address": ip, "mask": mask, "host_type": "Network"},
            is_member=True,
        ))
        member_names.append(member_name)

    plan.objects.append(PlannedObject(
        sophos_type="ip_host_group",
        sophos_name=sophos_name,
        method="create_ip_hostgroup",
        kwargs={"name": sophos_name, "host_list": member_names, "description": descr},
    ))
    _check_duplicate(plan, existing_names, "ip_host_groups", sophos_name)
    plan.reason = f"Network group with {len(member_names)} members"


def _plan_port_alias(plan, sophos_name, addresses, descr, existing_names):
    """Plan migration for a port-type alias."""
    if len(addresses) == 1:
        port = addresses[0]
        plan.objects.append(PlannedObject(
            sophos_type="service",
            sophos_name=sophos_name,
            method="create_service",
            kwargs={
                "name": sophos_name,
                "service_type": "TCPorUDP",
                "service_list": [{"dst_port": port, "protocol": "TCP"}],
            },
        ))
        _check_duplicate(plan, existing_names, "services", sophos_name)
        plan.reason = "Single service"
        plan.warnings.append(
            "Port alias defaults to TCP protocol. If UDP is also needed, "
            "create it manually on Sophos."
        )
        return

    # Multiple ports — individual services + group
    member_names = []
    for i, port in enumerate(addresses, 1):
        member_name = _member_name(sophos_name, i, len(addresses))
        plan.objects.append(PlannedObject(
            sophos_type="service",
            sophos_name=member_name,
            method="create_service",
            kwargs={
                "name": member_name,
                "service_type": "TCPorUDP",
                "service_list": [{"dst_port": port, "protocol": "TCP"}],
            },
            is_member=True,
        ))
        member_names.append(member_name)

    plan.objects.append(PlannedObject(
        sophos_type="service_group",
        sophos_name=sophos_name,
        method="create_service_group",
        kwargs={"name": sophos_name, "service_list": member_names, "description": descr},
    ))
    _check_duplicate(plan, existing_names, "service_groups", sophos_name)
    plan.reason = f"Service group with {len(member_names)} members"
    plan.warnings.append(
        "Port aliases default to TCP protocol. If UDP is also needed, "
        "create the services manually on Sophos."
    )


def execute_alias_migration(client, plan):
    """Execute a migration plan by calling Sophos SDK methods.

    Args:
        client: SophosFirewall SDK client
        plan: MigrationPlan with action="create"

    Returns:
        MigrationResult
    """
    if plan.action != "create":
        return MigrationResult(
            alias_id=plan.alias_id,
            success=plan.action == "exists",
            status="migrated" if plan.action == "exists" else "skipped",
            error=None,
        )

    created = []
    try:
        for obj in plan.objects:
            method = getattr(client, obj.method)
            _retry_on_rate_limit(method, **obj.kwargs)
            created.append(obj.sophos_name)
            logger.info("Created %s: %s", obj.sophos_type, obj.sophos_name)

        return MigrationResult(
            alias_id=plan.alias_id,
            success=True,
            status="migrated",
            objects_created=created,
        )
    except Exception as e:
        logger.error("Migration failed for alias %s: %s", plan.alias_name, e)
        error_msg = str(e)
        if created:
            error_msg = f"Partial failure — created {', '.join(created)} before error: {e}"
        return MigrationResult(
            alias_id=plan.alias_id,
            success=False,
            status="failed",
            objects_created=created,
            error=error_msg,
        )


def plan_to_dict(plan):
    """Serialize a MigrationPlan to a JSON-safe dict."""
    return {
        "alias_id": plan.alias_id,
        "alias_name": plan.alias_name,
        "alias_type": plan.alias_type,
        "action": plan.action,
        "reason": plan.reason,
        "warnings": plan.warnings,
        "objects": [
            {
                "sophos_type": obj.sophos_type,
                "sophos_name": obj.sophos_name,
                "method": obj.method,
                "is_member": obj.is_member,
            }
            for obj in plan.objects
        ],
    }


def result_to_dict(result):
    """Serialize a MigrationResult to a JSON-safe dict."""
    return {
        "alias_id": result.alias_id,
        "success": result.success,
        "status": result.status,
        "objects_created": result.objects_created,
        "error": result.error,
    }


# --- Helpers ---

def _parse_addresses(address_str):
    """Split comma-separated address string, trim whitespace, filter empty."""
    if not address_str:
        return []
    return [a.strip() for a in address_str.split(" ") if a.strip()]


def _is_ip_address(value):
    """Check if value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_cidr(value):
    """Check if value is a valid CIDR notation (e.g. 10.0.0.0/24)."""
    try:
        ipaddress.ip_network(value, strict=False)
        return "/" in value
    except ValueError:
        return False


def _looks_like_fqdn(value):
    """Check if value looks like a domain name."""
    return bool(re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$", value))


def _cidr_to_mask(bits):
    """Convert CIDR prefix length to dotted decimal netmask."""
    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    return f"{(mask >> 24) & 0xFF}.{(mask >> 16) & 0xFF}.{(mask >> 8) & 0xFF}.{mask & 0xFF}"


def _member_name(base_name, index, total):
    """Generate a member name for multi-address aliases."""
    if total <= 1:
        return base_name
    return f"{base_name}_{index}"[:MAX_SOPHOS_NAME_LENGTH]


# --- Firewall Rule Migration ---


@dataclass
class PlannedRule:
    rule_id: int
    rule_name: str
    pf_description: str
    action: str             # create, skip, exists
    reason: str
    rule_params: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)


@dataclass
class RuleMigrationResult:
    rule_id: int
    success: bool
    status: str             # migrated, failed, skipped
    rule_name: str = None
    error: str = None


def plan_fwrule_migration(rule_row, zone_mappings, network_mappings,
                          existing_rule_names, existing_services,
                          migrated_alias_names, existing_object_names,
                          prev_rule_name=None, dst_zone_override=None,
                          dst_network_override=None, nat_destination=None,
                          sophos_ip_lookup=None):
    """Generate a migration plan for a single pfSense firewall rule.

    Args:
        rule_row: dict from firewall_rules table
        zone_mappings: dict {pfsense_interface: sophos_zone}
        network_mappings: dict {pfsense_value: sophos_object}
        existing_rule_names: set of existing Sophos FW rule names
        existing_services: list of service dicts with details
        migrated_alias_names: set of alias names migrated to Sophos
        existing_object_names: dict of sets from get_existing_object_names()
        prev_rule_name: Sophos name of previously planned rule (for ordering)
        dst_zone_override: optional Sophos zone name for destination (bulk override)
        dst_network_override: optional Sophos object name for destination network (bulk override)
        nat_destination: optional NAT rule destination_value (public IP for port forwards)
        sophos_ip_lookup: optional dict {ip: "#InterfaceName"} for matching raw IPs to Sophos interfaces

    Returns:
        PlannedRule
    """
    rule_id = rule_row["id"]
    descr = rule_row.get("descr") or ""
    tracker = rule_row.get("tracker") or str(rule_id)

    plan = PlannedRule(
        rule_id=rule_id,
        rule_name="",
        pf_description=descr,
        action="create",
        reason="",
    )

    # NAT-linked rules: migrate the firewall rule, ignore the NAT link
    assoc = rule_row.get("associated_rule_id") or ""
    if assoc:
        plan.warnings.append({"level": "orange", "text": "NAT-linked rule — the associated NAT rule will be migrated separately in v0.7"})

    # Generate Sophos name
    name_base = descr if descr else f"pf_rule_{tracker}"
    sophos_name = sanitize_sophos_name(name_base)
    if not sophos_name:
        sophos_name = f"pf_rule_{rule_id}"
    plan.rule_name = sophos_name

    # Check duplicate
    existing_lower = {n.lower() for n in existing_rule_names}
    if sophos_name.lower() in existing_lower:
        plan.action = "exists"
        plan.reason = f"Rule '{sophos_name}' already exists on Sophos"
        return plan

    # Resolve source zone
    interface = rule_row.get("interface") or ""
    src_zone = zone_mappings.get(interface)
    if not src_zone:
        plan.action = "skip"
        plan.reason = f"Unmapped interface: '{interface}'. Configure zone mapping first."
        plan.warnings.append({"level": "red", "text": f"pfSense interface '{interface}' has no zone mapping"})
        return plan

    # Destination zone: use override if provided, else default to Any
    dst_zone = dst_zone_override or "Any"
    if not dst_zone_override:
        plan.warnings.append({"level": "orange", "text": "Destination zone set to 'Any' — select a destination zone or verify on Sophos after migration"})

    # Resolve source network
    src_networks, src_warnings = _resolve_network(
        rule_row.get("source_type", ""),
        rule_row.get("source_value", ""),
        rule_row.get("source_not", 0),
        network_mappings, migrated_alias_names, existing_object_names,
        sophos_ip_lookup=sophos_ip_lookup,
    )
    plan.warnings.extend(src_warnings)

    # Resolve destination network: priority is UI override > NAT destination > rule's own destination
    if dst_network_override:
        dst_networks = [dst_network_override]
        dst_warnings = []
    elif nat_destination:
        # NAT-linked rule: use NAT dest address (public IP) as dst_network
        dst_networks, dst_warnings = _resolve_network(
            "address", nat_destination, 0,
            network_mappings, migrated_alias_names, existing_object_names,
            sophos_ip_lookup=sophos_ip_lookup,
        )
        # Check if IP was matched to a Sophos interface (green) or left as raw (red)
        matched_iface = any(
            isinstance(w, dict) and w.get("level") == "green" and "Matched IP" in w.get("text", "")
            for w in dst_warnings
        )
        if matched_iface:
            # Merge NAT dest + matched interface into one green warning
            iface_warning = next(w for w in dst_warnings if isinstance(w, dict) and "Matched IP" in w.get("text", ""))
            dst_warnings = [w for w in dst_warnings if w is not iface_warning]
            plan.warnings.append({"level": "green", "text": f"NAT destination '{nat_destination}' → {dst_networks[0]} (port forward public IP)"})
        else:
            plan.warnings.append(
                {"level": "orange", "text": f"Using NAT destination '{nat_destination}' as Dst Network (port forward public IP)"}
            )
    else:
        dst_networks, dst_warnings = _resolve_network(
            rule_row.get("destination_type", ""),
            rule_row.get("destination_value", ""),
            rule_row.get("destination_not", 0),
            network_mappings, migrated_alias_names, existing_object_names,
            sophos_ip_lookup=sophos_ip_lookup,
        )
    plan.warnings.extend(dst_warnings)

    # Resolve service: dst_port should map to a Sophos service
    protocol = rule_row.get("protocol") or ""
    dst_port = rule_row.get("destination_port") or ""
    missing_service_info = None
    service_list = _resolve_service(protocol, dst_port, existing_services, migrated_alias_names)
    if service_list is None:
        # Build proposed service names for auto-creation
        proposed = _propose_services(protocol, dst_port)
        plan.warnings.append({"level": "red", "text":
            f"No matching Sophos service for {protocol}/{dst_port}. "
            "Create the service on Sophos first, then retry."
        })
        missing_service_info = {
            "protocol": protocol,
            "port": dst_port,
            "proposed": proposed,
        }
        service_list = []

    # Check for schedule
    raw_xml = rule_row.get("raw_xml") or ""
    if "<sched>" in raw_xml:
        plan.warnings.append({"level": "orange", "text": "Rule has a schedule in pfSense. Schedules are not migrated — configure manually on Sophos."})

    # Map action
    pf_type = rule_row.get("type") or "pass"
    sophos_action = "Accept" if pf_type == "pass" else "Drop"

    # Map status
    disabled = rule_row.get("disabled", 0)
    sophos_status = "Disable" if disabled else "Enable"

    # Map logging
    log_enabled = rule_row.get("log", 0)
    sophos_log = "Enable" if log_enabled else "Disable"

    # Build rule_params (Position/After must be capitalized per SDK template)
    rule_params = {
        "rulename": sophos_name,
        "status": sophos_status,
        "position": "After" if prev_rule_name else "Bottom",
        "action": sophos_action,
        "description": descr[:200],
        "log": sophos_log,
        "src_zones": [src_zone],
        "dst_zones": [dst_zone],
        "src_networks": src_networks,
        "dst_networks": dst_networks,
        "service_list": service_list,
    }
    if prev_rule_name:
        rule_params["after_rulename"] = prev_rule_name
    if missing_service_info:
        rule_params["_missing_service"] = missing_service_info

    plan.rule_params = rule_params
    plan.reason = f"Create rule: {sophos_action} from {src_zone} to {dst_zone}"

    if disabled:
        plan.warnings.append({"level": "green", "text": "Rule is disabled in pfSense — will be created as disabled on Sophos"})

    return plan


def execute_fwrule_migration(client, planned_rule):
    """Execute a firewall rule migration plan.

    Args:
        client: SophosFirewall SDK client
        planned_rule: PlannedRule with action="create"

    Returns:
        RuleMigrationResult
    """
    if planned_rule.action != "create":
        return RuleMigrationResult(
            rule_id=planned_rule.rule_id,
            success=planned_rule.action == "exists",
            status="migrated" if planned_rule.action == "exists" else "skipped",
            rule_name=planned_rule.rule_name,
        )

    try:
        _retry_on_rate_limit(client.create_rule, planned_rule.rule_params)
        logger.info("Created firewall rule: %s", planned_rule.rule_name)
        return RuleMigrationResult(
            rule_id=planned_rule.rule_id,
            success=True,
            status="migrated",
            rule_name=planned_rule.rule_name,
        )
    except Exception as e:
        logger.error("Failed to create rule %s: %s", planned_rule.rule_name, e)
        return RuleMigrationResult(
            rule_id=planned_rule.rule_id,
            success=False,
            status="failed",
            rule_name=planned_rule.rule_name,
            error=str(e),
        )


def planned_rule_to_dict(plan):
    """Serialize a PlannedRule to a JSON-safe dict."""
    return {
        "rule_id": plan.rule_id,
        "rule_name": plan.rule_name,
        "pf_description": plan.pf_description,
        "action": plan.action,
        "reason": plan.reason,
        "rule_params": plan.rule_params,
        "warnings": plan.warnings,
    }


def rule_result_to_dict(result):
    """Serialize a RuleMigrationResult to a JSON-safe dict."""
    return {
        "rule_id": result.rule_id,
        "success": result.success,
        "status": result.status,
        "rule_name": result.rule_name,
        "error": result.error,
    }


def _resolve_network(type_field, value_field, not_field,
                     network_mappings, migrated_alias_names, existing_object_names,
                     sophos_ip_lookup=None):
    """Resolve a pfSense source/destination reference to Sophos object names.

    Args:
        sophos_ip_lookup: optional dict {ip_address: "#InterfaceName"} for matching raw IPs

    Returns:
        (list of network names, list of warning strings)
    """
    warnings = []

    if not_field:
        warnings.append({"level": "orange", "text":
            f"Negation ('not') on '{value_field}' is not directly supported on Sophos. "
            "Verify rule logic after migration."
        })

    if type_field == "any" or not type_field:
        return ["Any"], warnings

    value = value_field or ""

    if type_field == "network":
        # pfSense network refs: wanip, lanip, (self), opt1ip, etc.
        mapped = network_mappings.get(value)
        if mapped:
            return [mapped], warnings
        warnings.append({"level": "red", "text": f"Unmapped network reference: '{value}'. Configure in network alias mappings."})
        return [value], warnings

    if type_field == "address":
        # Check if it's a migrated alias
        sophos_name = sanitize_sophos_name(value)
        if sophos_name.lower() in {n.lower() for n in migrated_alias_names}:
            return [sophos_name], warnings

        # Check if it exists as a Sophos object
        all_names = set()
        for names_set in existing_object_names.values():
            all_names.update(n.lower() for n in names_set)
        if sophos_name.lower() in all_names:
            return [sophos_name], warnings

        # Check if it's a raw IP address — match against Sophos interface IPs
        if _is_ip_address(value) or _is_cidr(value):
            if sophos_ip_lookup and value in sophos_ip_lookup:
                iface_name = sophos_ip_lookup[value]
                warnings.append({"level": "green", "text": f"Matched IP '{value}' to Sophos interface '{iface_name}'"})
                return [iface_name], warnings
            warnings.append({"level": "red", "text": f"Raw IP '{value}' used — create an IP Host object on Sophos or use an existing one"})
            return [value], warnings

        warnings.append({"level": "red", "text": f"Unknown reference: '{value}'. Migrate the alias first or configure a mapping."})
        return [sophos_name], warnings

    return ["Any"], warnings


def _resolve_service(protocol, dst_port, existing_services, migrated_alias_names):
    """Match protocol+port against existing Sophos services.

    Returns:
        list of service names, or None if no match found
    """
    if not protocol:
        return []

    protocol_upper = protocol.upper()

    # ICMP special case
    if protocol_upper == "ICMP":
        return ["ICMP"]
    if protocol_upper == "ICMPV6":
        return ["ICMPv6"]

    if not dst_port:
        # Protocol-only rule (no port)
        return []

    # Try to match the full port spec against existing Sophos services
    match = _match_sophos_service(protocol_upper, dst_port, existing_services)
    if match:
        return [match]

    # Check if a migrated alias-service matches by name
    sophos_name = sanitize_sophos_name(dst_port)
    if sophos_name and sophos_name.lower() in {n.lower() for n in migrated_alias_names}:
        return [sophos_name]

    # For port ranges: first try the new range service name
    if "-" in dst_port:
        range_name = sanitize_sophos_name(f"pf_range_{protocol_upper}_{dst_port}")
        all_existing = {s["name"].lower(): s["name"] for s in existing_services}
        if range_name.lower() in all_existing:
            return [all_existing[range_name.lower()]]

        # Fallback: check if old-style individual port services exist
        proposed = _propose_services(protocol, dst_port)
        matched = []
        for port in proposed[0].get("ports", [proposed[0]["port"]]):
            old_name = sanitize_sophos_name(f"pf_svc_{protocol_upper}_{port}")
            if old_name.lower() in all_existing:
                matched.append(all_existing[old_name.lower()])
                continue
            port_match = _match_sophos_service(protocol_upper, port, existing_services)
            if port_match:
                matched.append(port_match)
                continue
        if matched and len(matched) == len(proposed[0].get("ports", [proposed[0]["port"]])):
            return matched

    return None


def _match_sophos_service(protocol, port, existing_services):
    """Find an existing Sophos service matching protocol+port.

    Args:
        protocol: e.g. "TCP", "UDP"
        port: e.g. "80", "443", "10001-20000"

    Returns:
        Service name string, or None
    """
    # Normalize port format: pfSense uses ":" for ranges, Sophos uses ":"
    port_normalized = port.replace("-", ":")

    for svc in existing_services:
        for detail in svc.get("details", []):
            svc_proto = (detail.get("protocol") or "").upper()
            svc_port = (detail.get("dst_port") or "").replace("-", ":")

            # Match protocol (TCP/UDP match TCPorUDP too)
            proto_match = (
                svc_proto == protocol or
                svc_proto == "TCPORUDP" or
                (svc_proto in ("TCP", "UDP") and protocol in ("TCP", "UDP", "TCPORUDP"))
            )
            if proto_match and svc_port == port_normalized:
                return svc["name"]
    return None


def _propose_services(protocol, port_str):
    """Generate proposed Sophos service definitions for a port specification.

    For port ranges like '25021-25022', creates ONE service with multiple port entries.
    For single ports, creates one service with one port entry.
    Returns list of dicts with 'name', 'protocol', 'port', and optionally 'ports' (list).
    """
    if not protocol or not port_str:
        return []

    proto_upper = protocol.upper()
    if proto_upper not in ("TCP", "UDP"):
        proto_upper = "TCP"

    if "-" in port_str:
        # Port range → single service with multiple ServiceDetail entries
        parts = port_str.split("-")
        try:
            start = int(parts[0])
            end = int(parts[1])
            ports = [str(p) for p in range(start, end + 1)]
        except (ValueError, IndexError):
            ports = [port_str]
        name = sanitize_sophos_name(f"pf_range_{proto_upper}_{port_str}")
        return [{
            "name": name,
            "protocol": proto_upper,
            "port": port_str,
            "ports": ports,
        }]
    else:
        # Single port → single service, single entry
        name = sanitize_sophos_name(f"pf_svc_{proto_upper}_{port_str}")
        return [{
            "name": name,
            "protocol": proto_upper,
            "port": port_str,
        }]


def _check_duplicate(plan, existing_names, sophos_type, sophos_name):
    """Check if the main object name already exists on Sophos."""
    existing = existing_names.get(sophos_type, set())
    # Case-insensitive comparison
    existing_lower = {n.lower() for n in existing}
    if sophos_name.lower() in existing_lower:
        plan.action = "exists"
        plan.reason = f"Object '{sophos_name}' already exists on Sophos as {sophos_type}"


# --- NAT Rule Migration (DNAT / Port Forward) ---


@dataclass
class PlannedNatRule:
    rule_id: int
    rule_name: str
    pf_description: str
    action: str             # create, skip, exists
    reason: str
    nat_xml: str = ""
    rule_params: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)


@dataclass
class NatRuleMigrationResult:
    rule_id: int
    success: bool
    status: str             # migrated, failed, skipped
    rule_name: str = None
    error: str = None


def plan_nat_migration(rule_row, existing_nat_names, existing_services,
                       existing_object_names, migrated_alias_names,
                       sophos_ip_lookup, prev_rule_name=None,
                       alias_address_lookup=None, orig_dest_override=None):
    """Generate a migration plan for a single pfSense NAT (port forward) rule.

    Args:
        rule_row: dict from nat_rules table
        existing_nat_names: set of existing Sophos NAT rule names
        existing_services: list of service dicts with details
        existing_object_names: dict of sets from get_existing_object_names()
        migrated_alias_names: set of alias names migrated to Sophos
        sophos_ip_lookup: dict {ip: "#InterfaceName"} for matching IPs
        prev_rule_name: Sophos name of previously planned NAT rule (for ordering)
        alias_address_lookup: optional dict {alias_name: address_string} for resolving alias IPs
        orig_dest_override: optional Sophos interface reference (e.g. "#Port1:2") to override original destination

    Returns:
        PlannedNatRule
    """
    rule_id = rule_row["id"]
    descr = rule_row.get("descr") or ""
    protocol = rule_row.get("protocol") or ""

    plan = PlannedNatRule(
        rule_id=rule_id,
        rule_name="",
        pf_description=descr,
        action="create",
        reason="",
    )

    # Generate Sophos name
    name_base = descr if descr else f"pf_nat_{rule_id}"
    sophos_name = sanitize_sophos_name(name_base)
    if not sophos_name:
        sophos_name = f"pf_nat_{rule_id}"
    plan.rule_name = sophos_name

    # Check duplicate
    existing_lower = {n.lower() for n in existing_nat_names}
    if sophos_name.lower() in existing_lower:
        plan.action = "exists"
        plan.reason = f"NAT rule '{sophos_name}' already exists on Sophos"
        return plan

    # Status
    disabled = rule_row.get("disabled", 0)
    sophos_status = "Disable" if disabled else "Enable"
    if disabled:
        plan.warnings.append({"level": "green", "text": "Rule is disabled in pfSense — will be created as disabled on Sophos"})

    # IPFamily
    ipprotocol = rule_row.get("ipprotocol") or "inet"
    ip_family = "IPv6" if ipprotocol == "inet6" else "IPv4"

    # Position
    position = "After" if prev_rule_name else "Top"

    # --- Original Destination (WAN port / public IP) ---
    dest_value = rule_row.get("destination_value") or ""
    orig_dest_network = None
    missing_host_info_orig = None

    if orig_dest_override:
        orig_dest_network = orig_dest_override
        plan.warnings.append({"level": "green", "text": f"Original destination overridden to '{orig_dest_override}'"})
    elif dest_value and sophos_ip_lookup and dest_value in sophos_ip_lookup:
        orig_dest_network = sophos_ip_lookup[dest_value]
        plan.warnings.append({"level": "green", "text": f"Original destination '{dest_value}' → {orig_dest_network} (Sophos interface)"})
    elif dest_value and (_is_ip_address(dest_value) or _is_cidr(dest_value)):
        # Check if a host object exists for this IP
        all_names = set()
        for names_set in existing_object_names.values():
            all_names.update(n.lower() for n in names_set)
        host_name = sanitize_sophos_name(f"pf_nat_dest_{dest_value.replace('.', '_')}")
        if host_name.lower() in all_names:
            orig_dest_network = host_name
            plan.warnings.append({"level": "green", "text": f"Original destination '{dest_value}' → existing host '{host_name}'"})
        else:
            orig_dest_network = dest_value
            plan.warnings.append({"level": "red", "text":
                f"Original destination '{dest_value}' not matched to Sophos interface. "
                "Map to an interface or create a host object."
            })
            missing_host_info_orig = {
                "name": host_name,
                "ip": dest_value,
                "type": "original_destination",
            }
    elif dest_value:
        # Could be an alias name
        sophos_ref = sanitize_sophos_name(dest_value)
        if sophos_ref.lower() in {n.lower() for n in migrated_alias_names}:
            orig_dest_network = sophos_ref
        else:
            all_names = set()
            for names_set in existing_object_names.values():
                all_names.update(n.lower() for n in names_set)
            if sophos_ref.lower() in all_names:
                orig_dest_network = sophos_ref
            else:
                orig_dest_network = dest_value
                plan.warnings.append({"level": "red", "text": f"Unknown original destination reference: '{dest_value}'"})
    else:
        plan.action = "skip"
        plan.reason = "No destination value defined"
        plan.warnings.append({"level": "red", "text": "NAT rule has no destination — cannot create DNAT rule"})
        return plan

    # --- Translated Destination (target / internal server) ---
    target = rule_row.get("target") or ""
    translated_dest = None
    missing_host_info_target = None

    if not target:
        plan.action = "skip"
        plan.reason = "No target (translated destination) defined"
        plan.warnings.append({"level": "red", "text": "NAT rule has no target — cannot create DNAT rule"})
        return plan

    if _is_ip_address(target):
        # Check if host object exists
        target_host_name = sanitize_sophos_name(f"pf_nat_target_{target.replace('.', '_')}")
        all_names = set()
        for names_set in existing_object_names.values():
            all_names.update(n.lower() for n in names_set)
        if target_host_name.lower() in all_names:
            translated_dest = target_host_name
            plan.warnings.append({"level": "green", "text": f"Target '{target}' → existing host '{target_host_name}'"})
        else:
            # Check if any existing host matches this name pattern
            alt_name = sanitize_sophos_name(target.replace(".", "_"))
            if alt_name.lower() in all_names:
                translated_dest = alt_name
            else:
                translated_dest = target_host_name
                plan.warnings.append({"level": "red", "text":
                    f"Target '{target}' needs a host object. Create '{target_host_name}' first."
                })
                missing_host_info_target = {
                    "name": target_host_name,
                    "ip": target,
                    "type": "translated_destination",
                }
    else:
        # Alias name
        sophos_ref = sanitize_sophos_name(target)
        if sophos_ref.lower() in {n.lower() for n in migrated_alias_names}:
            translated_dest = sophos_ref
            plan.warnings.append({"level": "green", "text": f"Target '{target}' → migrated alias '{sophos_ref}'"})
        else:
            all_names = set()
            for names_set in existing_object_names.values():
                all_names.update(n.lower() for n in names_set)
            if sophos_ref.lower() in all_names:
                translated_dest = sophos_ref
            else:
                translated_dest = sophos_ref
                # Try to resolve alias IP from pfSense aliases for host creation
                alias_ip = None
                if alias_address_lookup:
                    alias_ip = alias_address_lookup.get(target)
                if alias_ip and _is_ip_address(alias_ip):
                    plan.warnings.append({"level": "red", "text":
                        f"Target alias '{target}' ({alias_ip}) not found on Sophos. Create host or migrate the alias first."
                    })
                    missing_host_info_target = {
                        "name": sophos_ref,
                        "ip": alias_ip,
                        "type": "translated_destination",
                    }
                else:
                    plan.warnings.append({"level": "red", "text":
                        f"Target alias '{target}' not found on Sophos. Migrate the alias first."
                    })

    # --- Original Service (destination port) ---
    dst_port = rule_row.get("destination_port") or ""
    original_service = None
    missing_service_orig = None

    if dst_port:
        service_list = _resolve_service(protocol, dst_port, existing_services, migrated_alias_names)
        if service_list:
            original_service = service_list[0] if len(service_list) == 1 else service_list[0]
        else:
            proposed = _propose_services(protocol, dst_port)
            if proposed:
                original_service = proposed[0]["name"]
                plan.warnings.append({"level": "red", "text":
                    f"No matching Sophos service for {protocol}/{dst_port}. "
                    f"Create '{proposed[0]['name']}' first."
                })
                missing_service_orig = {
                    "protocol": protocol,
                    "port": dst_port,
                    "proposed": proposed,
                    "type": "original_service",
                }
    else:
        plan.warnings.append({"level": "orange", "text": "No destination port — original service will be empty"})

    # --- Translated Service (local port / PAT) ---
    local_port = rule_row.get("local_port") or ""
    translated_service = "Original"
    missing_service_trans = None

    if local_port and local_port != dst_port:
        # Different port = PAT, need a separate service
        service_list = _resolve_service(protocol, local_port, existing_services, migrated_alias_names)
        if service_list:
            translated_service = service_list[0]
        else:
            proposed = _propose_services(protocol, local_port)
            if proposed:
                translated_service = proposed[0]["name"]
                plan.warnings.append({"level": "red", "text":
                    f"No matching Sophos service for translated port {protocol}/{local_port}. "
                    f"Create '{proposed[0]['name']}' first."
                })
                missing_service_trans = {
                    "protocol": protocol,
                    "port": local_port,
                    "proposed": proposed,
                    "type": "translated_service",
                }
    elif local_port and local_port == dst_port:
        translated_service = "Original"
        plan.warnings.append({"level": "green", "text": "Translated port same as original — using 'Original'"})

    # Build rule_params for display and XML generation
    rule_params = {
        "name": sophos_name,
        "description": descr[:200],
        "ip_family": ip_family,
        "status": sophos_status,
        "position": position,
        "original_destination": orig_dest_network,
        "translated_destination": translated_dest,
        "original_service": original_service,
        "translated_service": translated_service,
        "protocol": protocol,
    }
    if prev_rule_name:
        rule_params["after_rule_name"] = prev_rule_name

    # Collect missing objects
    missing_services = []
    if missing_service_orig:
        missing_services.append(missing_service_orig)
    if missing_service_trans:
        missing_services.append(missing_service_trans)
    if missing_services:
        rule_params["_missing_services"] = missing_services

    missing_hosts = []
    if missing_host_info_orig:
        missing_hosts.append(missing_host_info_orig)
    if missing_host_info_target:
        missing_hosts.append(missing_host_info_target)
    if missing_hosts:
        rule_params["_missing_hosts"] = missing_hosts

    plan.rule_params = rule_params
    plan.reason = f"Create DNAT: {orig_dest_network} → {translated_dest}"

    # Build XML
    plan.nat_xml = _build_nat_rule_xml(rule_params)

    return plan


def _build_nat_rule_xml(params):
    """Build Sophos NATRule XML from rule_params dict.

    Returns:
        str: XML string for submit_xml()
    """
    name = _xml_escape(params.get("name", ""))
    description = _xml_escape(params.get("description", ""))
    ip_family = _xml_escape(params.get("ip_family", "IPv4"))
    status = _xml_escape(params.get("status", "Enable"))
    position = _xml_escape(params.get("position", "Top"))
    orig_dest = _xml_escape(params.get("original_destination", ""))
    trans_dest = _xml_escape(params.get("translated_destination", ""))
    orig_svc = _xml_escape(params.get("original_service", ""))
    trans_svc = _xml_escape(params.get("translated_service", "Original"))

    xml = f"""<NATRule>
  <Name>{name}</Name>
  <Description>{description}</Description>
  <IPFamily>{ip_family}</IPFamily>
  <Status>{status}</Status>
  <Position>{position}</Position>"""

    if position == "After" and params.get("after_rule_name"):
        after_name = _xml_escape(params["after_rule_name"])
        xml += f"""
  <After><Name>{after_name}</Name></After>"""

    xml += f"""
  <LinkedFirewallrule>None</LinkedFirewallrule>
  <OriginalDestinationNetworks><Network>{orig_dest}</Network></OriginalDestinationNetworks>
  <TranslatedDestination>{trans_dest}</TranslatedDestination>"""

    if orig_svc:
        xml += f"""
  <OriginalServices><Service>{orig_svc}</Service></OriginalServices>"""

    xml += f"""
  <TranslatedService>{trans_svc}</TranslatedService>
  <OverrideInterfaceNATPolicy>Disable</OverrideInterfaceNATPolicy>
  <TranslatedSource>Original</TranslatedSource>
  <NATMethod>0</NATMethod>
  <HealthCheck>Disable</HealthCheck>
</NATRule>"""

    return xml


def _xml_escape(value):
    """Escape special XML characters."""
    if not value:
        return ""
    return (str(value)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;"))


def execute_nat_migration(client, planned_nat):
    """Execute a NAT rule migration plan via submit_xml().

    Args:
        client: SophosFirewall SDK client
        planned_nat: PlannedNatRule with action="create"

    Returns:
        NatRuleMigrationResult
    """
    if planned_nat.action != "create":
        return NatRuleMigrationResult(
            rule_id=planned_nat.rule_id,
            success=planned_nat.action == "exists",
            status="migrated" if planned_nat.action == "exists" else "skipped",
            rule_name=planned_nat.rule_name,
        )

    try:
        _retry_on_rate_limit(client.submit_xml, planned_nat.nat_xml)
        logger.info("Created NAT rule: %s", planned_nat.rule_name)
        return NatRuleMigrationResult(
            rule_id=planned_nat.rule_id,
            success=True,
            status="migrated",
            rule_name=planned_nat.rule_name,
        )
    except Exception as e:
        logger.error("Failed to create NAT rule %s: %s", planned_nat.rule_name, e)
        return NatRuleMigrationResult(
            rule_id=planned_nat.rule_id,
            success=False,
            status="failed",
            rule_name=planned_nat.rule_name,
            error=str(e),
        )


def planned_nat_to_dict(plan):
    """Serialize a PlannedNatRule to a JSON-safe dict."""
    return {
        "rule_id": plan.rule_id,
        "rule_name": plan.rule_name,
        "pf_description": plan.pf_description,
        "action": plan.action,
        "reason": plan.reason,
        "rule_params": plan.rule_params,
        "warnings": plan.warnings,
        "nat_xml": plan.nat_xml,
    }


def nat_result_to_dict(result):
    """Serialize a NatRuleMigrationResult to a JSON-safe dict."""
    return {
        "rule_id": result.rule_id,
        "success": result.success,
        "status": result.status,
        "rule_name": result.rule_name,
        "error": result.error,
    }
