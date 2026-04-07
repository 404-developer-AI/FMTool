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


def _check_duplicate(plan, existing_names, sophos_type, sophos_name):
    """Check if the main object name already exists on Sophos."""
    existing = existing_names.get(sophos_type, set())
    # Case-insensitive comparison
    existing_lower = {n.lower() for n in existing}
    if sophos_name.lower() in existing_lower:
        plan.action = "exists"
        plan.reason = f"Object '{sophos_name}' already exists on Sophos as {sophos_type}"
