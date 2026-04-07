"""Sophos XGS API client wrapper for FMTool."""

import logging
import time
import urllib3

from requests.exceptions import ConnectionError, Timeout
from sophosfirewall_python.firewallapi import SophosFirewall
from sophosfirewall_python.api_client import (
    SophosFirewallAPIError,
    SophosFirewallAuthFailure,
    SophosFirewallZeroRecords,
)

# Suppress InsecureRequestWarning for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2


class SophosConnectionError(Exception):
    """Raised when connection to Sophos fails."""


class SophosAuthError(Exception):
    """Raised when authentication fails."""


def is_configured(app_config):
    """Check if Sophos credentials are present in config."""
    return all([
        app_config.get("SOPHOS_HOST"),
        app_config.get("SOPHOS_USERNAME"),
        app_config.get("SOPHOS_PASSWORD"),
    ])


def get_client(app_config):
    """Create a SophosFirewall SDK client from Flask app config.

    Returns:
        SophosFirewall instance

    Raises:
        SophosConnectionError: If credentials are not configured
    """
    host = app_config.get("SOPHOS_HOST")
    username = app_config.get("SOPHOS_USERNAME")
    password = app_config.get("SOPHOS_PASSWORD")
    port = app_config.get("SOPHOS_PORT", 4444)

    if not all([host, username, password]):
        raise SophosConnectionError("Sophos API credentials not configured. "
                                    "Create config.local.py with SOPHOS_HOST, "
                                    "SOPHOS_USERNAME, and SOPHOS_PASSWORD.")

    return SophosFirewall(
        username=username,
        password=password,
        hostname=host,
        port=port,
        verify=False,
    )


def test_connection(app_config):
    """Test the Sophos API connection.

    Returns:
        dict: {success: bool, message: str, firmware_version?, model?}
    """
    if not is_configured(app_config):
        return {
            "success": False,
            "message": "Sophos API credentials not configured.",
        }

    host = app_config.get("SOPHOS_HOST")
    port = app_config.get("SOPHOS_PORT", 4444)

    try:
        client = get_client(app_config)
        # Use login() to verify credentials work
        client.login()
        # Try to fetch device info (non-fatal if it fails)
        info = _get_device_info(client)
        return {
            "success": True,
            "message": "Connection successful",
            **info,
        }
    except SophosFirewallAuthFailure:
        return {
            "success": False,
            "message": "Authentication failed. Check username and password.",
        }
    except (ConnectionError, Timeout, OSError):
        return {
            "success": False,
            "message": f"Cannot reach Sophos at {host}:{port}. "
                       "Check host, port, and network connectivity.",
        }
    except SophosFirewallAPIError as e:
        return {
            "success": False,
            "message": f"API error: {e}",
        }
    except Exception as e:
        logger.exception("Unexpected error testing Sophos connection")
        return {
            "success": False,
            "message": f"Unexpected error: {e}",
        }


def _get_device_info(client):
    """Fetch basic device info from Sophos. Returns dict with available fields."""
    info = {}
    try:
        result = client.get_tag("LicenseDetails")
        if result and "Response" in result:
            response = result["Response"]
            info["firmware_version"] = _extract_nested(response, "Firmware")
            info["serial_number"] = _extract_nested(response, "SerialNumber")
            info["model"] = _extract_nested(response, "Model")
    except (SophosFirewallZeroRecords, SophosFirewallAPIError, Exception):
        pass
    # Filter out None values
    return {k: v for k, v in info.items() if v is not None}


def get_sophos_objects_summary(app_config):
    """Fetch summary counts of existing Sophos objects.

    Returns:
        dict: {category: count} where count is int or None (on error)
    """
    client = get_client(app_config)
    summary = {}

    fetch_map = [
        ("ip_hosts", "get_ip_host", "IP Hosts"),
        ("ip_host_groups", "get_ip_hostgroup", "IP Host Groups"),
        ("fqdn_hosts", "get_fqdn_host", "FQDN Hosts"),
        ("services", "get_service", "Services"),
        ("service_groups", "get_service_group", "Service Groups"),
        ("fw_rules", "get_fw_rule", "Firewall Rules"),
        ("zones", "get_zone", "Zones"),
        ("interfaces", "get_interface", "Interfaces"),
        ("vlans", "get_vlan", "VLANs"),
    ]

    for key, method_name, _label in fetch_map:
        try:
            method = getattr(client, method_name)
            result = _retry_on_rate_limit(method)
            summary[key] = _count_items(result)
        except SophosFirewallZeroRecords:
            summary[key] = 0
        except (SophosFirewallAPIError, Exception) as e:
            logger.warning("Failed to fetch %s: %s", key, e)
            summary[key] = None

    return summary


# Label map for display in templates
SOPHOS_OBJECT_LABELS = {
    "ip_hosts": "IP Hosts",
    "ip_host_groups": "IP Host Groups",
    "fqdn_hosts": "FQDN Hosts",
    "services": "Services",
    "service_groups": "Service Groups",
    "fw_rules": "Firewall Rules",
    "zones": "Zones",
    "interfaces": "Interfaces",
    "vlans": "VLANs",
}


def get_existing_object_names(app_config):
    """Fetch names of existing Sophos objects for duplicate detection.

    Returns:
        dict: {category: set of names} e.g. {"ip_hosts": {"host1", "host2"}, ...}
    """
    client = get_client(app_config)
    result = {}

    fetch_map = [
        ("ip_hosts", "get_ip_host", "IPHost"),
        ("ip_host_groups", "get_ip_hostgroup", "IPHostGroup"),
        ("fqdn_hosts", "get_fqdn_host", "FQDNHost"),
        ("services", "get_service", "Services"),
        ("service_groups", "get_service_group", "ServiceGroup"),
    ]

    for key, method_name, xml_tag in fetch_map:
        try:
            method = getattr(client, method_name)
            response = _retry_on_rate_limit(method)
            result[key] = _extract_names(response, xml_tag)
        except SophosFirewallZeroRecords:
            result[key] = set()
        except (SophosFirewallAPIError, Exception) as e:
            logger.warning("Failed to fetch %s names: %s", key, e)
            result[key] = set()

    return result


def get_existing_fw_rule_names(app_config):
    """Fetch names of existing Sophos firewall rules for duplicate detection.

    Returns:
        set: Set of rule name strings
    """
    client = get_client(app_config)
    try:
        response = _retry_on_rate_limit(client.get_fw_rule)
        return _extract_names(response, "FirewallRule")
    except SophosFirewallZeroRecords:
        return set()
    except (SophosFirewallAPIError, Exception) as e:
        logger.warning("Failed to fetch firewall rule names: %s", e)
        return set()


def get_interface_details(app_config):
    """Fetch Sophos interface details including IPs and interface aliases.

    Interface aliases are a separate API object ('Alias' tag) linked by hardware name.
    Sophos firewall rules accept #InterfaceName and #AliasName as destination networks.

    Returns:
        list: List of dicts with interface info:
              [{"name": "Port1_WAN", "hardware": "Port1", "zone": "WAN",
                "ip": "1.2.3.4", "alias_ips": [{"name": "Port1:0", "ip": "1.2.3.5"}]}]
    """
    client = get_client(app_config)

    # Fetch interfaces
    try:
        response = _retry_on_rate_limit(client.get_interface)
    except SophosFirewallZeroRecords:
        return []
    except (SophosFirewallAPIError, Exception) as e:
        logger.warning("Failed to fetch interface details: %s", e)
        return []

    if not response or "Response" not in response:
        return []

    data = response["Response"].get("Interface")
    if not data:
        return []

    items = data if isinstance(data, list) else [data]

    # Fetch interface aliases (separate 'Alias' API tag)
    alias_by_hardware = {}
    try:
        alias_resp = _retry_on_rate_limit(client.get_tag, "Alias")
        alias_data = alias_resp.get("Response", {}).get("Alias", [])
        if isinstance(alias_data, dict):
            alias_data = [alias_data]
        for a in alias_data:
            if not isinstance(a, dict):
                continue
            hw = a.get("Interface", "")
            aip = a.get("IPAddress", "")
            aname = a.get("Name", "")
            if hw and aip:
                alias_by_hardware.setdefault(hw, []).append({
                    "name": aname,
                    "ip": aip,
                })
    except (SophosFirewallZeroRecords, SophosFirewallAPIError, Exception) as e:
        logger.warning("Failed to fetch interface aliases: %s", e)

    interfaces = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("Name", "")
        if not name:
            continue

        ip = item.get("IPAddress") or ""
        zone = item.get("NetworkZone", "")
        hardware = item.get("Hardware", "")
        alias_ips = alias_by_hardware.get(hardware, [])

        interfaces.append({
            "name": name,
            "hardware": hardware,
            "zone": zone,
            "ip": ip,
            "alias_ips": alias_ips,
        })

    return interfaces


def get_zone_names(app_config):
    """Fetch names of existing Sophos zones.

    Returns:
        list: List of zone name strings, sorted
    """
    client = get_client(app_config)
    try:
        response = _retry_on_rate_limit(client.get_zone)
        names = _extract_names(response, "Zone")
        return sorted(names)
    except SophosFirewallZeroRecords:
        return []
    except (SophosFirewallAPIError, Exception) as e:
        logger.warning("Failed to fetch zone names: %s", e)
        return []


def get_existing_services_with_details(app_config):
    """Fetch existing Sophos services with protocol/port details.

    Returns:
        list: List of dicts with 'name' and 'details' keys.
              Each detail has 'protocol' and 'dst_port'.
    """
    client = get_client(app_config)
    try:
        response = _retry_on_rate_limit(client.get_service)
    except SophosFirewallZeroRecords:
        return []
    except (SophosFirewallAPIError, Exception) as e:
        logger.warning("Failed to fetch service details: %s", e)
        return []

    services = []
    if not response or "Response" not in response:
        return services

    data = response["Response"].get("Services")
    if not data:
        return services

    items = data if isinstance(data, list) else [data]
    for item in items:
        if not isinstance(item, dict) or "Name" not in item:
            continue
        details = []
        sd = item.get("ServiceDetails", {})
        if sd:
            detail_list = sd.get("ServiceDetail")
            if detail_list:
                if isinstance(detail_list, dict):
                    detail_list = [detail_list]
                for d in detail_list:
                    if isinstance(d, dict):
                        details.append({
                            "protocol": d.get("Protocol", ""),
                            "dst_port": d.get("DestinationPort", ""),
                        })
        services.append({"name": item["Name"], "details": details})
    return services


def _extract_names(response, xml_tag):
    """Extract object names from SDK response dict."""
    names = set()
    if not response or "Response" not in response:
        return names
    data = response["Response"].get(xml_tag)
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and "Name" in item:
                names.add(item["Name"])
    elif isinstance(data, dict) and "Name" in data:
        names.add(data["Name"])
    return names


def _retry_on_rate_limit(func, *args, **kwargs):
    """Retry a function call with exponential backoff on rate limiting."""
    for attempt in range(MAX_RETRIES):
        try:
            return func(*args, **kwargs)
        except SophosFirewallAPIError as e:
            if "429" in str(e) and attempt < MAX_RETRIES - 1:
                wait = RETRY_BACKOFF_BASE ** (attempt + 1)
                logger.warning("Rate limited, retrying in %ds...", wait)
                time.sleep(wait)
            else:
                raise


def _count_items(result):
    """Count items in SDK response dict."""
    if not result or "Response" not in result:
        return 0
    response = result["Response"]
    for key, value in response.items():
        if key in ("@APIVersion", "@IPS_CAT_VER", "Login"):
            continue
        if isinstance(value, list):
            return len(value)
        if isinstance(value, dict):
            return 1
    return 0


def _extract_nested(data, key):
    """Recursively search for a key in nested dict/list structure."""
    if isinstance(data, dict):
        if key in data:
            return data[key]
        for v in data.values():
            found = _extract_nested(v, key)
            if found is not None:
                return found
    elif isinstance(data, list):
        for item in data:
            found = _extract_nested(item, key)
            if found is not None:
                return found
    return None
