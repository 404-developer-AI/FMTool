"""pfSense XML backup parser for FMTool."""

import xml.etree.ElementTree as ET


class ParseError(Exception):
    """Raised when a pfSense backup cannot be parsed."""
    pass


def _get_text(element, tag, default=""):
    """Safely get text content of a child element."""
    child = element.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return default


def _has_element(element, tag):
    """Check if a child element exists (used for boolean flags like <disabled/>)."""
    return element.find(tag) is not None


def _element_to_xml(element):
    """Serialize an element to raw XML string."""
    return ET.tostring(element, encoding="unicode")


def _parse_source_dest(element):
    """Parse a <source> or <destination> sub-element."""
    if element is None:
        return {"type": "", "value": "", "port": "", "not": 0}

    result = {
        "type": "",
        "value": "",
        "port": _get_text(element, "port"),
        "not": 1 if _has_element(element, "not") else 0,
    }

    if _has_element(element, "any"):
        result["type"] = "any"
    elif element.find("address") is not None:
        result["type"] = "address"
        result["value"] = _get_text(element, "address")
    elif element.find("network") is not None:
        result["type"] = "network"
        result["value"] = _get_text(element, "network")

    return result


def _parse_interfaces(root):
    """Parse /pfsense/interfaces/*."""
    interfaces_el = root.find("interfaces")
    if interfaces_el is None:
        return []

    items = []
    for iface in interfaces_el:
        items.append({
            "if_name": iface.tag,
            "device": _get_text(iface, "if"),
            "descr": _get_text(iface, "descr"),
            "enable": 1 if _has_element(iface, "enable") else 0,
            "ipaddr": _get_text(iface, "ipaddr"),
            "subnet": _get_text(iface, "subnet"),
            "ipaddrv6": _get_text(iface, "ipaddrv6"),
            "subnetv6": _get_text(iface, "subnetv6"),
            "gateway": _get_text(iface, "gateway"),
            "gatewayv6": _get_text(iface, "gatewayv6"),
            "spoofmac": _get_text(iface, "spoofmac"),
            "blockpriv": 1 if _has_element(iface, "blockpriv") else 0,
            "blockbogons": 1 if _has_element(iface, "blockbogons") else 0,
            "track6_interface": _get_text(iface, "track6-interface"),
            "track6_prefix_id": _get_text(iface, "track6-prefix-id"),
            "media": _get_text(iface, "media"),
            "mediaopt": _get_text(iface, "mediaopt"),
            "raw_xml": _element_to_xml(iface),
        })
    return items


def _parse_firewall_rules(root):
    """Parse /pfsense/filter/rule."""
    filter_el = root.find("filter")
    if filter_el is None:
        return []

    items = []
    for rule in filter_el.findall("rule"):
        tracker = _get_text(rule, "tracker")
        if not tracker:
            continue

        src = _parse_source_dest(rule.find("source"))
        dst = _parse_source_dest(rule.find("destination"))

        created_el = rule.find("created")
        updated_el = rule.find("updated")

        items.append({
            "tracker": tracker,
            "type": _get_text(rule, "type", "pass"),
            "interface": _get_text(rule, "interface"),
            "ipprotocol": _get_text(rule, "ipprotocol"),
            "protocol": _get_text(rule, "protocol"),
            "source_type": src["type"],
            "source_value": src["value"],
            "source_port": src["port"],
            "source_not": src["not"],
            "destination_type": dst["type"],
            "destination_value": dst["value"],
            "destination_port": dst["port"],
            "destination_not": dst["not"],
            "descr": _get_text(rule, "descr"),
            "disabled": 1 if _has_element(rule, "disabled") else 0,
            "log": 1 if _has_element(rule, "log") else 0,
            "statetype": _get_text(rule, "statetype"),
            "tag": _get_text(rule, "tag"),
            "tagged": _get_text(rule, "tagged"),
            "associated_rule_id": _get_text(rule, "associated-rule-id"),
            "created_time": _get_text(created_el, "time") if created_el is not None else "",
            "created_username": _get_text(created_el, "username") if created_el is not None else "",
            "updated_time": _get_text(updated_el, "time") if updated_el is not None else "",
            "updated_username": _get_text(updated_el, "username") if updated_el is not None else "",
            "raw_xml": _element_to_xml(rule),
        })
    return items


def _parse_nat_rules(root):
    """Parse /pfsense/nat/rule (port forward rules)."""
    nat_el = root.find("nat")
    if nat_el is None:
        return []

    items = []
    for rule in nat_el.findall("rule"):
        assoc_id = _get_text(rule, "associated-rule-id")
        if not assoc_id:
            continue

        src = _parse_source_dest(rule.find("source"))
        dst = _parse_source_dest(rule.find("destination"))

        created_el = rule.find("created")
        updated_el = rule.find("updated")

        items.append({
            "associated_rule_id": assoc_id,
            "interface": _get_text(rule, "interface"),
            "ipprotocol": _get_text(rule, "ipprotocol"),
            "protocol": _get_text(rule, "protocol"),
            "source_type": src["type"],
            "source_value": src["value"],
            "source_port": src["port"],
            "destination_type": dst["type"],
            "destination_value": dst["value"],
            "destination_port": dst["port"],
            "target": _get_text(rule, "target"),
            "local_port": _get_text(rule, "local-port"),
            "descr": _get_text(rule, "descr"),
            "disabled": 1 if _has_element(rule, "disabled") else 0,
            "created_time": _get_text(created_el, "time") if created_el is not None else "",
            "created_username": _get_text(created_el, "username") if created_el is not None else "",
            "updated_time": _get_text(updated_el, "time") if updated_el is not None else "",
            "updated_username": _get_text(updated_el, "username") if updated_el is not None else "",
            "raw_xml": _element_to_xml(rule),
        })
    return items


def _parse_nat_onetoone(root):
    """Parse /pfsense/nat/onetoone (1:1 NAT rules)."""
    nat_el = root.find("nat")
    if nat_el is None:
        return []

    items = []
    for oto in nat_el.findall("onetoone"):
        external = _get_text(oto, "external")
        if not external:
            continue

        src = _parse_source_dest(oto.find("source"))
        dst = _parse_source_dest(oto.find("destination"))

        items.append({
            "interface": _get_text(oto, "interface"),
            "ipprotocol": _get_text(oto, "ipprotocol"),
            "external": external,
            "source_type": src["type"],
            "source_value": src["value"],
            "destination_type": dst["type"],
            "destination_value": dst["value"],
            "descr": _get_text(oto, "descr"),
            "disabled": 1 if _has_element(oto, "disabled") else 0,
            "raw_xml": _element_to_xml(oto),
        })
    return items


def _parse_nat_separators(root):
    """Parse /pfsense/nat/separator/*."""
    sep_el = root.find("nat/separator")
    if sep_el is None:
        return []

    items = []
    for sep in sep_el:
        items.append({
            "sep_key": sep.tag,
            "row_ref": _get_text(sep, "row"),
            "text": _get_text(sep, "text"),
            "color": _get_text(sep, "color"),
            "if_ref": _get_text(sep, "if"),
            "raw_xml": _element_to_xml(sep),
        })
    return items


def _parse_nat_outbound_mode(root):
    """Parse /pfsense/nat/outbound/mode."""
    return _get_text(root, "nat/outbound/mode", "automatic")


def _parse_filter_separators(root):
    """Parse /pfsense/filter/separator (per-interface separators)."""
    sep_el = root.find("filter/separator")
    if sep_el is None:
        return []

    items = []
    for iface_el in sep_el:
        interface = iface_el.tag
        for sep in iface_el:
            items.append({
                "interface": interface,
                "sep_key": sep.tag,
                "row_ref": _get_text(sep, "row"),
                "text": _get_text(sep, "text"),
                "color": _get_text(sep, "color"),
                "raw_xml": _element_to_xml(sep),
            })
    return items


def _parse_aliases(root):
    """Parse /pfsense/aliases/alias."""
    aliases_el = root.find("aliases")
    if aliases_el is None:
        return []

    items = []
    for alias in aliases_el.findall("alias"):
        name = _get_text(alias, "name")
        if not name:
            continue
        items.append({
            "name": name,
            "type": _get_text(alias, "type"),
            "address": _get_text(alias, "address"),
            "descr": _get_text(alias, "descr"),
            "detail": _get_text(alias, "detail"),
            "raw_xml": _element_to_xml(alias),
        })
    return items


def _parse_virtual_ips(root):
    """Parse /pfsense/virtualip/vip."""
    vip_el = root.find("virtualip")
    if vip_el is None:
        return []

    items = []
    for vip in vip_el.findall("vip"):
        uniqid = _get_text(vip, "uniqid")
        if not uniqid:
            continue
        items.append({
            "uniqid": uniqid,
            "mode": _get_text(vip, "mode"),
            "interface": _get_text(vip, "interface"),
            "descr": _get_text(vip, "descr"),
            "type": _get_text(vip, "type"),
            "subnet": _get_text(vip, "subnet"),
            "subnet_bits": _get_text(vip, "subnet_bits"),
            "raw_xml": _element_to_xml(vip),
        })
    return items


def _parse_gateways(root):
    """Parse /pfsense/gateways. Returns (items, default_gw4, default_gw6)."""
    gw_el = root.find("gateways")
    if gw_el is None:
        return [], "", ""

    default_gw4 = _get_text(gw_el, "defaultgw4")
    default_gw6 = _get_text(gw_el, "defaultgw6")

    items = []
    for gw in gw_el.findall("gateway_item"):
        name = _get_text(gw, "name")
        if not name:
            continue
        items.append({
            "name": name,
            "interface": _get_text(gw, "interface"),
            "gateway": _get_text(gw, "gateway"),
            "ipprotocol": _get_text(gw, "ipprotocol"),
            "weight": _get_text(gw, "weight"),
            "descr": _get_text(gw, "descr"),
            "default_v4": 1 if name == default_gw4 else 0,
            "default_v6": 1 if name == default_gw6 else 0,
            "raw_xml": _element_to_xml(gw),
        })
    return items, default_gw4, default_gw6


def _parse_static_routes(root):
    """Parse /pfsense/staticroutes/route."""
    sr_el = root.find("staticroutes")
    if sr_el is None:
        return []

    items = []
    for route in sr_el.findall("route"):
        network = _get_text(route, "network")
        gateway = _get_text(route, "gateway")
        if not network or not gateway:
            continue
        items.append({
            "network": network,
            "gateway": gateway,
            "descr": _get_text(route, "descr"),
            "raw_xml": _element_to_xml(route),
        })
    return items


def _parse_dhcpd(root):
    """Parse /pfsense/dhcpd/* (DHCP v4 per interface)."""
    dhcpd_el = root.find("dhcpd")
    if dhcpd_el is None:
        return []

    items = []
    for iface in dhcpd_el:
        range_el = iface.find("range")
        items.append({
            "interface": iface.tag,
            "version": 4,
            "range_from": _get_text(range_el, "from") if range_el is not None else "",
            "range_to": _get_text(range_el, "to") if range_el is not None else "",
            "ramode": "",
            "rapriority": "",
            "raw_xml": _element_to_xml(iface),
        })
    return items


def _parse_dhcpdv6(root):
    """Parse /pfsense/dhcpdv6/* (DHCP v6 per interface)."""
    dhcpdv6_el = root.find("dhcpdv6")
    if dhcpdv6_el is None:
        return []

    items = []
    for iface in dhcpdv6_el:
        range_el = iface.find("range")
        items.append({
            "interface": iface.tag,
            "version": 6,
            "range_from": _get_text(range_el, "from") if range_el is not None else "",
            "range_to": _get_text(range_el, "to") if range_el is not None else "",
            "ramode": _get_text(iface, "ramode"),
            "rapriority": _get_text(iface, "rapriority"),
            "raw_xml": _element_to_xml(iface),
        })
    return items


def _parse_dns_hosts(root):
    """Parse /pfsense/unbound/hosts."""
    unbound_el = root.find("unbound")
    if unbound_el is None:
        return []

    items = []
    for host_el in unbound_el.findall("hosts"):
        host = _get_text(host_el, "host")
        domain = _get_text(host_el, "domain")
        if not host or not domain:
            continue

        aliases_child = host_el.find("aliases")
        aliases_xml = _element_to_xml(aliases_child) if aliases_child is not None and len(aliases_child) > 0 else ""

        items.append({
            "host": host,
            "domain": domain,
            "ip": _get_text(host_el, "ip"),
            "descr": _get_text(host_el, "descr"),
            "aliases_xml": aliases_xml,
            "raw_xml": _element_to_xml(host_el),
        })
    return items


def _parse_unbound_settings(root):
    """Parse /pfsense/unbound settings (excluding hosts)."""
    unbound_el = root.find("unbound")
    if unbound_el is None:
        return None

    return {
        "enable": 1 if _has_element(unbound_el, "enable") else 0,
        "dnssec": 1 if _has_element(unbound_el, "dnssec") else 0,
        "active_interface": _get_text(unbound_el, "active_interface"),
        "outgoing_interface": _get_text(unbound_el, "outgoing_interface"),
        "custom_options": _get_text(unbound_el, "custom_options"),
        "port": _get_text(unbound_el, "port"),
        "sslcertref": _get_text(unbound_el, "sslcertref"),
        "system_domain_local_zone_type": _get_text(unbound_el, "system_domain_local_zone_type"),
        "raw_xml": _element_to_xml(unbound_el),
    }


def _parse_ipsec(root):
    """Parse /pfsense/ipsec. Returns (phase1_list, phase2_list)."""
    ipsec_el = root.find("ipsec")
    if ipsec_el is None:
        return [], []

    phase1_items = []
    for p1 in ipsec_el.findall("phase1"):
        ikeid = _get_text(p1, "ikeid")
        if not ikeid:
            continue

        enc_el = p1.find("encryption")
        enc_xml = _element_to_xml(enc_el) if enc_el is not None else ""

        phase1_items.append({
            "ikeid": ikeid,
            "iketype": _get_text(p1, "iketype"),
            "mode": _get_text(p1, "mode"),
            "interface": _get_text(p1, "interface"),
            "remote_gateway": _get_text(p1, "remote-gateway"),
            "protocol": _get_text(p1, "protocol"),
            "authentication_method": _get_text(p1, "authentication_method"),
            "pre_shared_key": _get_text(p1, "pre-shared-key"),
            "descr": _get_text(p1, "descr"),
            "disabled": 1 if _has_element(p1, "disabled") else 0,
            "nat_traversal": _get_text(p1, "nat_traversal"),
            "dpd_delay": _get_text(p1, "dpd_delay"),
            "dpd_maxfail": _get_text(p1, "dpd_maxfail"),
            "lifetime": _get_text(p1, "lifetime"),
            "encryption_xml": enc_xml,
            "raw_xml": _element_to_xml(p1),
        })

    phase2_items = []
    for p2 in ipsec_el.findall("phase2"):
        ikeid = _get_text(p2, "ikeid")
        uniqid = _get_text(p2, "uniqid")
        if not ikeid or not uniqid:
            continue

        localid = p2.find("localid")
        remoteid = p2.find("remoteid")

        enc_opts = p2.findall("encryption-algorithm-option")
        enc_xml = "".join(_element_to_xml(e) for e in enc_opts) if enc_opts else ""

        phase2_items.append({
            "ikeid": ikeid,
            "uniqid": uniqid,
            "mode": _get_text(p2, "mode"),
            "reqid": _get_text(p2, "reqid"),
            "protocol": _get_text(p2, "protocol"),
            "descr": _get_text(p2, "descr"),
            "localid_type": _get_text(localid, "type") if localid is not None else "",
            "localid_address": _get_text(localid, "address") if localid is not None else "",
            "localid_netbits": _get_text(localid, "netbits") if localid is not None else "",
            "remoteid_type": _get_text(remoteid, "type") if remoteid is not None else "",
            "remoteid_address": _get_text(remoteid, "address") if remoteid is not None else "",
            "remoteid_netbits": _get_text(remoteid, "netbits") if remoteid is not None else "",
            "lifetime": _get_text(p2, "lifetime"),
            "pfsgroup": _get_text(p2, "pfsgroup"),
            "encryption_xml": enc_xml,
            "hash_algorithm": _get_text(p2, "hash-algorithm-option"),
            "raw_xml": _element_to_xml(p2),
        })

    return phase1_items, phase2_items


def _parse_openvpn(root):
    """Parse /pfsense/openvpn. Returns (servers, csc_list)."""
    ovpn_el = root.find("openvpn")
    if ovpn_el is None:
        return [], []

    servers = []
    for srv in ovpn_el.findall("openvpn-server"):
        vpnid = _get_text(srv, "vpnid")
        if not vpnid:
            continue
        servers.append({
            "vpnid": vpnid,
            "mode": _get_text(srv, "mode"),
            "authmode": _get_text(srv, "authmode"),
            "protocol": _get_text(srv, "protocol"),
            "dev_mode": _get_text(srv, "dev_mode"),
            "interface": _get_text(srv, "interface"),
            "local_port": _get_text(srv, "local_port"),
            "description": _get_text(srv, "description"),
            "tls": _get_text(srv, "tls"),
            "tls_type": _get_text(srv, "tls_type"),
            "caref": _get_text(srv, "caref"),
            "certref": _get_text(srv, "certref"),
            "dh_length": _get_text(srv, "dh_length"),
            "digest": _get_text(srv, "digest"),
            "data_ciphers": _get_text(srv, "data_ciphers"),
            "data_ciphers_fallback": _get_text(srv, "data_ciphers_fallback"),
            "tunnel_network": _get_text(srv, "tunnel_network"),
            "tunnel_networkv6": _get_text(srv, "tunnel_networkv6"),
            "local_network": _get_text(srv, "local_network"),
            "local_networkv6": _get_text(srv, "local_networkv6"),
            "remote_network": _get_text(srv, "remote_network"),
            "remote_networkv6": _get_text(srv, "remote_networkv6"),
            "maxclients": _get_text(srv, "maxclients"),
            "compression": _get_text(srv, "compression"),
            "topology": _get_text(srv, "topology"),
            "raw_xml": _element_to_xml(srv),
        })

    csc_list = []
    for csc in ovpn_el.findall("openvpn-csc"):
        cn = _get_text(csc, "common_name")
        if not cn:
            continue
        csc_list.append({
            "common_name": cn,
            "description": _get_text(csc, "description"),
            "server_list": _get_text(csc, "server_list"),
            "tunnel_network": _get_text(csc, "tunnel_network"),
            "tunnel_networkv6": _get_text(csc, "tunnel_networkv6"),
            "local_network": _get_text(csc, "local_network"),
            "local_networkv6": _get_text(csc, "local_networkv6"),
            "remote_network": _get_text(csc, "remote_network"),
            "remote_networkv6": _get_text(csc, "remote_networkv6"),
            "block": 1 if _has_element(csc, "block") else 0,
            "gwredir": 1 if _has_element(csc, "gwredir") else 0,
            "push_reset": 1 if _has_element(csc, "push_reset") else 0,
            "raw_xml": _element_to_xml(csc),
        })

    return servers, csc_list


def _parse_certificates(root):
    """Parse /pfsense/cert."""
    items = []
    for cert in root.findall("cert"):
        refid = _get_text(cert, "refid")
        if not refid:
            continue
        items.append({
            "refid": refid,
            "descr": _get_text(cert, "descr"),
            "crt": _get_text(cert, "crt"),
            "prv": _get_text(cert, "prv"),
            "serial": _get_text(cert, "serial"),
            "raw_xml": _element_to_xml(cert),
        })
    return items


def _parse_cas(root):
    """Parse /pfsense/ca."""
    items = []
    for ca in root.findall("ca"):
        refid = _get_text(ca, "refid")
        if not refid:
            continue
        items.append({
            "refid": refid,
            "descr": _get_text(ca, "descr"),
            "crt": _get_text(ca, "crt"),
            "prv": _get_text(ca, "prv"),
            "serial": _get_text(ca, "serial"),
            "raw_xml": _element_to_xml(ca),
        })
    return items


def _parse_syslog(root):
    """Parse /pfsense/syslog."""
    syslog_el = root.find("syslog")
    if syslog_el is None:
        return None
    return {"raw_xml": _element_to_xml(syslog_el)}


def _parse_snmp(root):
    """Parse /pfsense/snmpd."""
    snmp_el = root.find("snmpd")
    if snmp_el is None:
        return None
    return {
        "syslocation": _get_text(snmp_el, "syslocation"),
        "syscontact": _get_text(snmp_el, "syscontact"),
        "rocommunity": _get_text(snmp_el, "rocommunity"),
        "raw_xml": _element_to_xml(snmp_el),
    }


def _parse_users(root):
    """Parse /pfsense/system/user."""
    system_el = root.find("system")
    if system_el is None:
        return []

    items = []
    for user in system_el.findall("user"):
        name = _get_text(user, "name")
        if not name:
            continue

        certref_els = user.findall("cert")
        certrefs = ",".join(el.text.strip() for el in certref_els if el.text)

        items.append({
            "name": name,
            "uid": _get_text(user, "uid"),
            "descr": _get_text(user, "descr"),
            "scope": _get_text(user, "scope"),
            "certref": certrefs,
            "raw_xml": _element_to_xml(user),
        })
    return items


def _parse_groups(root):
    """Parse /pfsense/system/group."""
    system_el = root.find("system")
    if system_el is None:
        return []

    items = []
    for group in system_el.findall("group"):
        name = _get_text(group, "name")
        if not name:
            continue

        member_els = group.findall("member")
        members = ",".join(el.text.strip() for el in member_els if el.text)

        items.append({
            "name": name,
            "gid": _get_text(group, "gid"),
            "description": _get_text(group, "description"),
            "scope": _get_text(group, "scope"),
            "members": members,
            "raw_xml": _element_to_xml(group),
        })
    return items


def _parse_packages(root):
    """Parse /pfsense/installedpackages/package."""
    pkg_el = root.find("installedpackages")
    if pkg_el is None:
        return []

    items = []
    for pkg in pkg_el.findall("package"):
        internal_name = _get_text(pkg, "internal_name")
        if not internal_name:
            continue
        items.append({
            "internal_name": internal_name,
            "name": _get_text(pkg, "name"),
            "version": _get_text(pkg, "version"),
            "descr": _get_text(pkg, "descr"),
            "raw_xml": _element_to_xml(pkg),
        })
    return items


def parse_pfsense_backup(filepath):
    """Parse a pfSense XML backup file.

    Returns a dict with all parsed sections.
    Raises ParseError if the file is invalid.
    """
    try:
        tree = ET.parse(filepath)
    except ET.ParseError as e:
        raise ParseError(f"Invalid XML file: {e}")

    root = tree.getroot()
    if root.tag != "pfsense":
        raise ParseError(f"Not a pfSense backup: root element is <{root.tag}>, expected <pfsense>")

    gateways, default_gw4, default_gw6 = _parse_gateways(root)
    phase1, phase2 = _parse_ipsec(root)
    ovpn_servers, ovpn_csc = _parse_openvpn(root)

    return {
        "metadata": {
            "version": _get_text(root, "version"),
            "hostname": _get_text(root, "system/hostname"),
            "domain": _get_text(root, "system/domain"),
        },
        "interfaces": _parse_interfaces(root),
        "firewall_rules": _parse_firewall_rules(root),
        "nat_rules": _parse_nat_rules(root),
        "nat_onetoone": _parse_nat_onetoone(root),
        "nat_separators": _parse_nat_separators(root),
        "nat_outbound_mode": _parse_nat_outbound_mode(root),
        "filter_separators": _parse_filter_separators(root),
        "aliases": _parse_aliases(root),
        "virtual_ips": _parse_virtual_ips(root),
        "gateways": gateways,
        "default_gw4": default_gw4,
        "default_gw6": default_gw6,
        "static_routes": _parse_static_routes(root),
        "dhcp_v4": _parse_dhcpd(root),
        "dhcp_v6": _parse_dhcpdv6(root),
        "dns_host_overrides": _parse_dns_hosts(root),
        "unbound_settings": _parse_unbound_settings(root),
        "ipsec_phase1": phase1,
        "ipsec_phase2": phase2,
        "openvpn_servers": ovpn_servers,
        "openvpn_csc": ovpn_csc,
        "certificates": _parse_certificates(root),
        "cas": _parse_cas(root),
        "syslog": _parse_syslog(root),
        "snmp": _parse_snmp(root),
        "users": _parse_users(root),
        "groups": _parse_groups(root),
        "packages": _parse_packages(root),
    }
