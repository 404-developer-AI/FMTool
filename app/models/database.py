"""SQLite database schema and operations for FMTool."""

import glob as globmod
import os
import sqlite3
from datetime import datetime, timezone


def get_db(db_path):
    """Get a database connection with Row factory."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path):
    """Create all tables if they don't exist."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = get_db(db_path)
    cur = conn.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS imports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            pfsense_version TEXT,
            hostname TEXT,
            domain TEXT,
            imported_at TEXT NOT NULL,
            item_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS interfaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            if_name TEXT NOT NULL,
            device TEXT,
            descr TEXT,
            enable INTEGER DEFAULT 0,
            ipaddr TEXT,
            subnet TEXT,
            ipaddrv6 TEXT,
            subnetv6 TEXT,
            gateway TEXT,
            gatewayv6 TEXT,
            spoofmac TEXT,
            blockpriv INTEGER DEFAULT 0,
            blockbogons INTEGER DEFAULT 0,
            track6_interface TEXT,
            track6_prefix_id TEXT,
            media TEXT,
            mediaopt TEXT,
            raw_xml TEXT,
            migration_status TEXT DEFAULT 'pending',
            UNIQUE(if_name)
        );

        CREATE TABLE IF NOT EXISTS firewall_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            tracker TEXT NOT NULL,
            type TEXT,
            interface TEXT,
            ipprotocol TEXT,
            protocol TEXT,
            source_type TEXT,
            source_value TEXT,
            source_port TEXT,
            source_not INTEGER DEFAULT 0,
            destination_type TEXT,
            destination_value TEXT,
            destination_port TEXT,
            destination_not INTEGER DEFAULT 0,
            descr TEXT,
            disabled INTEGER DEFAULT 0,
            log INTEGER DEFAULT 0,
            statetype TEXT,
            tag TEXT,
            tagged TEXT,
            associated_rule_id TEXT,
            created_time TEXT,
            created_username TEXT,
            updated_time TEXT,
            updated_username TEXT,
            raw_xml TEXT,
            migration_status TEXT DEFAULT 'pending',
            UNIQUE(tracker)
        );

        CREATE TABLE IF NOT EXISTS nat_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            associated_rule_id TEXT NOT NULL,
            interface TEXT,
            ipprotocol TEXT,
            protocol TEXT,
            source_type TEXT,
            source_value TEXT,
            source_port TEXT,
            destination_type TEXT,
            destination_value TEXT,
            destination_port TEXT,
            target TEXT,
            local_port TEXT,
            descr TEXT,
            disabled INTEGER DEFAULT 0,
            created_time TEXT,
            created_username TEXT,
            updated_time TEXT,
            updated_username TEXT,
            raw_xml TEXT,
            migration_status TEXT DEFAULT 'pending',
            UNIQUE(associated_rule_id)
        );

        CREATE TABLE IF NOT EXISTS nat_separators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            sep_key TEXT NOT NULL,
            row_ref TEXT,
            text TEXT,
            color TEXT,
            if_ref TEXT,
            raw_xml TEXT,
            UNIQUE(sep_key)
        );

        CREATE TABLE IF NOT EXISTS nat_outbound (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            mode TEXT
        );

        CREATE TABLE IF NOT EXISTS aliases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            name TEXT NOT NULL,
            type TEXT,
            address TEXT,
            descr TEXT,
            detail TEXT,
            raw_xml TEXT,
            migration_status TEXT DEFAULT 'pending',
            UNIQUE(name)
        );

        CREATE TABLE IF NOT EXISTS virtual_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            uniqid TEXT NOT NULL,
            mode TEXT,
            interface TEXT,
            descr TEXT,
            type TEXT,
            subnet TEXT,
            subnet_bits TEXT,
            raw_xml TEXT,
            migration_status TEXT DEFAULT 'pending',
            UNIQUE(uniqid)
        );

        CREATE TABLE IF NOT EXISTS gateways (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            name TEXT NOT NULL,
            interface TEXT,
            gateway TEXT,
            ipprotocol TEXT,
            weight TEXT,
            descr TEXT,
            default_v4 INTEGER DEFAULT 0,
            default_v6 INTEGER DEFAULT 0,
            raw_xml TEXT,
            migration_status TEXT DEFAULT 'pending',
            UNIQUE(name)
        );

        CREATE TABLE IF NOT EXISTS static_routes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            network TEXT NOT NULL,
            gateway TEXT NOT NULL,
            descr TEXT,
            raw_xml TEXT,
            migration_status TEXT DEFAULT 'pending',
            UNIQUE(network, gateway)
        );

        CREATE TABLE IF NOT EXISTS dhcp_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            interface TEXT NOT NULL,
            version INTEGER NOT NULL,
            range_from TEXT,
            range_to TEXT,
            ramode TEXT,
            rapriority TEXT,
            raw_xml TEXT,
            migration_status TEXT DEFAULT 'pending',
            UNIQUE(interface, version)
        );

        CREATE TABLE IF NOT EXISTS dns_host_overrides (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            host TEXT NOT NULL,
            domain TEXT NOT NULL,
            ip TEXT,
            descr TEXT,
            aliases_xml TEXT,
            raw_xml TEXT,
            migration_status TEXT DEFAULT 'pending',
            UNIQUE(host, domain)
        );

        CREATE TABLE IF NOT EXISTS unbound_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            enable INTEGER DEFAULT 0,
            dnssec INTEGER DEFAULT 0,
            active_interface TEXT,
            outgoing_interface TEXT,
            custom_options TEXT,
            port TEXT,
            sslcertref TEXT,
            system_domain_local_zone_type TEXT,
            raw_xml TEXT
        );

        CREATE TABLE IF NOT EXISTS ipsec_phase1 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            ikeid TEXT NOT NULL,
            iketype TEXT,
            mode TEXT,
            interface TEXT,
            remote_gateway TEXT,
            protocol TEXT,
            authentication_method TEXT,
            pre_shared_key TEXT,
            descr TEXT,
            disabled INTEGER DEFAULT 0,
            nat_traversal TEXT,
            dpd_delay TEXT,
            dpd_maxfail TEXT,
            lifetime TEXT,
            encryption_xml TEXT,
            raw_xml TEXT,
            migration_status TEXT DEFAULT 'pending',
            UNIQUE(ikeid)
        );

        CREATE TABLE IF NOT EXISTS ipsec_phase2 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            ikeid TEXT NOT NULL,
            uniqid TEXT NOT NULL,
            mode TEXT,
            reqid TEXT,
            protocol TEXT,
            descr TEXT,
            localid_type TEXT,
            localid_address TEXT,
            localid_netbits TEXT,
            remoteid_type TEXT,
            remoteid_address TEXT,
            remoteid_netbits TEXT,
            lifetime TEXT,
            pfsgroup TEXT,
            encryption_xml TEXT,
            hash_algorithm TEXT,
            raw_xml TEXT,
            migration_status TEXT DEFAULT 'pending',
            UNIQUE(ikeid, uniqid)
        );

        CREATE TABLE IF NOT EXISTS openvpn_servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            vpnid TEXT NOT NULL,
            mode TEXT,
            authmode TEXT,
            protocol TEXT,
            dev_mode TEXT,
            interface TEXT,
            local_port TEXT,
            description TEXT,
            tls TEXT,
            tls_type TEXT,
            caref TEXT,
            certref TEXT,
            dh_length TEXT,
            digest TEXT,
            data_ciphers TEXT,
            data_ciphers_fallback TEXT,
            tunnel_network TEXT,
            tunnel_networkv6 TEXT,
            local_network TEXT,
            local_networkv6 TEXT,
            remote_network TEXT,
            remote_networkv6 TEXT,
            maxclients TEXT,
            compression TEXT,
            topology TEXT,
            raw_xml TEXT,
            migration_status TEXT DEFAULT 'pending',
            UNIQUE(vpnid)
        );

        CREATE TABLE IF NOT EXISTS openvpn_csc (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            common_name TEXT NOT NULL,
            description TEXT,
            server_list TEXT,
            tunnel_network TEXT,
            tunnel_networkv6 TEXT,
            local_network TEXT,
            local_networkv6 TEXT,
            remote_network TEXT,
            remote_networkv6 TEXT,
            block INTEGER DEFAULT 0,
            gwredir INTEGER DEFAULT 0,
            push_reset INTEGER DEFAULT 0,
            raw_xml TEXT,
            migration_status TEXT DEFAULT 'pending',
            UNIQUE(common_name)
        );

        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            refid TEXT NOT NULL,
            descr TEXT,
            crt TEXT,
            prv TEXT,
            serial TEXT,
            raw_xml TEXT,
            migration_status TEXT DEFAULT 'pending',
            UNIQUE(refid)
        );

        CREATE TABLE IF NOT EXISTS certificate_authorities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            refid TEXT NOT NULL,
            descr TEXT,
            crt TEXT,
            prv TEXT,
            serial TEXT,
            raw_xml TEXT,
            migration_status TEXT DEFAULT 'pending',
            UNIQUE(refid)
        );

        CREATE TABLE IF NOT EXISTS syslog_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            raw_xml TEXT,
            migration_status TEXT DEFAULT 'pending'
        );

        CREATE TABLE IF NOT EXISTS snmp_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            syslocation TEXT,
            syscontact TEXT,
            rocommunity TEXT,
            raw_xml TEXT,
            migration_status TEXT DEFAULT 'pending'
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            name TEXT NOT NULL,
            uid TEXT,
            descr TEXT,
            scope TEXT,
            certref TEXT,
            raw_xml TEXT,
            UNIQUE(name)
        );

        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            name TEXT NOT NULL,
            gid TEXT,
            description TEXT,
            scope TEXT,
            members TEXT,
            raw_xml TEXT,
            UNIQUE(name)
        );

        CREATE TABLE IF NOT EXISTS packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            internal_name TEXT NOT NULL,
            name TEXT,
            version TEXT,
            descr TEXT,
            raw_xml TEXT,
            UNIQUE(internal_name)
        );

        CREATE TABLE IF NOT EXISTS filter_separators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            interface TEXT NOT NULL,
            sep_key TEXT NOT NULL,
            row_ref TEXT,
            text TEXT,
            color TEXT,
            raw_xml TEXT,
            UNIQUE(interface, sep_key)
        );

        CREATE TABLE IF NOT EXISTS nat_onetoone (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL REFERENCES imports(id),
            interface TEXT,
            ipprotocol TEXT,
            external TEXT NOT NULL,
            source_type TEXT,
            source_value TEXT,
            destination_type TEXT,
            destination_value TEXT,
            descr TEXT,
            disabled INTEGER DEFAULT 0,
            raw_xml TEXT,
            migration_status TEXT DEFAULT 'pending',
            UNIQUE(external)
        );

        CREATE TABLE IF NOT EXISTS zone_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pfsense_interface TEXT NOT NULL UNIQUE,
            sophos_zone TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS network_alias_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pfsense_value TEXT NOT NULL UNIQUE,
            sophos_object TEXT NOT NULL
        );
    """)

    conn.commit()
    conn.close()


# All data tables that hold imported config items
DATA_TABLES = [
    "interfaces", "firewall_rules", "nat_rules", "nat_onetoone",
    "nat_separators", "nat_outbound", "filter_separators",
    "aliases", "virtual_ips", "gateways", "static_routes",
    "dhcp_config", "dns_host_overrides", "unbound_settings",
    "ipsec_phase1", "ipsec_phase2", "openvpn_servers", "openvpn_csc",
    "certificates", "certificate_authorities",
    "syslog_config", "snmp_config",
    "users", "groups", "packages",
]

# Detail page configuration: which tables get detail pages and what columns to show
DETAIL_TABLES = {
    "interfaces": {
        "label": "Interfaces",
        "columns": [
            ("if_name", "Interface"), ("device", "Device"), ("descr", "Description"),
            ("enable", "Enabled"), ("ipaddr", "IP Address"), ("subnet", "Subnet"), ("gateway", "Gateway"),
        ],
        "has_status": True,
    },
    "firewall_rules": {
        "label": "Firewall Rules",
        "columns": [
            ("interface", "Interface"), ("protocol", "Protocol"),
            ("source_value", "Source"), ("source_port", "Src Port"),
            ("destination_value", "Destination"), ("destination_port", "Dst Port"),
            ("descr", "Description"), ("disabled", "Disabled"),
        ],
        "has_status": True,
    },
    "nat_rules": {
        "label": "NAT Port Forward",
        "columns": [
            ("interface", "Interface"), ("protocol", "Protocol"),
            ("source_value", "Source"), ("destination_value", "Destination"),
            ("destination_port", "Dst Port"), ("target", "Target"), ("local_port", "Local Port"),
            ("descr", "Description"), ("disabled", "Disabled"),
        ],
        "has_status": True,
    },
    "nat_onetoone": {
        "label": "NAT 1:1",
        "columns": [
            ("interface", "Interface"), ("external", "External IP"),
            ("source_value", "Source"), ("destination_value", "Destination"),
            ("descr", "Description"), ("disabled", "Disabled"),
        ],
        "has_status": True,
    },
    "aliases": {
        "label": "Aliases",
        "columns": [
            ("name", "Name"), ("type", "Type"), ("address", "Address"), ("descr", "Description"),
        ],
        "has_status": True,
    },
    "virtual_ips": {
        "label": "Virtual IPs",
        "columns": [
            ("mode", "Mode"), ("interface", "Interface"), ("subnet", "Subnet"),
            ("subnet_bits", "Bits"), ("descr", "Description"),
        ],
        "has_status": True,
    },
    "gateways": {
        "label": "Gateways",
        "columns": [
            ("name", "Name"), ("interface", "Interface"), ("gateway", "Gateway"),
            ("ipprotocol", "Protocol"), ("descr", "Description"),
            ("default_v4", "Default v4"), ("default_v6", "Default v6"),
        ],
        "has_status": True,
    },
    "static_routes": {
        "label": "Static Routes",
        "columns": [
            ("network", "Network"), ("gateway", "Gateway"), ("descr", "Description"),
        ],
        "has_status": True,
    },
    "dhcp_config": {
        "label": "DHCP",
        "columns": [
            ("interface", "Interface"), ("version", "Version"),
            ("range_from", "Range From"), ("range_to", "Range To"),
        ],
        "has_status": True,
    },
    "dns_host_overrides": {
        "label": "DNS Overrides",
        "columns": [
            ("host", "Host"), ("domain", "Domain"), ("ip", "IP Address"), ("descr", "Description"),
        ],
        "has_status": True,
    },
    "ipsec_phase1": {
        "label": "IPsec Phase 1",
        "columns": [
            ("ikeid", "IKE ID"), ("iketype", "Type"), ("mode", "Mode"),
            ("interface", "Interface"), ("remote_gateway", "Remote Gateway"),
            ("descr", "Description"), ("disabled", "Disabled"),
        ],
        "has_status": True,
    },
    "ipsec_phase2": {
        "label": "IPsec Phase 2",
        "columns": [
            ("ikeid", "IKE ID"), ("uniqid", "Unique ID"), ("mode", "Mode"),
            ("descr", "Description"), ("localid_address", "Local"), ("remoteid_address", "Remote"),
        ],
        "has_status": True,
    },
    "openvpn_servers": {
        "label": "OpenVPN Servers",
        "columns": [
            ("vpnid", "VPN ID"), ("mode", "Mode"), ("protocol", "Protocol"),
            ("interface", "Interface"), ("local_port", "Port"),
            ("tunnel_network", "Tunnel Network"), ("description", "Description"),
        ],
        "has_status": True,
    },
    "openvpn_csc": {
        "label": "OpenVPN CSC",
        "columns": [
            ("common_name", "Common Name"), ("description", "Description"),
            ("tunnel_network", "Tunnel Network"), ("local_network", "Local Network"),
        ],
        "has_status": True,
    },
    "certificates": {
        "label": "Certificates",
        "columns": [
            ("refid", "Ref ID"), ("descr", "Description"), ("serial", "Serial"),
        ],
        "has_status": True,
    },
    "certificate_authorities": {
        "label": "Certificate Authorities",
        "columns": [
            ("refid", "Ref ID"), ("descr", "Description"), ("serial", "Serial"),
        ],
        "has_status": True,
    },
    "users": {
        "label": "Users",
        "columns": [
            ("name", "Name"), ("uid", "UID"), ("descr", "Description"), ("scope", "Scope"),
        ],
        "has_status": False,
    },
    "groups": {
        "label": "Groups",
        "columns": [
            ("name", "Name"), ("gid", "GID"), ("description", "Description"), ("scope", "Scope"),
        ],
        "has_status": False,
    },
    "packages": {
        "label": "Packages",
        "columns": [
            ("internal_name", "Internal Name"), ("name", "Name"),
            ("version", "Version"), ("descr", "Description"),
        ],
        "has_status": False,
    },
}


# Tables shown in the summary with display labels
SUMMARY_TABLES = [
    ("interfaces", "Interfaces"),
    ("firewall_rules", "Firewall Rules"),
    ("nat_rules", "NAT Port Forward"),
    ("nat_onetoone", "NAT 1:1"),
    ("aliases", "Aliases"),
    ("virtual_ips", "Virtual IPs"),
    ("gateways", "Gateways"),
    ("static_routes", "Static Routes"),
    ("dhcp_config", "DHCP"),
    ("dns_host_overrides", "DNS Overrides"),
    ("ipsec_phase1", "IPsec Phase 1"),
    ("ipsec_phase2", "IPsec Phase 2"),
    ("openvpn_servers", "OpenVPN Servers"),
    ("openvpn_csc", "OpenVPN CSC"),
    ("certificates", "Certificates"),
    ("certificate_authorities", "Certificate Authorities"),
    ("users", "Users"),
    ("groups", "Groups"),
    ("packages", "Packages"),
]


def get_last_import(db_path):
    """Get the most recent import record, or None."""
    conn = get_db(db_path)
    row = conn.execute(
        "SELECT * FROM imports ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def _upsert_list(cur, table, unique_cols, data_cols, items, import_id):
    """Upsert a list of items into a table. Preserves migration_status on conflict."""
    if not items:
        return 0

    all_cols = ["import_id"] + unique_cols + data_cols
    placeholders = ", ".join("?" for _ in all_cols)
    col_names = ", ".join(all_cols)

    # Build ON CONFLICT update clause (update data_cols + import_id, NOT migration_status)
    update_cols = ["import_id"] + data_cols
    update_set = ", ".join(f"{c}=excluded.{c}" for c in update_cols)
    conflict_cols = ", ".join(unique_cols)

    sql = (
        f"INSERT INTO {table} ({col_names}) VALUES ({placeholders}) "
        f"ON CONFLICT({conflict_cols}) DO UPDATE SET {update_set}"
    )

    count = 0
    for item in items:
        values = [import_id] + [item[c] for c in unique_cols] + [item[c] for c in data_cols]
        cur.execute(sql, values)
        count += 1
    return count


def store_import(db_path, filename, file_hash, parsed_data):
    """Store parsed pfSense data into the database.

    Uses upsert: new items are inserted, existing items (by natural key) are updated.
    migration_status is preserved for existing items.
    Returns the import ID.
    """
    conn = get_db(db_path)
    cur = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    meta = parsed_data["metadata"]

    cur.execute(
        "INSERT INTO imports (filename, file_hash, pfsense_version, hostname, domain, imported_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (filename, file_hash, meta["version"], meta["hostname"], meta["domain"], now),
    )
    import_id = cur.lastrowid
    total = 0

    # Interfaces
    total += _upsert_list(cur, "interfaces",
        ["if_name"],
        ["device", "descr", "enable", "ipaddr", "subnet", "ipaddrv6", "subnetv6",
         "gateway", "gatewayv6", "spoofmac", "blockpriv", "blockbogons",
         "track6_interface", "track6_prefix_id", "media", "mediaopt", "raw_xml"],
        parsed_data["interfaces"], import_id)

    # Firewall rules
    total += _upsert_list(cur, "firewall_rules",
        ["tracker"],
        ["type", "interface", "ipprotocol", "protocol",
         "source_type", "source_value", "source_port", "source_not",
         "destination_type", "destination_value", "destination_port", "destination_not",
         "descr", "disabled", "log", "statetype", "tag", "tagged",
         "associated_rule_id", "created_time", "created_username",
         "updated_time", "updated_username", "raw_xml"],
        parsed_data["firewall_rules"], import_id)

    # NAT rules
    total += _upsert_list(cur, "nat_rules",
        ["associated_rule_id"],
        ["interface", "ipprotocol", "protocol",
         "source_type", "source_value", "source_port",
         "destination_type", "destination_value", "destination_port",
         "target", "local_port", "descr", "disabled",
         "created_time", "created_username", "updated_time", "updated_username", "raw_xml"],
        parsed_data["nat_rules"], import_id)

    # NAT 1:1
    total += _upsert_list(cur, "nat_onetoone",
        ["external"],
        ["interface", "ipprotocol", "source_type", "source_value",
         "destination_type", "destination_value", "descr", "disabled", "raw_xml"],
        parsed_data["nat_onetoone"], import_id)

    # NAT separators
    total += _upsert_list(cur, "nat_separators",
        ["sep_key"],
        ["row_ref", "text", "color", "if_ref", "raw_xml"],
        parsed_data["nat_separators"], import_id)

    # NAT outbound mode
    cur.execute("DELETE FROM nat_outbound")
    cur.execute(
        "INSERT INTO nat_outbound (import_id, mode) VALUES (?, ?)",
        (import_id, parsed_data["nat_outbound_mode"]),
    )

    # Filter separators
    total += _upsert_list(cur, "filter_separators",
        ["interface", "sep_key"],
        ["row_ref", "text", "color", "raw_xml"],
        parsed_data["filter_separators"], import_id)

    # Aliases
    total += _upsert_list(cur, "aliases",
        ["name"],
        ["type", "address", "descr", "detail", "raw_xml"],
        parsed_data["aliases"], import_id)

    # Virtual IPs
    total += _upsert_list(cur, "virtual_ips",
        ["uniqid"],
        ["mode", "interface", "descr", "type", "subnet", "subnet_bits", "raw_xml"],
        parsed_data["virtual_ips"], import_id)

    # Gateways
    total += _upsert_list(cur, "gateways",
        ["name"],
        ["interface", "gateway", "ipprotocol", "weight", "descr",
         "default_v4", "default_v6", "raw_xml"],
        parsed_data["gateways"], import_id)

    # Static routes
    total += _upsert_list(cur, "static_routes",
        ["network", "gateway"],
        ["descr", "raw_xml"],
        parsed_data["static_routes"], import_id)

    # DHCP v4 + v6
    dhcp_items = parsed_data["dhcp_v4"] + parsed_data["dhcp_v6"]
    total += _upsert_list(cur, "dhcp_config",
        ["interface", "version"],
        ["range_from", "range_to", "ramode", "rapriority", "raw_xml"],
        dhcp_items, import_id)

    # DNS host overrides
    total += _upsert_list(cur, "dns_host_overrides",
        ["host", "domain"],
        ["ip", "descr", "aliases_xml", "raw_xml"],
        parsed_data["dns_host_overrides"], import_id)

    # Unbound settings (singleton — replace)
    ub = parsed_data["unbound_settings"]
    if ub:
        cur.execute("DELETE FROM unbound_settings")
        cur.execute(
            "INSERT INTO unbound_settings (import_id, enable, dnssec, active_interface, "
            "outgoing_interface, custom_options, port, sslcertref, system_domain_local_zone_type, raw_xml) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (import_id, ub["enable"], ub["dnssec"], ub["active_interface"],
             ub["outgoing_interface"], ub["custom_options"], ub["port"],
             ub["sslcertref"], ub["system_domain_local_zone_type"], ub["raw_xml"]),
        )

    # IPsec phase 1
    total += _upsert_list(cur, "ipsec_phase1",
        ["ikeid"],
        ["iketype", "mode", "interface", "remote_gateway", "protocol",
         "authentication_method", "pre_shared_key", "descr", "disabled",
         "nat_traversal", "dpd_delay", "dpd_maxfail", "lifetime", "encryption_xml", "raw_xml"],
        parsed_data["ipsec_phase1"], import_id)

    # IPsec phase 2
    total += _upsert_list(cur, "ipsec_phase2",
        ["ikeid", "uniqid"],
        ["mode", "reqid", "protocol", "descr",
         "localid_type", "localid_address", "localid_netbits",
         "remoteid_type", "remoteid_address", "remoteid_netbits",
         "lifetime", "pfsgroup", "encryption_xml", "hash_algorithm", "raw_xml"],
        parsed_data["ipsec_phase2"], import_id)

    # OpenVPN servers
    total += _upsert_list(cur, "openvpn_servers",
        ["vpnid"],
        ["mode", "authmode", "protocol", "dev_mode", "interface", "local_port",
         "description", "tls", "tls_type", "caref", "certref", "dh_length", "digest",
         "data_ciphers", "data_ciphers_fallback",
         "tunnel_network", "tunnel_networkv6", "local_network", "local_networkv6",
         "remote_network", "remote_networkv6", "maxclients", "compression", "topology", "raw_xml"],
        parsed_data["openvpn_servers"], import_id)

    # OpenVPN CSC
    total += _upsert_list(cur, "openvpn_csc",
        ["common_name"],
        ["description", "server_list", "tunnel_network", "tunnel_networkv6",
         "local_network", "local_networkv6", "remote_network", "remote_networkv6",
         "block", "gwredir", "push_reset", "raw_xml"],
        parsed_data["openvpn_csc"], import_id)

    # Certificates
    total += _upsert_list(cur, "certificates",
        ["refid"],
        ["descr", "crt", "prv", "serial", "raw_xml"],
        parsed_data["certificates"], import_id)

    # Certificate Authorities
    total += _upsert_list(cur, "certificate_authorities",
        ["refid"],
        ["descr", "crt", "prv", "serial", "raw_xml"],
        parsed_data["cas"], import_id)

    # Syslog (singleton — replace)
    sl = parsed_data["syslog"]
    if sl:
        cur.execute("DELETE FROM syslog_config")
        cur.execute(
            "INSERT INTO syslog_config (import_id, raw_xml) VALUES (?, ?)",
            (import_id, sl["raw_xml"]),
        )

    # SNMP (singleton — replace)
    snmp = parsed_data["snmp"]
    if snmp:
        cur.execute("DELETE FROM snmp_config")
        cur.execute(
            "INSERT INTO snmp_config (import_id, syslocation, syscontact, rocommunity, raw_xml) "
            "VALUES (?, ?, ?, ?, ?)",
            (import_id, snmp["syslocation"], snmp["syscontact"], snmp["rocommunity"], snmp["raw_xml"]),
        )

    # Users
    total += _upsert_list(cur, "users",
        ["name"],
        ["uid", "descr", "scope", "certref", "raw_xml"],
        parsed_data["users"], import_id)

    # Groups
    total += _upsert_list(cur, "groups",
        ["name"],
        ["gid", "description", "scope", "members", "raw_xml"],
        parsed_data["groups"], import_id)

    # Packages
    total += _upsert_list(cur, "packages",
        ["internal_name"],
        ["name", "version", "descr", "raw_xml"],
        parsed_data["packages"], import_id)

    # Update total item count
    cur.execute("UPDATE imports SET item_count = ? WHERE id = ?", (total, import_id))

    conn.commit()
    conn.close()
    return import_id


def get_import_summary(db_path):
    """Get summary of the current import state.

    Returns dict with import metadata and per-table counts, or None if no imports.
    """
    last = get_last_import(db_path)
    if not last:
        return None

    conn = get_db(db_path)
    counts = []
    total = 0
    for table, label in SUMMARY_TABLES:
        row = conn.execute(f"SELECT COUNT(*) as cnt FROM {table}").fetchone()
        count = row["cnt"]
        counts.append({"table": table, "label": label, "count": count})
        total += count
    conn.close()

    return {
        "import": last,
        "counts": counts,
        "total": total,
    }


def get_table_items(db_path, table_name):
    """Get all items from a specific table.

    Validates table_name against DETAIL_TABLES to prevent SQL injection.
    Returns list of dicts, or empty list if table_name is invalid.
    """
    if table_name not in DETAIL_TABLES:
        return []
    conn = get_db(db_path)
    rows = conn.execute(f"SELECT * FROM {table_name}").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_import_summary_with_status(db_path):
    """Get summary with per-table migration status breakdown.

    Extends get_import_summary with status counts per table.
    Returns None if no imports exist.
    """
    last = get_last_import(db_path)
    if not last:
        return None

    conn = get_db(db_path)
    counts = []
    total = 0
    for table, label in SUMMARY_TABLES:
        row = conn.execute(f"SELECT COUNT(*) as cnt FROM {table}").fetchone()
        count = row["cnt"]

        statuses = {}
        has_status = DETAIL_TABLES.get(table, {}).get("has_status", False)
        if has_status and count > 0:
            status_rows = conn.execute(
                f"SELECT migration_status, COUNT(*) as cnt FROM {table} GROUP BY migration_status"
            ).fetchall()
            for sr in status_rows:
                statuses[sr["migration_status"]] = sr["cnt"]

        counts.append({
            "table": table,
            "label": label,
            "count": count,
            "has_status": has_status,
            "statuses": statuses,
        })
        total += count
    conn.close()

    return {
        "import": last,
        "counts": counts,
        "total": total,
    }


VALID_STATUSES = ("pending", "migrated", "skipped", "failed")


def update_migration_status(db_path, table_name, item_ids, status):
    """Update migration_status for specific items in a table.

    Validates table_name against DETAIL_TABLES (has_status=True) and status
    against VALID_STATUSES to prevent SQL injection and invalid data.
    Returns number of rows updated.
    """
    config = DETAIL_TABLES.get(table_name)
    if not config or not config.get("has_status"):
        return 0
    if status not in VALID_STATUSES:
        return 0
    if not item_ids:
        return 0

    conn = get_db(db_path)
    placeholders = ", ".join("?" for _ in item_ids)
    cur = conn.execute(
        f"UPDATE {table_name} SET migration_status = ? WHERE id IN ({placeholders})",
        [status] + list(item_ids),
    )
    conn.commit()
    updated = cur.rowcount
    conn.close()
    return updated


def get_aliases_by_ids(db_path, alias_ids):
    """Fetch specific alias rows by ID list. Returns list of dicts."""
    if not alias_ids:
        return []
    conn = get_db(db_path)
    placeholders = ", ".join("?" for _ in alias_ids)
    rows = conn.execute(
        f"SELECT * FROM aliases WHERE id IN ({placeholders})",
        list(alias_ids),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_firewall_rules_by_ids(db_path, rule_ids):
    """Fetch specific firewall rule rows by ID list. Returns list of dicts."""
    if not rule_ids:
        return []
    conn = get_db(db_path)
    placeholders = ", ".join("?" for _ in rule_ids)
    rows = conn.execute(
        f"SELECT * FROM firewall_rules WHERE id IN ({placeholders})",
        list(rule_ids),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_nat_rules_by_ids(db_path, rule_ids):
    """Fetch specific NAT rule rows by ID list. Returns list of dicts."""
    if not rule_ids:
        return []
    conn = get_db(db_path)
    placeholders = ", ".join("?" for _ in rule_ids)
    rows = conn.execute(
        f"SELECT * FROM nat_rules WHERE id IN ({placeholders})",
        list(rule_ids),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_nat_destination_lookup(db_path):
    """Build lookup: associated_rule_id → NAT destination_value.

    Used to show the public IP from linked NAT rules in the firewall rules table
    and auto-fill it as Sophos Dst Network during migration.

    Returns:
        dict: {associated_rule_id: destination_value}
    """
    conn = get_db(db_path)
    rows = conn.execute(
        "SELECT associated_rule_id, destination_value FROM nat_rules "
        "WHERE destination_value IS NOT NULL AND destination_value != ''"
    ).fetchall()
    conn.close()
    return {r["associated_rule_id"]: r["destination_value"] for r in rows}


def get_zone_mappings(db_path):
    """Get all zone mappings. Returns list of dicts."""
    conn = get_db(db_path)
    rows = conn.execute("SELECT * FROM zone_mappings ORDER BY pfsense_interface").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_zone_mapping(db_path, pfsense_interface, sophos_zone):
    """Save or update a zone mapping. Returns the row id."""
    conn = get_db(db_path)
    cur = conn.execute(
        "INSERT INTO zone_mappings (pfsense_interface, sophos_zone) VALUES (?, ?) "
        "ON CONFLICT(pfsense_interface) DO UPDATE SET sophos_zone=excluded.sophos_zone",
        (pfsense_interface, sophos_zone),
    )
    conn.commit()
    row_id = cur.lastrowid
    conn.close()
    return row_id


def delete_zone_mapping(db_path, mapping_id):
    """Delete a zone mapping by ID. Returns number of rows deleted."""
    conn = get_db(db_path)
    cur = conn.execute("DELETE FROM zone_mappings WHERE id = ?", (mapping_id,))
    conn.commit()
    deleted = cur.rowcount
    conn.close()
    return deleted


def get_network_alias_mappings(db_path):
    """Get all network alias mappings. Returns list of dicts."""
    conn = get_db(db_path)
    rows = conn.execute("SELECT * FROM network_alias_mappings ORDER BY pfsense_value").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_network_alias_mapping(db_path, pfsense_value, sophos_object):
    """Save or update a network alias mapping. Returns the row id."""
    conn = get_db(db_path)
    cur = conn.execute(
        "INSERT INTO network_alias_mappings (pfsense_value, sophos_object) VALUES (?, ?) "
        "ON CONFLICT(pfsense_value) DO UPDATE SET sophos_object=excluded.sophos_object",
        (pfsense_value, sophos_object),
    )
    conn.commit()
    row_id = cur.lastrowid
    conn.close()
    return row_id


def delete_network_alias_mapping(db_path, mapping_id):
    """Delete a network alias mapping by ID. Returns number of rows deleted."""
    conn = get_db(db_path)
    cur = conn.execute("DELETE FROM network_alias_mappings WHERE id = ?", (mapping_id,))
    conn.commit()
    deleted = cur.rowcount
    conn.close()
    return deleted


def cleanup_all(db_path, upload_folder):
    """Delete all imported data, imports log, and uploaded files."""
    conn = get_db(db_path)
    cur = conn.cursor()

    for table in DATA_TABLES:
        cur.execute(f"DELETE FROM {table}")
    cur.execute("DELETE FROM imports")

    conn.commit()
    conn.close()

    # Remove uploaded files
    for f in globmod.glob(os.path.join(upload_folder, "*.xml")):
        os.remove(f)
