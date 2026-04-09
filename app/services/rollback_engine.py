"""Rollback engine for removing migrated Sophos objects."""

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Deletion order: groups/rules first (release references), then members
_TYPE_ORDER = {
    "FirewallRule": 0,
    "NATRule": 0,
    "IPHostGroup": 1,
    "ServiceGroup": 1,
    "IPHost": 2,
    "FQDNHost": 2,
    "Service": 2,
}


@dataclass
class RollbackPlan:
    source_table: str
    source_id: int
    item_name: str
    primary_objects: list = field(default_factory=list)   # non-member objects
    member_objects: list = field(default_factory=list)     # child/member objects
    warnings: list = field(default_factory=list)


@dataclass
class RollbackResult:
    source_id: int
    success: bool
    objects_deleted: list = field(default_factory=list)
    objects_failed: list = field(default_factory=list)     # list of (name, error)
    error: str = None


def plan_rollback(db_path, source_table, source_ids, item_names, cascade=False):
    """Build rollback plans for the given source items.

    Args:
        db_path: Database path
        source_table: 'aliases', 'firewall_rules', or 'nat_rules'
        source_ids: List of source item IDs
        item_names: Dict mapping source_id -> display name
        cascade: If True, include member objects in deletion

    Returns:
        List of RollbackPlan
    """
    from app.models.database import get_sophos_objects_for_items

    objects_by_item = get_sophos_objects_for_items(db_path, source_table, source_ids)
    plans = []

    for source_id in source_ids:
        name = item_names.get(source_id, f"item_{source_id}")
        sophos_objs = objects_by_item.get(source_id, [])

        plan = RollbackPlan(
            source_table=source_table,
            source_id=source_id,
            item_name=name,
        )

        if not sophos_objs:
            plan.warnings.append("No tracked Sophos objects found for this item")
            plans.append(plan)
            continue

        for obj in sophos_objs:
            entry = {
                "sophos_object_id": obj["id"],
                "sophos_name": obj["sophos_name"],
                "sophos_type": obj["sophos_type"],
            }
            if obj["is_member"]:
                plan.member_objects.append(entry)
            else:
                plan.primary_objects.append(entry)

        # Sort by deletion order: groups/rules first, then members
        plan.primary_objects.sort(key=lambda o: _TYPE_ORDER.get(o["sophos_type"], 5))
        plan.member_objects.sort(key=lambda o: _TYPE_ORDER.get(o["sophos_type"], 5))

        if not cascade and plan.member_objects:
            plan.warnings.append(
                f"{len(plan.member_objects)} dependent object(s) will NOT be deleted "
                "(enable cascade to include them)"
            )

        plans.append(plan)

    return plans


def plan_to_dict(plan):
    """Serialize a RollbackPlan to a JSON-safe dict."""
    return {
        "source_table": plan.source_table,
        "source_id": plan.source_id,
        "item_name": plan.item_name,
        "primary_objects": plan.primary_objects,
        "member_objects": plan.member_objects,
        "warnings": plan.warnings,
        "total_objects": len(plan.primary_objects) + len(plan.member_objects),
    }


def execute_rollback(app_config, plan, db_path, cascade=False):
    """Execute a rollback plan: delete Sophos objects and clean up tracking.

    Args:
        app_config: Flask app config dict
        plan: RollbackPlan instance
        db_path: Database path
        cascade: If True, also delete member objects

    Yields:
        (sophos_name, sophos_type, success, error_msg) for each deletion attempt
    """
    from app.services.sophos_client import remove_object
    from app.models.database import delete_sophos_object_rows

    # Build ordered list: primary objects first, then members if cascade
    objects_to_delete = list(plan.primary_objects)
    if cascade:
        objects_to_delete.extend(plan.member_objects)

    for obj in objects_to_delete:
        sophos_name = obj["sophos_name"]
        sophos_type = obj["sophos_type"]
        sophos_object_id = obj["sophos_object_id"]

        success, error = remove_object(app_config, sophos_type, sophos_name)

        if success:
            delete_sophos_object_rows(db_path, [sophos_object_id])
            logger.info("Rolled back %s: %s", sophos_type, sophos_name)
        else:
            logger.warning("Failed to rollback %s '%s': %s",
                           sophos_type, sophos_name, error)

        yield sophos_name, sophos_type, success, error
