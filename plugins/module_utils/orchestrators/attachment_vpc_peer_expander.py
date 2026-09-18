# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Shared vPC peer expansion helpers for attachment payload planning."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any


def expand_desired_attachments_with_vpc_peers(
    desired: dict[tuple[str, str], dict[str, Any]],
    attachment_details: Iterable[Any] | None,
    resource_name_field: str,
    peer_payload_mutator: Callable[[dict[str, Any]], None] | None = None,
) -> dict[tuple[str, str], dict[str, Any]]:
    """
    # Summary

    Add missing vPC peer attachment payloads from attachment-query metadata.

    Args:
        desired: Desired attachment payloads keyed by ``(resource_name, switch_id)``.
        attachment_details: Raw attachment-query rows containing ``peerSwitchId`` metadata.
        resource_name_field: API field that identifies the attached resource name.
        peer_payload_mutator: Optional callback for resource-specific peer payload cleanup.

    Returns:
        Desired attachment payloads plus any missing vPC peer payloads.
    """
    if not desired or not attachment_details:
        return desired

    detail_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for attachment in attachment_details:
        if not isinstance(attachment, dict):
            continue
        resource_name = attachment.get(resource_name_field)
        switch_id = attachment.get("switchId")
        if resource_name and switch_id:
            detail_by_key[(resource_name, switch_id)] = attachment

    expanded = dict(desired)
    for key, payload in list(desired.items()):
        detail = detail_by_key.get(key)
        peer_switch_id = detail.get("peerSwitchId") if detail else None
        if not peer_switch_id:
            continue

        peer_key = (key[0], peer_switch_id)
        if peer_key in expanded:
            continue

        peer_payload = dict(payload)
        peer_payload["switchId"] = peer_switch_id
        if peer_payload_mutator is not None:
            peer_payload_mutator(peer_payload)
        expanded[peer_key] = peer_payload

    return expanded
