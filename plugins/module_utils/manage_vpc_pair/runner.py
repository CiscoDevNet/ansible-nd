# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami S <sivakasi@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


from typing import Any, Dict

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.enums import (
    VpcFieldNames,
)


def run_vpc_module(nrm: Any) -> Dict[str, Any]:
    """
    Run VPC module state machine with VPC-specific gathered output.

    Top-level state router. For gathered: builds read-only output filtering out
    pending-delete pairs. Otherwise delegates to nrm.manage_state().

    Args:
        nrm: VpcPairStateMachine instance

    Returns:
        Dict with module result including current, gathered, before, after,
        changed, created, deleted, updated keys.
    """
    state = nrm.module.params.get("state", "merged")
    config = nrm.module.params.get("config", [])

    if state == "gathered":
        nrm.add_logs_and_outputs()
        nrm.result["changed"] = False

        current_pairs = nrm.result.get("current", []) or []
        pending_delete = nrm.module.params.get("_pending_delete", []) or []

        # Exclude pairs in pending-delete from active gathered set.
        pending_delete_keys = set()
        for pair in pending_delete:
            switch_id = pair.get(VpcFieldNames.SWITCH_ID) or pair.get("switch_id")
            peer_switch_id = pair.get(VpcFieldNames.PEER_SWITCH_ID) or pair.get("peer_switch_id")
            if switch_id and peer_switch_id:
                pending_delete_keys.add(tuple(sorted([switch_id, peer_switch_id])))

        filtered_current = []
        for pair in current_pairs:
            switch_id = pair.get(VpcFieldNames.SWITCH_ID) or pair.get("switch_id")
            peer_switch_id = pair.get(VpcFieldNames.PEER_SWITCH_ID) or pair.get("peer_switch_id")
            if switch_id and peer_switch_id:
                pair_key = tuple(sorted([switch_id, peer_switch_id]))
                if pair_key in pending_delete_keys:
                    continue
            filtered_current.append(pair)

        nrm.result["current"] = filtered_current
        nrm.result["gathered"] = {
            "vpc_pairs": filtered_current,
            "pending_delete_vpc_pairs": pending_delete,
        }
        return nrm.result

    if state in ("deleted", "overridden") and not config:
        module = nrm.module
        module.fail_json(
            msg="Config parameter is required for state '%s'. "
            "Specify the vPC pair(s) to %s using the config parameter." % (state, "delete" if state == "deleted" else "override"),
        )

    nrm.manage_state(state=state, new_configs=config)
    nrm.add_logs_and_outputs()
    return nrm.result


# ===== Module Entry Point =====
