# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Any
from ansible.plugins.action import ActionBase
from ansible.utils.display import Display

display = Display()


def _as_bool(value: Any, default: bool) -> bool:
    """Parse bool-like values from task args with a sane default."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("true", "1", "yes", "on"):
            return True
        if normalized in ("false", "0", "no", "off"):
            return False
    return bool(value)


def _normalize_pair(pair: dict[str, Any]) -> frozenset[str]:
    """Return a frozenset key of (switch_id, peer_switch_id) so order does not matter."""
    s1 = pair.get("switchId") or pair.get("switch_id") or pair.get("peer1_switch_id", "")
    s2 = pair.get("peerSwitchId") or pair.get("peer_switch_id") or pair.get("peer2_switch_id", "")
    return frozenset([s1.strip(), s2.strip()])


def _get_virtual_peer_link(pair: dict[str, Any]) -> Any | None:
    """Extract the use_virtual_peer_link / useVirtualPeerLink value from a pair dict."""
    for key in ("useVirtualPeerLink", "use_virtual_peer_link"):
        if key in pair:
            return pair[key]
    return None


def _get_vpc_pair_details(pair: dict[str, Any]) -> dict[str, Any] | None:
    """Extract vpc_pair_details / vpcPairDetails from a pair dict."""
    for key in ("vpc_pair_details", "vpcPairDetails"):
        if key in pair:
            return pair[key]
    return None


def _coerce_scalar(value: Any) -> Any:
    """Normalize scalar value types for stable comparisons across API/model formats."""
    if isinstance(value, str):
        text = value.strip()
        lower = text.lower()
        if lower in ("true", "false"):
            return lower == "true"
        if text.isdigit() or (text.startswith("-") and text[1:].isdigit()):
            try:
                return int(text)
            except Exception:
                return text
        return text
    return value


def _values_equal(expected: Any, actual: Any) -> bool:
    """Compare values with lightweight normalization for bool/int/string drift."""
    if isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            return False
        return all(_values_equal(e, a) for e, a in zip(expected, actual))
    return _coerce_scalar(expected) == _coerce_scalar(actual)


def _detail_value_with_alias(details: dict[str, Any], key: str) -> tuple[Any, str | None]:
    """
    Fetch detail value supporting snake_case/camelCase alias forms.
    Returns tuple(value, resolved_key). value is None if not found.
    """
    aliases = {
        "type": ["type"],
        "domain_id": ["domain_id", "domainId"],
        "switch_keep_alive_local_ip": ["switch_keep_alive_local_ip", "switchKeepAliveLocalIp"],
        "peer_switch_keep_alive_local_ip": ["peer_switch_keep_alive_local_ip", "peerSwitchKeepAliveLocalIp"],
        "keep_alive_vrf": ["keep_alive_vrf", "keepAliveVrf"],
        "template_name": ["template_name", "templateName"],
        "template_config": ["template_config", "templateConfig"],
    }
    for alias in aliases.get(key, [key]):
        if alias in details:
            return details.get(alias), alias
    return None, None


def _mismatch(field: str, expected: Any, actual: Any) -> dict[str, Any]:
    """Build a normalized mismatch record."""
    return {"field": field, "expected": expected, "actual": actual}


def _compare_nested_details(
    mismatches: list[dict[str, Any]],
    parent_field: str,
    expected: dict[str, Any],
    actual: dict[str, Any],
) -> None:
    """Compare nested expected detail keys against actual and append mismatches."""
    for nested_key, nested_expected in expected.items():
        nested_actual = actual.get(nested_key)
        if nested_key not in actual:
            mismatches.append(_mismatch(f"{parent_field}.{nested_key}", nested_expected, "MISSING"))
            continue

        if not _values_equal(nested_expected, nested_actual):
            mismatches.append(_mismatch(f"{parent_field}.{nested_key}", nested_expected, nested_actual))


def _compare_vpc_pair_details(expected_details: Any, actual_details: Any) -> list[dict[str, Any]]:
    """Compare expected details as a subset of actual details and return mismatches."""
    mismatches: list[dict[str, Any]] = []

    if not isinstance(expected_details, dict):
        return mismatches

    if not isinstance(actual_details, dict):
        return [_mismatch("vpc_pair_details", expected_details, actual_details)]

    for exp_key, exp_value in expected_details.items():
        act_value, resolved_key = _detail_value_with_alias(actual_details, exp_key)
        field = "vpc_pair_details.{0}".format(exp_key)
        if resolved_key is None:
            mismatches.append(_mismatch(field, exp_value, "MISSING"))
            continue

        if isinstance(exp_value, dict):
            if not isinstance(act_value, dict):
                mismatches.append(_mismatch(field, exp_value, act_value))
                continue

            _compare_nested_details(mismatches, field, exp_value, act_value)
        else:
            if not _values_equal(exp_value, act_value):
                mismatches.append(_mismatch(field, exp_value, act_value))

    return mismatches


class ActionModule(ActionBase):
    """Ansible action plugin that validates nd_vpc_pair gathered output against expected test data.

    Usage in a playbook task::

        - name: Validate vPC pairs
          cisco.nd.tests.integration.nd_vpc_pair_validate:
            gathered_data: "{{ gathered_result }}"
            expected_data: "{{ expected_conf }}"
            changed: "{{ result.changed }}"
            mode: "full"          # full | count_only | exists

    Parameters
    ----------
    gathered_data : dict
        The full register output of a ``cisco.nd.nd_manage_vpc_pair`` task with ``state: gathered``.
        Must contain ``gathered.vpc_pairs`` (list).
    expected_data : list
        List of dicts with expected vPC pair config.  Each dict should have at least
        ``peer1_switch_id`` / ``peer2_switch_id`` (playbook-style keys).
        API-style keys (``switchId`` / ``peerSwitchId``) are also accepted.
    changed : bool, optional
        If provided the plugin asserts that the previous action reported ``changed``.
    mode : str, optional
        ``full``       – (default) match count **and** per-pair field values.
        ``count_only`` – only verify the number of pairs matches.
        ``exists``     – verify that every expected pair exists (extra pairs OK).
    validate_vpc_pair_details : bool, optional
        ``true`` (default) validates expected ``vpc_pair_details`` as subset of gathered
        details for each matched pair. Set to ``false`` to skip details validation.
    """

    VALID_MODES = frozenset(["full", "count_only", "exists"])

    def run(self, tmp: Any = None, task_vars: dict[str, Any] | None = None) -> dict[str, Any]:
        results = super(ActionModule, self).run(tmp, task_vars)
        results["failed"] = False

        # ------------------------------------------------------------------
        # Extract arguments
        # ------------------------------------------------------------------
        gathered_data = self._task.args.get("gathered_data")
        expected_data = self._task.args.get("expected_data")
        changed = self._task.args.get("changed")
        mode = self._task.args.get("mode", "full").lower()
        validate_vpc_pair_details = _as_bool(self._task.args.get("validate_vpc_pair_details"), True)

        if mode not in self.VALID_MODES:
            results["failed"] = True
            results["msg"] = "Invalid mode '{0}'. Choose from: {1}".format(mode, ", ".join(sorted(self.VALID_MODES)))
            return results

        # ------------------------------------------------------------------
        # Validate 'changed' flag if provided
        # ------------------------------------------------------------------
        if changed is not None:
            # Accept bool or string representation
            if isinstance(changed, str):
                changed = changed.strip().lower() in ("true", "1", "yes")
            if not changed:
                results["failed"] = True
                results["msg"] = "Preceding task reported changed=false but expected a change."
                return results

        # ------------------------------------------------------------------
        # Unwrap gathered data
        # ------------------------------------------------------------------
        if gathered_data is None:
            results["failed"] = True
            results["msg"] = "gathered_data is required."
            return results

        if isinstance(gathered_data, dict):
            # Could be the full register dict or just the gathered sub-dict
            vpc_pairs = gathered_data.get("gathered", {}).get("vpc_pairs") or gathered_data.get("vpc_pairs")
        else:
            results["failed"] = True
            results["msg"] = "gathered_data must be a dict (register output or gathered sub-dict)."
            return results

        if vpc_pairs is None:
            vpc_pairs = []

        # ------------------------------------------------------------------
        # Normalise expected data
        # ------------------------------------------------------------------
        if expected_data is None:
            expected_data = []
        if not isinstance(expected_data, list):
            results["failed"] = True
            results["msg"] = "expected_data must be a list of vpc pair dicts."
            return results

        # ------------------------------------------------------------------
        # Count check
        # ------------------------------------------------------------------
        if mode in ("full", "count_only"):
            if len(vpc_pairs) != len(expected_data):
                results["failed"] = True
                results["msg"] = "Pair count mismatch: gathered {0} pair(s) but expected {1}.".format(len(vpc_pairs), len(expected_data))
                results["gathered_count"] = len(vpc_pairs)
                results["expected_count"] = len(expected_data)
                return results

        if mode == "count_only":
            results["msg"] = "Validation successful (count_only): {0} pair(s).".format(len(vpc_pairs))
            return results

        # ------------------------------------------------------------------
        # Build lookup of gathered pairs keyed by normalised pair key
        # ------------------------------------------------------------------
        gathered_by_key = {}
        for pair in vpc_pairs:
            key = _normalize_pair(pair)
            gathered_by_key[key] = pair

        # ------------------------------------------------------------------
        # Match each expected pair
        # ------------------------------------------------------------------
        missing_pairs = []
        field_mismatches = []

        for expected in expected_data:
            key = _normalize_pair(expected)
            gathered_pair = gathered_by_key.get(key)

            if gathered_pair is None:
                missing_pairs.append(
                    {
                        "peer1": expected.get("peer1_switch_id") or expected.get("switchId", "?"),
                        "peer2": expected.get("peer2_switch_id") or expected.get("peerSwitchId", "?"),
                    }
                )
                continue

            # Field-level comparison (only in full mode)
            if mode == "full":
                expected_vpl = _get_virtual_peer_link(expected)
                gathered_vpl = _get_virtual_peer_link(gathered_pair)
                if expected_vpl is not None and gathered_vpl is not None:
                    # Normalise to bool
                    if isinstance(expected_vpl, str):
                        expected_vpl = expected_vpl.lower() in ("true", "1", "yes")
                    if isinstance(gathered_vpl, str):
                        gathered_vpl = gathered_vpl.lower() in ("true", "1", "yes")
                    if bool(expected_vpl) != bool(gathered_vpl):
                        field_mismatches.append(
                            {
                                "pair": "{0}-{1}".format(
                                    expected.get("peer1_switch_id") or expected.get("switchId", "?"),
                                    expected.get("peer2_switch_id") or expected.get("peerSwitchId", "?"),
                                ),
                                "field": "use_virtual_peer_link",
                                "expected": bool(expected_vpl),
                                "actual": bool(gathered_vpl),
                            }
                        )

                if validate_vpc_pair_details:
                    expected_details = _get_vpc_pair_details(expected)
                    gathered_details = _get_vpc_pair_details(gathered_pair)
                    if expected_details is not None:
                        details_mismatches = _compare_vpc_pair_details(expected_details, gathered_details)
                        for item in details_mismatches:
                            field_mismatches.append(
                                {
                                    "pair": "{0}-{1}".format(
                                        expected.get("peer1_switch_id") or expected.get("switchId", "?"),
                                        expected.get("peer2_switch_id") or expected.get("peerSwitchId", "?"),
                                    ),
                                    "field": item.get("field"),
                                    "expected": item.get("expected"),
                                    "actual": item.get("actual"),
                                }
                            )

        # ------------------------------------------------------------------
        # Compose result
        # ------------------------------------------------------------------
        if missing_pairs or field_mismatches:
            results["failed"] = True
            parts = []
            if missing_pairs:
                parts.append("Missing pairs: {0}".format(missing_pairs))
            if field_mismatches:
                parts.append("Field mismatches: {0}".format(field_mismatches))
            results["msg"] = "Validation failed. " + "; ".join(parts)
            results["missing_pairs"] = missing_pairs
            results["field_mismatches"] = field_mismatches
        else:
            results["msg"] = "Validation successful: {0} pair(s) verified ({1} mode).".format(len(expected_data), mode)

        return results
