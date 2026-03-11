# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat Chengam Saravanan (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or
# https://www.gnu.org/licenses/gpl-3.0.txt)

"""Bootstrap API helpers for POAP switch queries, serial-number indexing, and payload construction."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
from typing import Any, Dict, List, Optional

from ...endpoints.v1.nd_manage_switches.manage_fabric_bootstrap import (
    V1ManageFabricBootstrapGet,
)


def query_bootstrap_switches(
    nd,
    fabric: str,
    log: logging.Logger,
) -> List[Dict[str, Any]]:
    """GET switches currently in the bootstrap (POAP / PnP) loop.

    Args:
        nd:     NDModule instance (REST client).
        fabric: Fabric name.
        log:    Logger.

    Returns:
        List of raw switch dicts from the bootstrap API.
    """
    log.debug("ENTER: query_bootstrap_switches()")

    endpoint = V1ManageFabricBootstrapGet()
    endpoint.fabric_name = fabric
    log.debug(f"Bootstrap endpoint: {endpoint.path}")

    try:
        result = nd.request(
            path=endpoint.path, verb=endpoint.verb,
        )
    except Exception as e:
        msg = (
            f"Failed to query bootstrap switches for "
            f"fabric '{fabric}': {e}"
        )
        log.error(msg)
        nd.module.fail_json(msg=msg)

    if isinstance(result, dict):
        switches = result.get("switches", [])
    elif isinstance(result, list):
        switches = result
    else:
        switches = []

    log.info(
        f"Bootstrap API returned {len(switches)} "
        f"switch(es) in POAP loop"
    )
    log.debug("EXIT: query_bootstrap_switches()")
    return switches


def build_bootstrap_index(
    bootstrap_switches: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """Build a serial-number-keyed index from bootstrap API data.

    Args:
        bootstrap_switches: Raw switch dicts from the bootstrap API.

    Returns:
        Dict mapping ``serial_number`` -> switch dict.
    """
    return {
        sw.get("serialNumber", sw.get("serial_number", "")): sw
        for sw in bootstrap_switches
    }


def build_poap_data_block(poap_cfg) -> Optional[Dict[str, Any]]:
    """Build optional data block for bootstrap and pre-provision models.

    Args:
        poap_cfg: ``POAPConfigModel`` from the user playbook.

    Returns:
        Data block dict, or ``None`` if no ``config_data`` is present.
    """
    if not poap_cfg.config_data:
        return None
    data_block: Dict[str, Any] = {}
    gateway = poap_cfg.config_data.gateway
    if gateway:
        data_block["gatewayIpMask"] = gateway
    if poap_cfg.config_data.models:
        data_block["models"] = poap_cfg.config_data.models
    return data_block or None


__all__ = [
    "query_bootstrap_switches",
    "build_bootstrap_index",
    "build_poap_data_block",
]
