# -*- coding: utf-8 -*-

"""Pydantic models for Nexus Dashboard Manage network APIs."""

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.config_models import (
    NetworkAttachmentConfigModel,
    NetworkChildConfigModel,
    NetworkConfigModel,
    NetworkInterfaceConfigModel,
    NetworkParentConfigModel,
    NetworkTorPortConfigModel,
)

__all__ = [
    "NetworkAttachmentConfigModel",
    "NetworkChildConfigModel",
    "NetworkConfigModel",
    "NetworkInterfaceConfigModel",
    "NetworkParentConfigModel",
    "NetworkTorPortConfigModel",
]
