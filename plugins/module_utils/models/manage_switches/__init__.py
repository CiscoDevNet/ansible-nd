# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""nd_manage_switches models package.

Re-exports all model classes, enums, and validators from their individual
modules so that consumers can import directly from the package:

    from .models.nd_manage_switches import SwitchConfigModel, SwitchRole, ...
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

# --- Enums ---
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.enums import (  # noqa: F401
    AdvisoryLevel,
    AnomalyLevel,
    ConfigSyncStatus,
    DiscoveryStatus,
    PlatformType,
    RemoteCredentialStore,
    SnmpV3AuthProtocol,
    SwitchRole,
    SystemMode,
    VpcRole,
)

# --- Validators ---
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.validators import SwitchValidators  # noqa: F401

# --- Nested / shared models ---
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.switch_data_models import (  # noqa: F401
    AdditionalAciSwitchData,
    AdditionalSwitchData,
    Metadata,
    SwitchMetadata,
    TelemetryIpCollection,
    VpcData,
)

# --- Discovery models ---
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.discovery_models import (  # noqa: F401
    AddSwitchesRequestModel,
    ShallowDiscoveryRequestModel,
    SwitchDiscoveryModel,
)

# --- Switch data models ---
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.switch_data_models import (  # noqa: F401
    SwitchDataModel,
)

# --- Bootstrap models ---
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.bootstrap_models import (  # noqa: F401
    BootstrapBaseData,
    BootstrapBaseModel,
    BootstrapCredentialModel,
    BootstrapImportSpecificModel,
    BootstrapImportSwitchModel,
    ImportBootstrapSwitchesRequestModel,
)

# --- Preprovision models ---
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.preprovision_models import (  # noqa: F401
    PreProvisionSwitchesRequestModel,
    PreProvisionSwitchModel,
)

# --- RMA models ---
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.rma_models import (  # noqa: F401
    RMASwitchModel,
)

# --- Switch actions models ---
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.switch_actions_models import (  # noqa: F401
    ChangeSwitchSerialNumberRequestModel,
    SwitchCredentialsRequestModel,
)

# --- Config / playbook models ---
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.config_models import (  # noqa: F401
    ConfigDataModel,
    POAPConfigModel,
    RMAConfigModel,
    SwitchConfigModel,
)


__all__ = [
    # Enums
    "AdvisoryLevel",
    "AnomalyLevel",
    "ConfigSyncStatus",
    "DiscoveryStatus",
    "PlatformType",
    "RemoteCredentialStore",
    "SnmpV3AuthProtocol",
    "SwitchRole",
    "SystemMode",
    "VpcRole",
    # Validators
    "SwitchValidators",
    # Nested models
    "AdditionalAciSwitchData",
    "AdditionalSwitchData",
    "Metadata",
    "SwitchMetadata",
    "TelemetryIpCollection",
    "VpcData",
    # Discovery models
    "AddSwitchesRequestModel",
    "ShallowDiscoveryRequestModel",
    "SwitchDiscoveryModel",
    # Switch data models
    "SwitchDataModel",
    # Bootstrap models
    "BootstrapBaseData",
    "BootstrapBaseModel",
    "BootstrapCredentialModel",
    "BootstrapImportSpecificModel",
    "BootstrapImportSwitchModel",
    "ImportBootstrapSwitchesRequestModel",
    # Preprovision models
    "PreProvisionSwitchesRequestModel",
    "PreProvisionSwitchModel",
    # RMA models
    "RMASwitchModel",
    # Switch actions models
    "ChangeSwitchSerialNumberRequestModel",
    "SwitchCredentialsRequestModel",
    # Config models
    "ConfigDataModel",
    "POAPConfigModel",
    "RMAConfigModel",
    "SwitchConfigModel",
]
