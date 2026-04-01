# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""manage_policies models package.

Re-exports all model classes and enums from their individual modules so
that consumers can import directly from the package:

    from .models.manage_policies import PolicyCreate, PolicyEntityType, ...
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

# --- Enums ---
from .enums import (  # noqa: F401
    PolicyEntityType,
)

# --- Base models ---
from .policy_base import (  # noqa: F401
    PolicyCreate,
)

# --- CRUD models ---
from .policy_crud import (  # noqa: F401
    PolicyCreateBulk,
    PolicyUpdate,
)

# --- Action models ---
from .policy_actions import (  # noqa: F401
    PolicyIds,
)

# --- Gathered (read) models ---
from .gathered_models import (  # noqa: F401
    GatheredPolicy,
)

# --- Config (playbook input) models ---
from .config_models import (  # noqa: F401
    PlaybookPolicyConfig,
    PlaybookSwitchEntry,
    PlaybookSwitchPolicyConfig,
)


__all__ = [
    # Enums
    "PolicyEntityType",
    # Base models
    "PolicyCreate",
    # CRUD models
    "PolicyCreateBulk",
    "PolicyUpdate",
    # Action models
    "PolicyIds",
    # Gathered (read) models
    "GatheredPolicy",
    # Config (playbook input) models
    "PlaybookPolicyConfig",
    "PlaybookSwitchEntry",
    "PlaybookSwitchPolicyConfig",
]