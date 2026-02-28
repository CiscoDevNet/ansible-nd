# Endpoint Versioning Strategy

## Overview

This document codifies the long-term strategy for supporting multiple ND REST API versions (v1, v2, v3, etc.) in the Cisco ND Ansible collection. It explains the current architecture, the rationale behind design decisions, and the planned next steps.

## Current Status

### ✅ Completed (Phase 1-2)

1. **Directory-Level Versioning Structure**
   - Endpoints organized in version-specific directories: `plugins/module_utils/ep/v1/`
   - File naming reflects API operations: `ep_infra_aaa.py`, `ep_manage_switches.py`, etc.
   - Class names simplified to remove version redundancy (version encoded in import path)

2. **Response Validation Strategy Infrastructure**
   - Created `ResponseValidationStrategy` Protocol in `plugins/module_utils/response_strategies/base_strategy.py`
   - Implemented `NdV1Strategy` with v1-specific status codes and error handling logic
   - Protocol allows version-specific response handling without coupling to ResponseHandler

3. **Version Metadata on Endpoints**
   - All endpoint classes have `api_version: Literal["v1"]` field
   - All endpoint classes have `min_controller_version` field
   - These fields enable runtime version detection and selection

4. **Backward Compatibility**
   - Re-export pattern in `ep/__init__.py` maintains compatibility with old import paths
   - Three import patterns all work simultaneously:
     ```python
     # Explicit v1 (preferred)
     from ep.v1 import EpInfraAaaLocalUsersGet

     # Via re-export (backward compatible)
     from ep import EpInfraAaaLocalUsersGet

     # Direct module import
     from ep.v1.ep_infra_aaa import EpInfraAaaLocalUsersGet
     ```

## Architecture

### Current File Structure

```
plugins/module_utils/ep/
├── base_path.py                          ← Constants (shared across all versions)
├── __init__.py                           ← Re-exports for backward compatibility
├── v1/
│   ├── __init__.py                       ← v1 exports
│   ├── base_paths_infra.py              ← v1-specific path builders
│   ├── base_paths_manage.py             ← v1-specific path builders
│   ├── ep_infra_aaa.py                  ← AAA endpoints (LocalUsers, etc.)
│   ├── ep_infra_clusterhealth.py        ← Cluster Health endpoints
│   └── ep_manage_switches.py            ← Switch management endpoints
└── v2/                                   ← Planned for future v2 API

plugins/module_utils/response_strategies/
├── __init__.py
├── base_strategy.py                      ← ResponseValidationStrategy Protocol
└── nd_v1_strategy.py                    ← NdV1Strategy implementation
```

### Key Design Principles

1. **Version-Agnostic Constants** - `base_path.py` contains root API paths shared across all versions
2. **Version-Specific Implementations** - Each version has its own directory with complete endpoint definitions
3. **Protocol-Based Strategy Pattern** - Response validation can be overridden per version without modifying core ResponseHandler
4. **Metadata-Driven Detection** - Version information embedded in classes enables runtime selection logic

## Planned Implementation (Phase 3+)

### 🔵 Planned: Runtime Version Selection Dispatcher

The next major phase will implement a **Strategy Pattern dispatcher** that selects which endpoint version to use based on controller version at module initialization time.

#### Design Approach

```python
# Pseudo-code showing planned architecture

class EndpointVersionDispatcher:
    """Selects appropriate endpoint version based on controller version."""

    @staticmethod
    def get_endpoint_for_version(
        endpoint_name: str,          # e.g., "InfraAaaLocalUsersGet"
        controller_version: str       # e.g., "3.0.0" or "4.0.0"
    ) -> BaseModel:
        """
        Returns the appropriate endpoint class instance for the given controller version.

        Examples:
            ep = EndpointVersionDispatcher.get_endpoint_for_version(
                "InfraAaaLocalUsersGet",
                "3.1.0"
            )
            # Returns: EpInfraAaaLocalUsersGet (v1 implementation)

            ep = EndpointVersionDispatcher.get_endpoint_for_version(
                "InfraAaaLocalUsersGet",
                "4.0.0"
            )
            # Returns: EpInfraAaaLocalUsersGet (v2 implementation, when available)
        """
```

#### Questions to Answer When v2 Arrives

1. **Response Format Changes**: Do v2 API responses maintain the same `{RETURN_CODE, MESSAGE, DATA}` structure?
   - If yes: Existing `ResponseHandler` can be reused
   - If no: Implement v2-specific response strategy via `ResponseValidationStrategy`

2. **Endpoint Coexistence**: Can v1 and v2 endpoints exist simultaneously?
   - If yes: Support both, auto-select based on controller version
   - If no: Version migration strategy required (deprecation period, migration guide, etc.)

3. **Controller Version Detection**: How to determine which API version the controller supports?
   - Option A: Query controller version at connection time via existing APIs
   - Option B: User configuration in inventory/playbook
   - Option C: Version negotiation (try v2, fallback to v1)

4. **Endpoint Changes**: Which endpoints change between v1 and v2?
   - Some endpoints may be identical (reuse class)
   - Some endpoints may have parameter changes (new class)
   - Some endpoints may be removed (with deprecation warning)

## Implementation Strategy When v2 Arrives

### Step 1: Create v2 Endpoint Directory
```bash
cp -r plugins/module_utils/ep/v1 plugins/module_utils/ep/v2
# Modify endpoints for v2 API differences
```

### Step 2: Update Version Metadata
```python
# In ep/v2 endpoint classes:
api_version: Literal["v2"] = Field(default="v2", ...)
min_controller_version: str = Field(default="4.0.0", ...)
```

### Step 3: Create Response Strategy (if needed)
```python
# plugins/module_utils/response_strategies/nd_v2_strategy.py
class NdV2Strategy(ResponseValidationStrategy):
    """v2-specific response validation with any updated status codes."""
```

### Step 4: Implement Dispatcher
```python
# plugins/module_utils/endpoint_dispatcher.py
class EndpointVersionDispatcher:
    VERSION_REGISTRY = {
        "v1": {...endpoint classes...},
        "v2": {...endpoint classes...},
    }

    @staticmethod
    def get_endpoint(name: str, version: str) -> BaseModel:
        # Dynamic dispatch logic
```

### Step 5: Integrate with Module Initialization
```python
# In NDModule or similar:
def __init__(self, ...):
    controller_version = self.detect_controller_version()
    self.endpoint_dispatcher = EndpointVersionDispatcher(controller_version)

    # Later in module code:
    ep = self.endpoint_dispatcher.get_endpoint("InfraAaaLocalUsersGet")
```

## Benefits of This Approach

1. **Scalable**: Easy to add v2, v3, etc. without modifying core module logic
2. **Maintainable**: Each version is isolated in its own directory
3. **Testable**: Version-specific behavior tested independently
4. **Backward Compatible**: Existing code continues to work during transition
5. **Future-Proof**: Metadata fields enable runtime decisions

## Current Testing Status

- ✅ All 161 endpoint unit tests pass
- ✅ pylint rating: 10.00/10
- ✅ Black formatting verified
- ✅ isort import sorting verified
- ✅ Three import patterns verified working
- ✅ Version metadata accessible and correct

## Related Files

- `plugins/module_utils/response_strategies/base_strategy.py` - Protocol definition
- `plugins/module_utils/response_strategies/nd_v1_strategy.py` - v1 implementation
- `plugins/module_utils/ep/v1/` - v1 endpoint definitions
- `plugins/httpapi/nd.py` - Connection layer (may need version detection here)
- `plugins/module_utils/nd_v2.py` - Module base class (where dispatcher might integrate)

## Next Steps

1. Monitor ND API development for v2 announcement
2. When v2 endpoints become available:
   - Create `ep/v2/` directory structure
   - Identify endpoint changes between versions
   - Implement `NdV2Strategy` if response format differs
   - Implement `EndpointVersionDispatcher`
   - Update module initialization to use dispatcher

3. Optional improvements (lower priority):
   - Add controller version detection utility function
   - Create comprehensive version compatibility matrix
   - Add version information to module documentation

## References

- Session work: Refactoring to remove version redundancy from class names (February 2026)
- Related PR commits: `ac0d1f4` (Endpoint class name refactoring), `ecba6ca` (Endpoint parameter analysis)
