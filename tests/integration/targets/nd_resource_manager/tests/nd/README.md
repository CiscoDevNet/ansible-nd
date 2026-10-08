# nd_resource_manager Fabric-Type Integration Tests

These tests are selected by two variables passed to the integration playbook:

- `fabric_type`: supported values are `base`, `ibgp`, `ebgp`, `external`,
  `all`, or a comma-separated subset. The dispatcher still supports legacy
  root-level discovery when this variable is omitted, but no root-level test
  YAML files currently exist, so omitting it causes test discovery to fail.
- `testcase`: `*`, a YAML test file name, or a comma-separated list of YAML
  test file names. It defaults to `*`. File names can be provided with or
  without the `.yaml` extension.

The fabric-specific files live in subdirectories:

```text
tests/nd/
  base/       # Common pools and the load test
  ibgp/       # iBGP-only pool deltas
  ebgp/       # eBGP-only pool deltas
  external/   # External-fabric pool deltas
```

The dispatcher includes files with the pattern `{fabric_type}/{testcase}.yaml`.
When `fabric_type` is omitted, the dispatcher includes root-level legacy files
with the pattern `{testcase}.yaml`.

The selected test directories are:

| `fabric_type` value | Directories searched |
| --- | --- |
| Omitted or empty | `tests/nd/` only; currently fails because no root-level test YAML files exist |
| `base` | `tests/nd/base/` only |
| `ibgp` | `tests/nd/base/`, then `tests/nd/ibgp/` |
| `ebgp` | `tests/nd/base/`, then `tests/nd/ebgp/` |
| `external` | `tests/nd/base/`, then `tests/nd/external/` |
| `all` | `tests/nd/base/`, `tests/nd/ibgp/`, `tests/nd/ebgp/`, and `tests/nd/external/` |

A comma-separated fabric subset includes `base` once, followed by each selected
delta directory. For example, `fabric_type=ibgp,external` searches `base/`,
`ibgp/`, and `external/`.

## Current Test Files

| Test case | `base` | `ibgp` | `ebgp` | `external` | Coverage |
| --- | --- | --- | --- | --- | --- |
| `delete.yaml` | Yes | Yes | Yes | Yes | Creates resources, deletes them with `state=deleted`, and validates API and diff results. |
| `gathered.yaml` | Yes | Yes | Yes | Yes | Creates resources, gathers by entity name and pool name, and validates filtered results. |
| `invalid_params.yaml` | Yes | Yes | Yes | Yes | Validates failures for unsupported pool types, pool names, and other invalid resource requests. |
| `load.yaml` | Yes | No | No | No | Opt-in scale and idempotence test across two switches. |
| `merge.yaml` | Yes | Yes | Yes | Yes | Creates resources with `state=merged`, verifies idempotence, and validates API and diff results. |
| `sanity.yaml` | Yes | Yes | Yes | Yes | Runs the create, gather, and delete lifecycle for the selected pool set. |

Files under `base/` cover pool names common to all supported fabric types.
Files under `ibgp/`, `ebgp/`, and `external/` cover the delta pool names for
each fabric type from `FABRIC_SUPPORTED_POOLS`. Selecting a delta fabric runs
both its common `base/` cases and its delta cases when matching files exist.

## Test Selection

`testcase=*` discovers and runs every `*.yaml` file directly inside each
selected directory. Discovery is non-recursive, so nested directories and
non-YAML files are not included.

A named value runs only the matching file. A comma-separated value is an exact
allowlist, so `testcase=merge,delete` runs only `merge.yaml` and `delete.yaml`
from the selected directories. It does not run any other test files.

Each requested name must exist in at least one selected directory, but it does
not need to exist in every selected directory. For example,
`fabric_type=ibgp testcase=load` runs `base/load.yaml` without requiring an
`ibgp/load.yaml` file. An unknown value such as `testcase=merge,lod` fails
before any test file is included because `lod.yaml` exists in none of the
selected directories.

## vPC Prerequisite

Before running selected cases other than `gathered`, the dispatcher verifies
the expected vPC pair for each selected fabric. If the pair is missing,
`vpc_pair_once.yaml` creates, saves, deploys, and verifies it once before the
resource-manager cases run. Standalone `gathered` cases skip this setup.

The prerequisite and resource tests use these inventory variables:

- `ansible_switch1` and `ansible_switch2`: switch management addresses.
- `ansible_sno_1` and `ansible_sno_2`: switch serial numbers.
- `intf_1_2`, `intf_1_3`, and `intf_1_10`: interfaces used by link and
  device-interface resources.

## Load Test

`base/load.yaml` is discovered like any other test file but does no work unless
`rm_load_test_enabled=true`. It allocates
`ROUTE_MAP_SEQUENCE_NUMBER_POOL` resources across exactly two switches, checks
create idempotence, and cleans up the generated resources.

| Variable | Default | Description |
| --- | --- | --- |
| `rm_load_test_enabled` | `false` | Enables the load-test block. |
| `rm_load_expected_resources` | `20` | Number of resources to generate; must be from 1 through 2000. |
| `rm_load_resource_start` | `300` | Non-negative starting ID; normalized into the supported 1 through 1000 range per switch. |

Examples:

```bash
ansible-playbook run_tests.yaml -e "fabric_type=base testcase=*"
ansible-playbook run_tests.yaml -e "fabric_type=base testcase=merge"
ansible-playbook run_tests.yaml -e "fabric_type=ibgp testcase=merge.yaml"
ansible-playbook run_tests.yaml -e "fabric_type=ibgp testcase=merge,delete"
ansible-playbook run_tests.yaml -e "fabric_type=ibgp testcase=*"
ansible-playbook run_tests.yaml -e "fabric_type=ebgp testcase=merge,gathered,delete"
ansible-playbook run_tests.yaml -e "fabric_type=external testcase=merge,gathered,delete"
ansible-playbook run_tests.yaml -e "fabric_type=all testcase=merge,gathered,delete,invalid_params,sanity"
ansible-playbook run_tests.yaml -e "fabric_type=base testcase=load rm_load_test_enabled=true"
ansible-playbook run_tests.yaml -e "fabric_type=base testcase=load rm_load_test_enabled=true rm_load_expected_resources=500 rm_load_resource_start=100"
```

Fabric names can be supplied independently with:

- `ansible_it_fabric_base`
- `ansible_it_fabric_ibgp`
- `ansible_it_fabric_ebgp`
- `ansible_it_fabric_external`

Each typed fabric variable falls back to `ansible_it_fabric` when it is not
provided.
