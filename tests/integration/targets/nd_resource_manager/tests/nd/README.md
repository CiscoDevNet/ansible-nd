# nd_resource_manager Fabric-Type Integration Tests

These tests are selected by two variables from `nd/playbook/run_tests.yaml`:

- `fabric_type`: optional. When omitted, legacy root-level files are used.
  When set, supported values are `base`, `ibgp`, `ebgp`, `external`, `all`,
  or a comma-separated subset.
- `testcase`: `*`, a YAML test file name, or a comma-separated list of YAML
  test file names. File names can be provided with or without the `.yaml`
  extension.

The fabric-specific files live in subdirectories:

```text
tests/nd/
  base/
  ibgp/
  ebgp/
  external/
```

The dispatcher includes files with the pattern `{fabric_type}/{testcase}.yaml`.
When `fabric_type` is omitted, the dispatcher includes root-level legacy files
with the pattern `{testcase}.yaml`.

The selected test directories are:

| `fabric_type` value | Directories searched |
| --- | --- |
| Omitted or empty | `tests/nd/` only |
| `base` | `tests/nd/base/` only |
| `ibgp` | `tests/nd/base/`, then `tests/nd/ibgp/` |
| `ebgp` | `tests/nd/base/`, then `tests/nd/ebgp/` |
| `external` | `tests/nd/base/`, then `tests/nd/external/` |
| `all` | `tests/nd/base/`, `tests/nd/ibgp/`, `tests/nd/ebgp/`, and `tests/nd/external/` |

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

Examples:

```bash
ansible-playbook run_tests.yaml -e "testcase=delete,gathered,invalid_params,load,merge"
ansible-playbook run_tests.yaml -e "testcase=*"
ansible-playbook run_tests.yaml -e "fabric_type=base testcase=merge"
ansible-playbook run_tests.yaml -e "fabric_type=ibgp testcase=merge.yaml"
ansible-playbook run_tests.yaml -e "fabric_type=ibgp testcase=merge,delete"
ansible-playbook run_tests.yaml -e "fabric_type=ibgp testcase=*"
ansible-playbook run_tests.yaml -e "fabric_type=ebgp testcase=merge,gathered,delete"
ansible-playbook run_tests.yaml -e "fabric_type=external testcase=merge,gathered,delete"
ansible-playbook run_tests.yaml -e "fabric_type=all testcase=merge,gathered,delete,invalid_params,sanity"
ansible-playbook run_tests.yaml -e "fabric_type=base testcase=load rm_load_test_enabled=true"
```

Fabric names can be supplied independently with:

- `ansible_it_fabric_base`
- `ansible_it_fabric_ibgp`
- `ansible_it_fabric_ebgp`
- `ansible_it_fabric_external`

Files under `base/` cover pool names common to all supported fabric types.
Files under `ibgp/`, `ebgp/`, and `external/` cover the delta pool names for
each fabric type from `FABRIC_SUPPORTED_POOLS`.
