# nd_resource_manager Fabric-Type Integration Tests

These tests are selected by two variables from `nd/playbook/run_tests.yaml`:

- `fabric_type`: optional. When omitted, legacy root-level files are used.
  When set, supported values are `base`, `ibgp`, `ebgp`, `external`, `all`,
  or a comma-separated subset.
- `testcase`: `merge`, `delete`, `gathered`, `invalid_params`, `sanity`,
  `load`, `*`, or a comma-separated subset.

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

When `fabric_type` is set to a concrete fabric type, the dispatcher runs common
base coverage first and then the fabric delta coverage:

- `fabric_type=base` runs `base/`.
- `fabric_type=ibgp` runs `base/` and `ibgp/`.
- `fabric_type=ebgp` runs `base/` and `ebgp/`.
- `fabric_type=external` runs `base/` and `external/`.
- `fabric_type=all` runs `base/`, `ibgp/`, `ebgp/`, and `external/`.

`testcase=*` expands to `delete,gathered,invalid_params,load,merge,sanity`.

Examples:

```bash
ansible-playbook run_tests.yaml -e "testcase=delete,gathered,invalid_params,load,merge"
ansible-playbook run_tests.yaml -e "testcase=*"
ansible-playbook run_tests.yaml -e "fabric_type=base testcase=merge,gathered,delete"
ansible-playbook run_tests.yaml -e "fabric_type=ibgp testcase=merge,gathered,delete"
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
