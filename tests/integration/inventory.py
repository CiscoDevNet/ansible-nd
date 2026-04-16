# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Generate `inventory.networking` for cisco.nd integration tests from environment variables.

`ansible-test network-integration` runs in a sandboxed environment that strips env vars, so a
dynamic inventory script cannot read them at runtime. Instead, run this generator *before*
`ansible-test` to produce a static `inventory.networking` file that `ansible-test` picks up
automatically.

The generated `inventory.networking` contains credentials and MUST NOT be committed.
It is already covered by `.gitignore`.

## Required Environment Variables

```bash
export ND_IP4=10.1.1.1             # ND controller management IP
export ND_USERNAME=admin            # ND login username
export ND_PASSWORD=secret           # ND login password
export ND_DOMAIN=local              # ND login domain (local, radius, etc.)
```

## Optional Environment Variables

These provide testbed-specific topology details. Each integration target can also
define its own defaults in `vars/main.yaml`; these env vars take precedence.

```bash
export ND_FABRIC_NAME=my_fabric     # Fabric name for interface tests
export ND_SWITCH_IP=192.168.1.1     # Switch management IP within the fabric
```

## macOS: Python Fork Safety

On macOS, `ansible-test` may crash with `crashed on child side of fork pre-exec` due to the
ObjC runtime's fork-safety check in Python 3.11. Set the following before running `ansible-test`:

```bash
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
```

This is not needed on Linux or with Python 3.12+.

## Usage

```bash
# 1. Generate inventory.networking from your environment
python tests/integration/inventory.py

# 2. Run tests via ansible-test
ansible-test network-integration nd_interface_loopback

# Or run directly with ansible-playbook (no generation step needed)
ansible-playbook \
    -i tests/integration/inventory.py \
    tests/integration/targets/nd_interface_loopback/tasks/main.yaml
```
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from os import environ
from pathlib import Path


def _required(var_name: str, description: str) -> str:
    """
    # Summary

    Return the value of a required environment variable, or exit with an error message.

    ## Raises

    None
    """
    value = environ.get(var_name)
    if not value:
        print(f"ERROR: {var_name} must be set ({description})", file=sys.stderr)
        sys.exit(1)
    return value


@dataclass
class NdConnection:
    """
    # Summary

    ND controller connection parameters sourced from environment variables.

    ## Raises

    None
    """

    host: str = field(default="", init=False)
    username: str = field(default="", init=False)
    password: str = field(default="", init=False)
    domain: str = field(default="", init=False)
    use_ssl: bool = True
    validate_certs: bool = False

    def __post_init__(self) -> None:
        """
        # Summary

        Resolve required environment variables at instance creation time, not at class definition time.

        ## Raises

        None
        """
        self.host = _required("ND_IP4", "ND controller management IP")
        self.username = _required("ND_USERNAME", "ND login username")
        self.password = _required("ND_PASSWORD", "ND login password")
        self.domain = _required("ND_DOMAIN", "ND login domain e.g. 'local', 'radius'")


@dataclass
class TestbedTopology:
    """
    # Summary

    Testbed topology variables. Defaults are provided for convenience; override via
    environment variables to match your testbed. Integration targets can further
    override these in their own `vars/main.yaml` using the Jinja default filter.

    ## Raises

    None
    """

    fabric_name: str = field(default="", init=False)
    switch_ip: str = field(default="", init=False)

    def __post_init__(self) -> None:
        """
        # Summary

        Resolve optional environment variables at instance creation time, not at class definition time.

        ## Raises

        None
        """
        self.fabric_name = environ.get("ND_FABRIC_NAME", "test_fabric")
        self.switch_ip = environ.get("ND_SWITCH_IP", "192.168.1.1")


def build_inventory() -> dict:
    """
    # Summary

    Build and return the Ansible dynamic inventory dict.

    ## Raises

    None
    """
    conn = NdConnection()
    topo = TestbedTopology()

    return {
        "_meta": {"hostvars": {}},
        "all": {
            "children": ["nd"],
        },
        "nd": {
            "hosts": [conn.host],
            "vars": {
                "ansible_connection": "ansible.netcommon.httpapi",
                "ansible_network_os": "cisco.nd.nd",
                "ansible_httpapi_login_domain": conn.domain,
                "ansible_httpapi_use_ssl": conn.use_ssl,
                "ansible_httpapi_validate_certs": conn.validate_certs,
                "ansible_user": conn.username,
                "ansible_password": conn.password,
                "ansible_python_interpreter": "python",
                # Testbed topology — targets reference these via Jinja defaults
                # e.g. {{ nd_test_fabric_name | default('test_fabric') }}
                "nd_test_fabric_name": topo.fabric_name,
                "nd_test_switch_ip": topo.switch_ip,
            },
        },
    }


def build_ini_inventory() -> str:
    """
    # Summary

    Build an INI-format inventory string suitable for `ansible-test network-integration`.

    ## Raises

    None
    """
    conn = NdConnection()
    topo = TestbedTopology()

    lines = [
        "[nd]",
        f"nd ansible_host={conn.host}",
        "",
        "[nd:vars]",
        "ansible_connection=ansible.netcommon.httpapi",
        "ansible_network_os=cisco.nd.nd",
        f"ansible_httpapi_login_domain={conn.domain}",
        f"ansible_httpapi_use_ssl={conn.use_ssl}",
        f"ansible_httpapi_validate_certs={conn.validate_certs}",
        f"ansible_user={conn.username}",
        f"ansible_password={conn.password}",
        "ansible_python_interpreter=python",
        f"nd_test_fabric_name={topo.fabric_name}",
        f"nd_test_switch_ip={topo.switch_ip}",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    """
    # Summary

    When called with `--list`, output JSON inventory to stdout (dynamic inventory mode for
    `ansible-playbook -i inventory.py`). When called with no arguments, generate a static
    `inventory.networking` file in the same directory for use with `ansible-test`.

    ## Raises

    None
    """
    if "--list" in sys.argv:
        print(json.dumps(build_inventory(), indent=4, sort_keys=True))
        return

    if "--host" in sys.argv:
        print(json.dumps({}))
        return

    # Generator mode: write static inventory.networking
    inventory_dir = Path(__file__).resolve().parent
    inventory_path = inventory_dir / "inventory.networking"

    ini_content = build_ini_inventory()
    inventory_path.write_text(ini_content)
    print(f"Generated {inventory_path}")


if __name__ == "__main__":
    main()
