# ansible-nd

## Description

The `ansible-nd` project provides an Ansible collection for managing and automating your Cisco Nexus Dashboard.
It consists of a set of plugins, modules and roles for performing tasks related to Cisco Nexus Dashboard.

See the [cisco.nd collection index](https://galaxy.ansible.com/ui/repo/published/cisco/nd/content/) for a full list of modules and plugins.

## Requirements

- Ansible v2.17 or newer
- Python v3.11 or newer

Follow the [Installing Ansible](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html) guide for detailed instructions.

## Installation

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:

```sh
ansible-galaxy collection install cisco.nd
```

You can also include this collection in a `requirements.yml` file and install it with:

```sh
ansible-galaxy collection install -r requirements.yml
```

Using the following `requirements.yml` format:

```yaml
collections:
  - name: cisco.nd
```

Note that if you install any collections from Ansible Galaxy, they will not be upgraded automatically when you upgrade the Ansible package.
To upgrade the collection to the latest available version, run the following command:

```sh
ansible-galaxy collection install cisco.nd --upgrade
```

You can also install a specific version of the collection. For example, to install version 1.0.0, use the following syntax:

```sh
ansible-galaxy collection install cisco.nd:==1.0.0
```

See [using Ansible collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.

### Latest Build

Follow these instructions to get the latest collection.

#### First Approach - Build From Source Code

Clone the ansible-nd repository.

```sh
git clone https://github.com/CiscoDevNet/ansible-nd.git
```

Go to the ansible-nd directory

```sh
cd ansible-nd
```

Pull the latest master on your nd

```sh
git pull origin master
```

Build and Install a collection from source

```sh
ansible-galaxy collection build --force
ansible-galaxy collection install cisco-nd-* --force
```

#### Second Approach - Download From Latest CI Build

Go to [ansible-nd Actions](https://github.com/CiscoDevNet/ansible-nd/actions/workflows/ansible-test.yml?query=branch%3Amaster) and select the latest CI build.

Under Artifacts download collection suffixed with the latest version of Ansible (eg. `collection-stable-2.17`) and unzip it using Terminal or Console.

*Note: The collection file is a zip file containing a tar.gz file. We recommend using CLI because some GUI-based unarchiver might unarchive both nested archives in one go.*

Install the unarchived tar.gz file

```sh
ansible-galaxy collection install cisco-nd-1.0.0.tar.gz —-force
```

## Use Cases

Once the collection is installed, you can use it in a playbook by specifying the full namespace path to the module, plugin and/or role.

### Get the ND version

```yaml
- hosts: nd
  gather_facts: no

  tasks:
  - name: Get ND version
    cisco.nd.nd_version:
      state: query
```

With the following inventory file:

```ini
[nd]
nd1 ansible_host=10.0.0.1 ansible_user=admin ansible_ssh_pass="MySuperPassword"

[nd:vars]
ansible_connection=ansible.netcommon.httpapi
ansible_network_os=cisco.nd.nd
ansible_httpapi_validate_certs=False
ansible_httpapi_use_ssl=True
ansible_httpapi_use_proxy=True
```

You can also use the ND HTTPAPI connection plugin with your cisco.mso Ansible collection for MSO running on ND (MSO version >= 3.2) using the inventory file above.

```yaml
- hosts: nd
  gather_facts: no

  tasks:
  - name: Get MSO version from MSO >= 3.2
    cisco.mso.mso_version:
      state: query
```

User API Key authorization is also supported in the ND HTTPAPI connection plugin. Use the `ansible_httpapi_session_key` option to specify the key instead of a password. The `ansible_httpapi_session_key` option takes precedence over the `ansible_password` option if defined. If authorization fails using the API Key, the plugin will fallback to using the password. The session key option must be defined as a dictionary. The dictionary can either be formated in two ways:

1. Using a single key-value dictionary eg. `{"key": "<APIKEY>"}`. Only the dictionary value is used with the `ansible_user` option to format the ND authorization header.

2. Providing the ND authorization header manually eg. `{"X-Nd-Username": "admin", "X-Nd-Apikey": "<APIKEY>"}`. The `ansible_httpapi_session_key` option will be used as-is and the `ansible_user` option is ignored.

See the [Authorization Using API Key](https://developer.cisco.com/docs/nexus-dashboard/latest/getting-started/#authorization-using-api-key) documentation for more information.

```ini
[nd]
nd1 ansible_host=10.0.0.1 ansible_user=admin ansible_httpapi_session_key='{"key": "MySuperSecretUserApiKey"}'

[nd:vars]
ansible_connection=ansible.netcommon.httpapi
ansible_network_os=cisco.nd.nd
ansible_httpapi_validate_certs=False
ansible_httpapi_use_ssl=True
ansible_httpapi_use_proxy=True
```

## Testing

Testing is currently done manually during the development of each module.
Automated integration testing for this collection will be added in the future.

## Contributing to this collection

Ongoing development efforts and contributions to this collection are tracked as issues in this repository.

We welcome community contributions to this collection. If you find problems, need an enhancement or need a new module, please open an issue or create a PR against the [Cisco Nexus Dashboard collection repository](https://github.com/CiscoDevNet/ansible-nd/issues).

## Support

This collection supports any ND version within the Last Day of Support (LDOS) date.

Certain modules and options in the collection are only available from specific versions of ND. The versions that a module or option supports are documented in the individual module documentation.

To find EOL announcements for ND versions, refer to the [End-of-Life and End-of-Sale Notices](https://www.cisco.com/c/en/us/products/data-center-analytics/nexus-dashboard/eos-eol-notice-listing.html) page.

## Release Notes

See the [Changelog](CHANGELOG.rst) for full release notes.

## Related Information

For further information, refer to the following:

- [Nexus Dashboard Overview](https://www.cisco.com/site/us/en/products/networking/cloud-networking/nexus-platform/index.html)
- [Nexus Dashboard Support Documentation](https://www.cisco.com/c/en/us/support/data-center-analytics/nexus-dashboard/series.html)
- [Nexus Dashboard API Documentation](https://developer.cisco.com/docs/nexus-dashboard/latest/introduction/#introduction)

## License Information

This collection is licensed under the [GNU General Public License v3.0](LICENSE)
