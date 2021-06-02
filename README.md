# ansible-nd

The `ansible-nd` project provides an Ansible collection for managing and automating your Cisco Nexus Dashboard.
It consists of a set of plugins, modules and roles for performing tasks related to Cisco Nexus Dashboard.

This collection has been tested and supports Nexus Dahsboard (ND) 2.0+.
Modules supporting new features introduced in ND API in specific ND versions might not be supported in earlier ND releases.

*Note: This collection is not compatible with versions of Ansible before v2.8.*

## Requirements
- Ansible v2.9 or newer

## Install
Ansible must be installed
```
sudo pip install ansible
```

Install the collection
```
ansible-galaxy collection install cisco.nd
```

## Use
Once the collection is installed, you can use it in a playbook by specifying the full namespace path to the module, plugin and/or role.
```yaml
- hosts: nd
  gather_facts: no

  tasks:
  - name: Get ND version
    cisco.nd.nd_version:
      state: query
```

You can also use the ND HTTPAPI connection plugin with your cisco.mso Ansible collection for MSO running on ND (MSO version >= 3.2)
```yaml
- hosts: nd
  gather_facts: no

  tasks:
  - name: Get MSO version from MSO >= 3.2
    cisco.mso.mso_version:
      state: query
```

## Update
Getting the latest/nightly collection build

### First Approach
Clone the ansible-nd repository.
```
git clone https://github.com/CiscoDevNet/ansible-nd.git
```

Go to the ansible-nd directory
```
cd ansible-nd
```

Pull the latest master on your local repo
```
git pull origin master
```

Build and Install a collection from source
```
ansible-galaxy collection build --force
ansible-galaxy collection install cisco-nd-* --force
```

### Second Approach
Go to: https://github.com/CiscoDevNet/ansible-nd/actions

Select the latest CI build

Under Artifacts download collection and unzip it using Terminal or Console.

*Note: The collection file is a zip file containing a tar.gz file. We recommend using CLI because some GUI-based unarchiver might unarchive both nested archives in one go.*

Install the unarchived tar.gz file
```
ansible-galaxy collection install cisco-nd-*.tar.gz —-force
```

### See Also:

* [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection

Ongoing development efforts and contributions to this collection are tracked as issues in this repository.

We welcome community contributions to this collection. If you find problems, need an enhancement or need a new module, please open an issue or create a PR against the [Cisco Nexus Dashboard collection repository](https://github.com/CiscoDevNet/ansible-nd/issues).
