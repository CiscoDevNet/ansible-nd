======================================================
Cisco Nexus Dashboard Ansible Collection Release Notes
======================================================

.. contents:: Topics


v0.1.2
======

Release Summary
---------------

New release v0.1.2

Bugfixes
--------

- Fix ND HTTAPI plugin login_domain issue when used with cisco.mso collection
- Fix default user when not defining the user. Default username "admin" has been removed. Always specify username via module attribute or define the ansible_user variable in inventory.
- Remove empty sanity ignore files

v0.1.1
======

Release Summary
---------------

New release v0.1.1

Bugfixes
--------

- Fix ND HTTAPI plugin to support remote users
- Remove required params for attributes that are handled by the HTTPAPI plugin

v0.1.0
======

Release Summary
---------------

Initial release of Nexus Dashboard collection
