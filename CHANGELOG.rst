======================================================
Cisco Nexus Dashboard Ansible Collection Release Notes
======================================================

.. contents:: Topics

v1.3.0
======

Release Summary
---------------

Release v1.3.0 of the ``ansible-nd`` collection on 2025-02-25.
This changelog describes all changes made to the modules and plugins included in this collection since v1.2.0.

Minor Changes
-------------

- Add nd_setup support for ND version 3.1.1 and later. Add deployment mode to nd_setup.
- Add support for XML file upload pre-change in nd_pcv (DCNE-150) (#77)
- Added support for Ansible 2.18 and dropped support for 2.15
- Enable the possibility to support pure IPv6 configurations for nd_setup module on nd version 3.0.1 and later.

Bugfixes
--------

- Updated README to match RedHat s ansible collection template.

v1.2.0
======

Release Summary
---------------

Release v1.2.0 of the ``ansible-nd`` collection on 2024-07-16.
This changelog describes all changes made to the modules and plugins included in this collection since v1.1.0.

New Modules
-----------

- cisco.nd.nd_federation_member - Setup multi-cluster configuration on Cisco Nexus Dashboard (ND).

v1.1.0
======

Release Summary
---------------

Release v1.1.0 of the ``ansible-nd`` collection on 2024-07-01.
This changelog describes all changes made to the modules and plugins included in this collection since v1.0.0.

Minor Changes
-------------

- Add nd_flow_rules and nd_interface_flow_rules as new modules.
- Default insights_group to default when not provided as argument

v1.0.0
======

Release Summary
---------------

Release v1.0.0 of the ``ansible-nd`` collection on 2023-11-03.
This release only includes changes needed to release v1.0.0 on RedHat Ansible Automation Hub. As required by RedHat, this release bump the minimum release supported of Ansible to v2.13.1+

v0.5.0
======

Release Summary
---------------

Release v0.5.0 of the ``ansible-nd`` collection on 2023-11-03.
This changelog describes all changes made to the modules and plugins included in this collection since v0.4.0.

Minor Changes
-------------

- Add nd_setup, nd_cluster_config_route, nd_backup, nd_backup_restore, nd_service, nd_service_instance and nd_policy_cam_statistics_hit_counts modules

New Modules
-----------

- cisco.nd.nd_backup - Manages backup on Nexus Dashboard.
- cisco.nd.nd_backup_restore - Manages restore of backup on Nexus Dashboard.
- cisco.nd.nd_cluster_config_route - Manages routes of the cluster config.
- cisco.nd.nd_policy_cam_statistics_hit_counts - Retrieves Policy CAM Statistics Hit Counts
- cisco.nd.nd_service - Manages Service Package on Nexus Dashboard.
- cisco.nd.nd_service_instance - Manages Service Instance on Nexus Dashboard.
- cisco.nd.nd_setup - Manages setting up the Nexus Dashboard.

v0.4.0
======

Release Summary
---------------

Release v0.4.0 of the ``ansible-nd`` collection on 2023-08-04.
This changelog describes all changes made to the modules and plugins included in this collection since v0.3.0.

Minor Changes
-------------

- Add new module nd_site (#47)

New Modules
-----------

- cisco.nd.nd_site - Manage sites on Nexus Dashboard.

v0.3.0
======

Release Summary
---------------

Release v0.3.0 of the ``ansible-nd`` collection on 2023-04-05.
This changelog describes all changes made to the modules and plugins included in this collection since v0.2.0.

Minor Changes
-------------

- Add module nd_compliance_analysis and nd_compliance_requirement_communication and nd_compliance_requirement_config_import and nd_compliance_requirement_config_manual and nd_compliance_requirement_config_snapshot and nd_compliance_requirement_config_template and nd_epoch

Bugfixes
--------

- Ensure python2 compatible methods are used for the bytes io object in ND HTTPAPI Connection Plugin (#41)

New Modules
-----------

- cisco.nd.nd_compliance_analysis - Query compliance analysis data from Cisco Nexus Dashboard Insights (NDI)
- cisco.nd.nd_compliance_requirement_communication - Manage communication type compliance requirements
- cisco.nd.nd_compliance_requirement_config_import - Manage import configuration type compliance requirements
- cisco.nd.nd_compliance_requirement_config_manual - Manage manual configuration type compliance requirements
- cisco.nd.nd_compliance_requirement_config_snapshot - Manage snapshot configuration type compliance requirements
- cisco.nd.nd_compliance_requirement_config_template - Manage template configuration type compliance requirements
- cisco.nd.nd_epoch - Query epoch data from Cisco Nexus Dashboard Insights (NDI)

v0.2.0
======

Release Summary
---------------

Release v0.2.0 of the ``ansible-nd`` collection on 2023-02-04.
This changelog describes all changes made to the modules and plugins included in this collection since v0.1.2.

Minor Changes
-------------

- Add ansible_httpapi_login_domain global inventory variable

Bugfixes
--------

- Allow local to be set as login_domain && set DefaultAuth as default for login_domain
- Fix HTTPAPI Connection plugin when wrong login_domain is provided
- Fix HTTPAPI ND connection plugin missing login_domain definition

New Modules
-----------

- cisco.nd.nd_delta_analysis - Manage delta analysis jobs
- cisco.nd.nd_instant_assurance_analysis - Manage instant online assurance analysis jobs
- cisco.nd.nd_pcv - Manage pre-change validation job
- cisco.nd.nd_pcv_compliance - Query pre-change validation compliance
- cisco.nd.nd_pcv_delta_analysis - Query delta analysis of pre-change validation

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

New Plugins
-----------

Httpapi
~~~~~~~

- cisco.nd.nd - Nexus Dashboard Ansible HTTPAPI Plugin.

New Modules
-----------

- cisco.nd.nd_version - Get version of Nexus Dashboard (ND)
