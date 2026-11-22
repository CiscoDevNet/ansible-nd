"""The original develop ToR role is no longer replaced by a reduced suite."""
from pathlib import Path
import yaml
ROOT = Path(__file__).resolve().parents[1]
def test_original_tor_role_is_not_replaced():
    text=(ROOT/'tests/run_integration_module.yaml').read_text()
    assert 'TOR TC' not in text
    assert 'nd_tor_switch_name' not in text
    assert 'name: "{{ test_module }}"' in text
def test_profile_describes_authored_topology():
    profile=yaml.safe_load((ROOT/'tests/nd_prerequisite_profiles.yaml').read_text())['profiles']['integration.nd_manage_tor']
    assert 'does not substitute a reduced test suite' in str(profile['confirmation']['reasons'])
    assert profile['runtime_vars'] == {'nd_test_fabric_name': 'VXLAN_EVPN_Fabric'}
