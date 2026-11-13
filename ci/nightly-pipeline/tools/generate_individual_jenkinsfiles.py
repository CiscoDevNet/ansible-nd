"""Generate private-Webex, single-target copies of the community-list pipeline."""

import argparse
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / 'Jenkinsfile_nd_jenkins_script_comm_list'
OUTPUT = ROOT / 'individual_jenkinsfiles'
SELECTORS = (
    'PLAYBOOK_FILES', 'INTEGRATION_MODULES', 'STANDALONE_INTEGRATION_MODULES',
    'VPC_PAIR_EXECUTIONS', 'INTERFACE_INTEGRATION_MODULES',
    'TRAILING_INTEGRATION_MODULES',
)
TARGETS = (
    'nd_manage_policy', 'nd_manage_policy_group',
    'nd_vpc_pair.advanced', 'nd_vpc_pair.external',
    'nd_manage_route_map', 'nd_manage_prefix_list', 'nd_manage_acl',
    'nd_manage_community_list', 'nd_manage_extended_community_list',
    'nd_manage_l3out', 'nd_manage_vrfs', 'nd_manage_networks',
    'nd_manage_fabric_group_vxlan', 'nd_manage_fabric_group_members',
    'nd_local_user', 'nd_manage_tor', 'nd_maintenance_mode',
    'nd_fabric_update_group', 'nd_interface_loopback', 'nd_interface_svi',
    'nd_interface_ethernet_access', 'nd_interface_ethernet_trunk_host',
    'nd_interface_ethernet_routed', 'nd_interface_port_channel_access',
    'nd_interface_port_channel_trunk_host', 'nd_interface_port_channel_routed',
    'nd_interface_subinterface_managed', 'nd_interface_subinterface_unmanaged',
    'nd_interface_vpc_access', 'nd_interface_vpc_trunk_host',
    'nd_resource_manager', 'nd_manage_fabric', 'nd_manage_links',
    'nd_manage_switches',
)
TRAILING = {
    'nd_resource_manager', 'nd_manage_fabric', 'nd_manage_links',
    'nd_manage_switches',
}
PAIR_ROWS = {
    'advanced': "[id: 'advanced', fabric: 'VXLAN_EVPN_Fabric', type: 'vxlanIbgp', switch1: 'vxlan_leaf_1', switch2: 'vxlan_leaf_2']",
    'external': "[id: 'external', fabric: 'External_Connectivity_Fabric', type: 'externalConnectivity', switch1: 'external_edge_1', switch2: 'external_edge_2']",
}


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('Template anchor is missing or ambiguous: ' + old[:80])
    return source.replace(old, new, 1)


def selector_pattern(name):
    return re.compile(r'^def ' + re.escape(name) + r' = \[\n.*?^\]', re.M | re.S)


def render(source, target):
    if target not in TARGETS:
        raise ValueError('Unknown target: ' + target)
    active_rooms = re.findall(r'^\s*WEBEX_ROOM_ID\s*=\s*(.+)$', source, re.M)
    if len(active_rooms) != 1 or active_rooms[0].split('//')[0].strip() != '"${WEBEX_ROOM_ID_PRIVATE}"':
        raise ValueError('Template must select private Webex exclusively')
    contents = dict.fromkeys(SELECTORS, '')
    if target.startswith('nd_vpc_pair.'):
        pair = target.split('.', 1)[1]
        contents['STANDALONE_INTEGRATION_MODULES'] = "    'nd_vpc_pair',\n"
        contents['VPC_PAIR_EXECUTIONS'] = '    ' + PAIR_ROWS[pair] + ',\n'
    else:
        selector = 'INTEGRATION_MODULES'
        if target.startswith('nd_interface_'):
            selector = 'INTERFACE_INTEGRATION_MODULES'
        elif target in TRAILING:
            selector = 'TRAILING_INTEGRATION_MODULES'
        contents[selector] = "    '" + target + "',\n"
    result = source
    for name in SELECTORS:
        replacement = 'def ' + name + ' = [\n' + contents[name] + ']'
        result, count = selector_pattern(name).subn(lambda match: replacement, result)
        if count != 1:
            raise ValueError('Expected exactly one selector: ' + name)
    if target.startswith('nd_vpc_pair.'):
        anchor = '            def plannedResultTargets = orderedIntegrationTargets.collect'
        result = replace_once(result, anchor,
            "            if (env.ND_PREREQUISITE_ONLY_EFFECTIVE != 'true') {\n"
            '                orderedIntegrationTargets.addAll(standaloneTargets)\n'
            '            }\n' + anchor)
        anchor = '    targets.addAll(PLAYBOOK_FILES)'
        result = replace_once(result, anchor,
            '    targets.addAll(pairRows.collect { "nd_vpc_pair.${it.id}".toString() })\n' + anchor)
    return '\n'.join(line.rstrip() for line in result.splitlines()) + '\n'


def artifacts(source):
    outputs = {}
    entries = []
    for number, target in enumerate(TARGETS, 1):
        name = 'Jenkinsfile_' + target.replace('.', '_')
        payload = render(source, target).encode('utf-8')
        outputs[name] = payload
        entries.append({
            'number': number, 'target': target, 'file': name,
            'webex': 'private', 'rounds': ['iBGP', 'eBGP'],
            'sha256': hashlib.sha256(payload).hexdigest(),
        })
    manifest = {
        'template': TEMPLATE.name,
        'template_sha256': hashlib.sha256(source.encode('utf-8')).hexdigest(),
        'target_count': len(entries),
        'status': 'generated_offline_not_deployed_or_live_validated',
        'targets': entries,
    }
    outputs['index.json'] = (json.dumps(manifest, indent=2) + '\n').encode('utf-8')
    return outputs


def generate(template=TEMPLATE, output=OUTPUT, check=False, refresh=False):
    outputs = artifacts(template.read_text(encoding='utf-8'))
    if check:
        for name, payload in outputs.items():
            path = output / name
            if not path.is_file() or path.read_bytes() != payload:
                raise ValueError('Generated file is missing or stale: ' + str(path))
        actual = {path.name for path in output.glob('Jenkinsfile_*')}
        expected = set(outputs) - {'index.json'}
        if actual != expected:
            raise ValueError('Unexpected Jenkinsfile set in output folder')
    else:
        previous = {}
        if refresh:
            manifest_path = output / 'index.json'
            manifest_bytes = manifest_path.read_bytes()
            manifest = json.loads(manifest_bytes)
            previous = {row['file']: row['sha256'] for row in manifest['targets']}
            if set(previous) != set(outputs) - {'index.json'}:
                raise ValueError('Existing manifest does not describe the expected target set')
            previous['index.json'] = hashlib.sha256(manifest_bytes).hexdigest()
        for name, payload in outputs.items():
            path = output / name
            if path.exists() and path.read_bytes() != payload:
                if not refresh or hashlib.sha256(path.read_bytes()).hexdigest() != previous.get(name):
                    raise ValueError('Refusing to overwrite an existing changed file: ' + str(path))
        output.mkdir(parents=True, exist_ok=True)
        for name, payload in outputs.items():
            path = output / name
            if not path.exists() or (refresh and path.read_bytes() != payload):
                path.write_bytes(payload)
    return len(TARGETS)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--refresh', action='store_true', help='Refresh only files unchanged since the previous generated manifest')
    parser.add_argument('--output', type=Path, default=OUTPUT)
    args = parser.parse_args()
    if args.check and args.refresh:
        parser.error('--check and --refresh cannot be combined')
    count = generate(output=args.output, check=args.check, refresh=args.refresh)
    print(('Verified' if args.check else 'Generated') + f' {count} private-Webex Jenkinsfiles in {args.output}')


if __name__ == '__main__':
    main()