# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Lionel Hercot (@lhercot) <lhercot@cisco.com>
# Copyright: (c) 2022, Cindy Zhao (@cizhao) <cizhao@cisco.com>
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import (absolute_import, division, print_function)
import json
from jsonpath_ng import parse
__metaclass__ = type

class NDI:

    def __init__(self, nd_module):
        self.nd = nd_module
        self.cmap = {}
        self.prefix = "/sedgeapi/v1/cisco-nir/api/api/telemetry/v2"
        self.config_ig_path = "config/insightsGroup"
        self.event_insight_group_path = "events/insightsGroup/{0}/fabric/{1}"
        self.compliance_path = "model/aciPolicy/complianceAnalysis"
        self.epoch_delta_ig_path = "epochDelta/insightsGroup/{0}/fabric/{1}/job/{2}/health/view"

    def get_site_id(self, ig_name, site_name, **kwargs):
        obj = self.nd.query_obj(self.config_ig_path, **kwargs)
        for insights_group in obj['value']['data']:
            if ig_name == insights_group['name']:
                for site in insights_group['assuranceEntities']:
                    if site['name'] == site_name:
                        return site['uuid']

    def get_pre_change_result(self, pcv_results, name, site_id, path,  **kwargs):
        pcv_result = {}
        for pcv in pcv_results:
            if pcv.get("name") == name and pcv.get("fabricUuid") == site_id:
                pcv_job_id = pcv.get("jobId")
                pcv_path = '{0}/{1}'.format(path, pcv_job_id)
                obj = self.nd.query_obj(pcv_path,  **kwargs)
                pcv_result = obj['value']['data']
        return pcv_result

    def get_epochs(self, ig_name, site_name):
        ig_base_path = self.event_insight_group_path.format(ig_name, site_name)
        path = '{0}/epochs?$size=1&$status=FINISHED'.format(ig_base_path)
        obj = self.nd.query_obj(path, prefix=self.prefix)
        return obj['value']['data'][0]

    def query_data(self, path):
        obj = self.nd.query_obj(path, prefix = self.prefix)
        return obj['value']['data']

    def query_compliance_score(self, ig_name, site_name, compliance_epoch_id):
        ig_base_path = self.event_insight_group_path.format(ig_name, site_name)
        path = "{0}/{1}/complianceScore?%24epochId={2}".format(ig_base_path, self.compliance_path, compliance_epoch_id)
        return self.query_data(path)

    def query_compliance_count(self, ig_name, site_name, compliance_epoch_id):
        ig_base_path = self.event_insight_group_path.format(ig_name, site_name)
        path = "{0}/{1}/count?%24epochId={2}".format(ig_base_path, self.compliance_path, compliance_epoch_id)
        return self.query_data(path)

    def query_entry(self, ig_name, site_name, epoch_delta_job_id):
        epoch_delta_ig_path = self.epoch_delta_ig_path.format(ig_name, site_name, epoch_delta_job_id)
        path = "{0}/individualTable?epochStatus=BOTH_EPOCHS".format(epoch_delta_ig_path)
        obj = self.nd.query_obj(path, prefix = self.prefix)
        return obj['entries']

    def format_event_severity(self, events_severity):
        result = {}
        for each in events_severity:
            event_severity_type = each.get("bucket").lower().split('_')[-1]
            result[event_severity_type] = {}
            for output in each.get("output"):
                epoch = output.get("bucket").lower()
                epoch_count = output.get("count")
                result[event_severity_type][epoch] = epoch_count
        return result

    def format_impacted_resource(self, impacted_resource):
        result = {}
        for each in impacted_resource:
            resource = each.get("bucket").lower()
            result[resource] = {}
            for output in each.get("output"):
                for epoch in output.get("output"):
                    epoch_type = epoch.get("bucket").lower()
                    count = epoch.get("count")
                    result[resource][epoch_type] = count
        return result

    def query_event_severity(self, ig_name, site_name, epoch_delta_job_id):
        epoch_delta_ig_path = self.epoch_delta_ig_path.format(ig_name, site_name, epoch_delta_job_id)
        path = "{0}/eventSeverity".format(epoch_delta_ig_path)
        event_severity = self.query_data(path)
        formated_event_severity = self.format_event_severity(event_severity)
        return formated_event_severity

    def query_impacted_resource(self, ig_name, site_name, epoch_delta_job_id):
        epoch_delta_ig_path = self.epoch_delta_ig_path.format(ig_name, site_name, epoch_delta_job_id)
        path = "{0}/impactedResource".format(epoch_delta_ig_path)
        impacted_resource = self.query_data(path)
        formated_impacted_resource = self.format_impacted_resource(impacted_resource)
        return formated_impacted_resource

    def format_messages(self, messages):
        result = {}
        for message in messages:
            msg = message.get("message")
            severity = message.get("severity").lower()
            result[severity] = msg
        return result

    def query_messages(self, path):
        obj = self.nd.query_obj(path, prefix=self.prefix)
        if obj.get("messages") is not None:
            result = self.format_messages(obj.get("messages"))
            return result

    def query_compliance_smart_event(self, ig_name, site_name, compliance_epoch_id):
        ig_base_path = self.event_insight_group_path.format(ig_name, site_name)
        path = "{0}/smartEvents?%24epochId={1}&%24page=0&%24size=10&%24sort=-severity&category=COMPLIANCE".format(ig_base_path, compliance_epoch_id)
        smart_event = self.query_messages(path)
        return smart_event

    def query_msg_with_data(self, ig_name, site_name, path):
        ig_base_path = self.event_insight_group_path.format(ig_name, site_name)
        path = "{0}/{1}/{2}".format(ig_base_path, self.compliance_path, path)
        result = {}
        obj = self.nd.query_obj(path, prefix=self.prefix)
        if obj.get("messages") is not None:
            message = self.format_messages(obj.get("messages"))
            if len(message) > 0:
                result["messages"] = message
        data = obj.get("value")["data"]
        if len(data) > 0:
            result["data"] = data
        return result

    def query_unhealthy_resources(self, ig_name, site_name, compliance_epoch_id):
        result = {}
        ig_base_path = self.event_insight_group_path.format(ig_name, site_name)
        path = "{0}/{1}/eventUnhealthyResources?%24epochId={2}".format(ig_base_path, self.compliance_path, compliance_epoch_id)
        objs = self.query_data(path)
        for obj in objs:
            result[obj.get("bucket")] = {"count": obj.get("count"), "total": obj.get("total")}
        return result

    def query_pcvs(self, ig_name):
        pcvs_path = '{0}/{1}/prechangeAnalysis?$sort=-analysisSubmissionTime'.format(self.config_ig_path, ig_name)
        obj = self.nd.query_obj(pcvs_path, prefix=self.prefix)
        return obj['value']['data']

    def query_pcv(self, ig_name, site_name, pcv_name):
        pcv_results = self.query_pcvs(ig_name)
        if pcv_name is not None and site_name is not None:
            site_id = self.get_site_id(ig_name, site_name, prefix=self.prefix)
            pcv_path = '{0}/{1}/fabric/{2}/prechangeAnalysis'.format(self.config_ig_path, ig_name, site_name)
            pcv_result = self.get_pre_change_result(pcv_results, pcv_name, site_id, pcv_path, prefix=self.prefix)
        else:
            self.nd.fail_json(msg="site name and prechange validation job name are required")
        return pcv_result

    def is_json(self, myjson):
        try:
            json.loads(myjson)
        except ValueError:
            return False
        return True

    def load(self, fh, chunk_size=1024):
        depth = 0
        in_str = False
        items = []
        buffer = ""

        while True:
            chunk = fh.read(chunk_size)
            if len(chunk) == 0:
                break
            i = 0
            while i < len(chunk):
                c = chunk[i]
                buffer += c

                if c == '"':
                    in_str = not in_str
                elif c == '[':
                    if not in_str:
                        depth += 1
                elif c == ']':
                    if not in_str:
                        depth -= 1
                elif c == '\\':
                    buffer += c[i + 1]
                    i += 1

                if depth == 0:
                    if len(buffer.strip()) > 0:
                        j = json.loads(buffer)
                        if not isinstance(j, list):
                            raise AssertionError("")
                        items += j
                    buffer = ""

                i += 1

        if depth != 0:
            raise AssertionError("Error in loading input json")
        return items

    def get_aci_class(self, prefix):
        """
        Contains a hardcoded mapping between dn prefix and aci class.
        E.g for the input identifier prefix of "tn"
        this function will return "fvTenant"
        """

        if prefix == "tn":
            return "fvTenant"
        elif prefix == "epg":
            return "fvAEPg"
        elif prefix == "rscons":
            return "fvRsCons"
        elif prefix == "rsprov":
            return "fvRsProv"
        elif prefix == "rsdomAtt":
            return "fvRsDomAtt"
        elif prefix == "attenp":
            return "infraAttEntityP"
        elif prefix == "rsdomP":
            return "infraRsDomP"
        elif prefix == "ap":
            return "fvAp"
        elif prefix == "BD":
            return "fvBD"
        elif prefix == "subnet":
            return "fvSubnet"
        elif prefix == "rsBDToOut":
            return "fvRsBDToOut"
        elif prefix == "brc":
            return "vzBrCP"
        elif prefix == "subj":
            return "vzSubj"
        elif prefix == "rssubjFiltAtt":
            return "vzRsSubjFiltAtt"
        elif prefix == "flt":
            return "vzFilter"
        elif prefix == "e":
            return "vzEntry"
        elif prefix == "out":
            return "l3extOut"
        elif prefix == "instP":
            return "l3extInstP"
        elif prefix == "extsubnet":
            return "l3extSubnet"
        elif prefix == "rttag":
            return "l3extRouteTagPol"
        elif prefix == "rspathAtt":
            return "fvRsPathAtt"
        elif prefix == "leaves":
            return "infraLeafS"
        elif prefix == "taboo":
            return "vzTaboo"
        elif prefix == "destgrp":
            return "spanDestGrp"
        elif prefix == "srcgrp":
            return "spanSrcGrp"
        elif prefix == "spanlbl":
            return "spanSpanLbl"
        elif prefix == "ctx":
            return "fvCtx"
        else:
            return False

    def construct_tree(self, item_list):
        """
        Given a flat list of items, each with a dn. Construct a tree representing their relative relationships.
        E.g. Given [/a/b/c/d, /a/b, /a/b/c/e, /a/f, /z], the function will construct
        __root__
          - a (no data)
             - b (data of /a/b)
               - c (no data)
                 - d (data of /a/b/c/d)
                 - e (data of /a/b/c/e)
             - f (data of /a/f)
          - z (data of /z)
        __root__ is a predefined name, you could replace this with a flag root:True/False
        """
        tree = {'data': None, 'name': '__root__', 'children': {}}

        for item in item_list:
            for nm, desc in item.items():
                if 'attributes' not in desc:
                    raise AssertionError("attributes not in desc")
                attr = desc.get('attributes')
                if 'dn' not in attr:
                    raise AssertionError("dn not in desc")
                if 'children' in desc:
                    existing_children = desc.get('children')
                    self.cmap[attr['dn']] = existing_children
                path = self.parse_path(attr['dn'])
                cursor = tree
                curr_node_dn = ""
                for node in path:
                    curr_node_dn += "/" + str(node)
                    if curr_node_dn[0] == "/":
                        curr_node_dn = curr_node_dn[1:]
                    if node not in cursor['children']:
                        if node == 'uni':
                            cursor['children'][node] = {
                                'data': None,
                                'name': node,
                                'children': {}
                            }
                        else:
                            aci_class_identifier = node.split("-")[0]
                            aci_class = self.get_aci_class(
                                aci_class_identifier)
                            if not aci_class:
                                return False
                            data_dic = {}
                            data_dic['attributes'] = dict(dn=curr_node_dn)
                            cursor['children'][node] = {
                                'data': (aci_class, data_dic),
                                'name': node,
                                'children': {}
                            }
                    cursor = cursor['children'][node]
                cursor['data'] = (nm, desc)
                cursor['name'] = path[-1]

        return tree

    def parse_path(self, dn):
        """
        Grouping aware extraction of items in a path
        E.g. for /a[b/c/d]/b/c/d/e extracts [a[b/c/d/], b, c, d, e]
        """

        path = []
        buffer = ""
        i = 0
        while i < len(dn):
            if dn[i] == '[':
                while i < len(dn) and dn[i] != ']':
                    buffer += dn[i]
                    i += 1

            if dn[i] == '/':
                path.append(buffer)
                buffer = ""
            else:
                buffer += dn[i]

            i += 1

        path.append(buffer)
        return path

    def find_tree_roots(self, tree):
        """
        Find roots for tree export. This involves finding all "fake" (dataless) nodes.
        E.g. for the tree
        __root__
          - a (no data)
             - b (data of /a/b)
               - c (no data)
                 - d (data of /a/b/c/d)
                 - e (data of /a/b/c/e)
             - f (data of /a/f)
          - z (data of /z)s
        This function will return [__root__, a, c]
        """
        if tree['data'] is not None:
            return [tree]

        roots = []
        for child in tree['children'].values():
            roots += self.find_tree_roots(child)

        return roots

    def export_tree(self, tree):
        """
        Exports the constructed tree to a hierarchial json representation. (equal to tn-ansible, except for ordering)
        """
        tree_data = {
            'attributes': tree['data'][1]['attributes']
        }
        children = []
        for child in tree['children'].values():
            children.append(self.export_tree(child))

        if len(children) > 0:
            tree_data['children'] = children

        return {tree['data'][0]: tree_data}

    def copy_children(self, tree):
        '''
        Copies existing children objects to the built tree
        '''
        cmap = self.cmap
        for dn, children in cmap.items():
            aci_class = self.get_aci_class(
                (self.parse_path(dn)[-1]).split("-")[0])
            json_path_expr_search = parse('$..children.[*].{0}'.format(aci_class))
            json_path_expr_update = parse(str([str(match.full_path) for match in json_path_expr_search.find(
                tree) if match.value['attributes']['dn'] == dn][0]))
            curr_obj = [
                match.value for match in json_path_expr_update.find(tree)][0]
            if 'children' in curr_obj:
                for child in children:
                    curr_obj['children'].append(child)
            elif 'children' not in curr_obj:
                curr_obj['children'] = []
                for child in children:
                    curr_obj['children'].append(child)
            json_path_expr_update.update(curr_obj, tree)

        return

    def create_structured_data(self, tree, file):
        if tree is False:
            self.module.fail_json(
                msg="Error parsing input file, unsupported object found in hierarchy.",
                **self.result)
        tree_roots = self.find_tree_roots(tree)
        ansible_ds = {}
        for root in tree_roots:
            exp = self.export_tree(root)
            for key, val in exp.items():
                ansible_ds[key] = val
        self.copy_children(ansible_ds)
        toplevel = {"totalCount": "1", "imdata": []}
        toplevel['imdata'].append(ansible_ds)
        with open(file, 'w') as f:
            json.dump(toplevel, f)
        self.cmap = {}
        f.close()



