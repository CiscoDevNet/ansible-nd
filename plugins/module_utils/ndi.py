# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Lionel Hercot (@lhercot) <lhercot@cisco.com>
# Copyright: (c) 2022, Cindy Zhao (@cizhao) <cizhao@cisco.com>
# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
import json

try:
    from jsonpath_ng import parse

    HAS_JSONPATH_NG_PARSE = True
except ImportError:
    HAS_JSONPATH_NG_PARSE = False
__metaclass__ = type

from ansible_collections.cisco.nd.plugins.module_utils.constants import OBJECT_TYPES, MATCH_TYPES


def get_object_selector_payload(object_selector, object_type):
    payload = {"includes": [], "excludes": [], "selectorType": OBJECT_TYPES.get(object_type)}
    for match_criteria in object_selector:
        criteria_payload = []
        for match in match_criteria.get("matches"):
            match_object_type = MATCH_TYPES.get(match["object_type"])
            match_payload = {match_object_type.get("match_value"): {"objectAttribute": match.get("object_attribute")}}
            for pattern in match.get("matches_pattern"):
                pattern_value = MATCH_TYPES.get(pattern.get("match_type")).get("pattern_value")
                match_payload[match_object_type.get("match_value")][pattern_value] = {
                    "type": pattern.get("pattern_type").upper(),
                    "pattern": pattern.get("pattern") if pattern.get("pattern") else "",
                }
            criteria_payload.append(match_payload)
        payload["{0}s".format(match_criteria.get("match_criteria_type"))].append({"matches": criteria_payload})
    return payload


class NDI:
    def __init__(self, nd_module):
        self.nd = nd_module
        self.cmap = {}
        self.prefix = "/sedgeapi/v1/cisco-nir/api/api/telemetry/v2"
        self.config_ig_path = "config/insightsGroup"
        self.event_insight_group_path = "events/insightsGroup/{0}/fabric/{1}"
        self.compliance_path = "model/aciPolicy/complianceAnalysis"
        self.epoch_delta_ig_path = "epochDelta/insightsGroup/{0}/fabric/{1}/job/{2}/health/view"
        self.run_analysis_ig_path = "{0}/fabric/{1}/runOnlineAnalysis"
        self.run_epoch_delta_ig_path = "{0}/fabric/{1}/runEpochDelta"
        self.jobs_ig_path = "jobs/summary.json"
        self.requirements_path = "config/insightsGroup/{0}/requirements"

    def get_site_id(self, ig_name, site_name, **kwargs):
        obj = self.nd.query_obj(self.config_ig_path, **kwargs)
        for insights_group in obj["value"]["data"]:
            if ig_name == insights_group["name"]:
                for site in insights_group["assuranceEntities"]:
                    if site["name"] == site_name:
                        return site["uuid"]

    def get_pre_change_result(self, pcv_results, name, site_id, path, **kwargs):
        pcv_result = {}
        for pcv in pcv_results:
            if pcv.get("name") == name and pcv.get("fabricUuid") == site_id:
                pcv_job_id = pcv.get("jobId")
                pcv_path = "{0}/{1}".format(path, pcv_job_id)
                obj = self.nd.query_obj(pcv_path, **kwargs)
                pcv_result = obj["value"]["data"]
        return pcv_result

    def get_last_epoch(self, ig_name, site_name):
        ig_base_path = self.event_insight_group_path.format(ig_name, site_name)
        path = "{0}/epochs?$size=1&$status=FINISHED&%24epochType=ONLINE%2C+OFFLINE&%24sort=-collectionTime%2C-analysisStartTime".format(ig_base_path)
        obj = self.nd.query_obj(path, prefix=self.prefix)
        return obj["value"]["data"][0]

    def get_epoch_by_jobid(self, ig_name, site_name, job_id):
        ig_base_path = self.event_insight_group_path.format(ig_name, site_name)
        path = "{0}/epochs?analysisId={1}".format(ig_base_path, job_id)
        obj = self.nd.query_obj(path, prefix=self.prefix)
        return obj["value"]["data"][0]

    def query_data(self, path):
        obj = self.nd.query_obj(path, prefix=self.prefix)
        return obj["value"]["data"]

    def query_compliance_score(self, ig_name, site_name, compliance_epoch_id):
        ig_base_path = self.event_insight_group_path.format(ig_name, site_name)
        path = "{0}/{1}/complianceScore?%24epochId={2}".format(ig_base_path, self.compliance_path, compliance_epoch_id)
        return self.query_data(path)

    def query_compliance_count(self, ig_name, site_name, compliance_epoch_id):
        ig_base_path = self.event_insight_group_path.format(ig_name, site_name)
        path = "{0}/{1}/count?%24epochId={2}".format(ig_base_path, self.compliance_path, compliance_epoch_id)
        return self.query_data(path)

    def query_entry(self, path, size):
        obj = self.nd.query_obj(path.format(size, 0), prefix=self.prefix)
        entries = obj.get("entries")
        if entries is None or len(entries) == 0:
            return []
        else:
            pages, last_page = divmod(obj.get("totalItemsCount"), size)
            if pages == 0 or (pages == 1 and last_page == 0):
                return entries
            if last_page > 0:
                pages += 1
            for page in range(1, pages):
                obj = self.nd.query_obj(path.format(size, page), prefix=self.prefix)
                entries += obj.get("entries")
            return entries

    def query_anomalies(self, ig_name, site_name, epoch_delta_job_id, epoch_choice, exclude_ack_anomalies):
        epoch_delta_ig_path = self.epoch_delta_ig_path.format(ig_name, site_name, epoch_delta_job_id)
        size = 100
        path = epoch_delta_ig_path + "/individualTable?%24size={0}&%24page={1}"
        if epoch_choice:
            path = "{0}&epochStatus={1}".format(path, epoch_choice)
        entries = self.query_entry(path, size)
        result = []
        for entry in entries:
            if entry.get("severity") != "info":
                if exclude_ack_anomalies:
                    if not entry.get("acknowledged"):
                        result.append(entry)
                else:
                    result.append(entry)
        return result

    def query_instant_assurance_analysis(self, ig_name, site_name, jobId=None):
        instant_assurance_jobs_path = (
            self.jobs_ig_path
            + "?insightsGroupName={0}&fabricName={1}&orderBy=startTs,desc&filter=(jobType:ONLINE\\-ANALYSIS*%20AND%20triggeredBy:INSTANT)&startTs={2}".format(
                ig_name, site_name, 0
            )
        )
        if jobId:
            instant_assurance_jobs_path = instant_assurance_jobs_path + "&jobId={0}".format(jobId)

        size = 1000
        path = instant_assurance_jobs_path
        # + "&count={0}&offset={1}" does not work with current implementation of query_entry

        entries = self.query_entry(path, size)
        return entries

    def query_delta_analysis(self, ig_name, site_name, jobId=None, jobName=None):
        if jobId:
            delta_job_path = (
                self.jobs_ig_path
                + "?jobType=EPOCH-DELTA-ANALYSIS&insightsGroupName={0}&fabricName={1}&filter=(!configData:pcvJobId%20AND%20jobId:{2})".format(
                    ig_name, site_name, jobId
                )
            )
            entries = self.query_entry(delta_job_path, 1)
            if len(entries) == 1:
                return entries[0]
            else:
                return {}
        elif jobName:
            delta_job_path = (
                self.jobs_ig_path
                + "?jobType=EPOCH-DELTA-ANALYSIS&insightsGroupName={0}&fabricName={1}&filter=(!configData:pcvJobId%20AND%20jobName:{2})".format(
                    ig_name, site_name, jobName
                )
            )
            entries = self.query_entry(delta_job_path, 1)
            if len(entries) == 1:
                return entries[0]
            else:
                return {}
        else:
            delta_jobs_path = (
                self.jobs_ig_path
                + "?jobType=EPOCH-DELTA-ANALYSIS&insightsGroupName={0}&fabricName={1}&filter=(!configData:pcvJobId)&orderBy=startTs,desc&startTs={2}".format(
                    ig_name, site_name, 0
                )
            )
            size = 1000
            path = delta_jobs_path
            # + "&count={0}&offset={1}" does not work with current implementation of query_entry

            entries = self.query_entry(path, size)
            return entries

    def format_event_severity(self, events_severity):
        result = {}
        for each in events_severity:
            event_severity_type = each.get("bucket").lower().split("_")[-1]
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
        size = 100
        path = "{0}/smartEvents?%24epochId={1}".format(ig_base_path, compliance_epoch_id)
        event_path = path + "&%24size={0}&%24page={1}&%24sort=-severity&category=COMPLIANCE"
        smart_event = self.query_entry(event_path, size)
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
        pcvs_path = "{0}/{1}/prechangeAnalysis?$sort=-analysisSubmissionTime".format(self.config_ig_path, ig_name)
        obj = self.nd.query_obj(pcvs_path, prefix=self.prefix)
        return obj["value"]["data"]

    def query_pcv(self, ig_name, site_name, pcv_name):
        pcv_results = self.query_pcvs(ig_name)
        if pcv_name is not None and site_name is not None:
            site_id = self.get_site_id(ig_name, site_name, prefix=self.prefix)
            pcv_path = "{0}/{1}/fabric/{2}/prechangeAnalysis".format(self.config_ig_path, ig_name, site_name)
            pcv_result = self.get_pre_change_result(pcv_results, pcv_name, site_id, pcv_path, prefix=self.prefix)
        else:
            self.nd.fail_json(msg="site name and prechange validation job name are required")
        return pcv_result

    def query_requirements(self, ig_name):
        requirements_path = "{0}/list".format(self.requirements_path.format(ig_name))
        obj = self.nd.query_obj(requirements_path, prefix=self.prefix)
        return obj.get("value", {}).get("data", []) if obj.get("value") else []

    def set_requirement_details(self, requirements, name):
        if name:
            self.nd.existing = next((item for item in requirements if item.get("name") == name), {})
            uuid = self.nd.existing.get("uuid")
        else:
            self.nd.existing = requirements
            uuid = None
        return uuid

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
                elif c == "[":
                    if not in_str:
                        depth += 1
                elif c == "]":
                    if not in_str:
                        depth -= 1
                elif c == "\\":
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
        tree = {"data": None, "name": "__root__", "children": {}}

        for item in item_list:
            for nm, desc in item.items():
                if "attributes" not in desc:
                    raise AssertionError("attributes not in desc")
                attr = desc.get("attributes")
                if "dn" not in attr:
                    raise AssertionError("dn not in desc")
                if "children" in desc:
                    existing_children = desc.get("children")
                    self.cmap[attr["dn"]] = existing_children
                path = self.parse_path(attr["dn"])
                cursor = tree
                curr_node_dn = ""
                for node in path:
                    curr_node_dn += "/" + str(node)
                    if curr_node_dn[0] == "/":
                        curr_node_dn = curr_node_dn[1:]
                    if node not in cursor["children"]:
                        if node == "uni":
                            cursor["children"][node] = {"data": None, "name": node, "children": {}}
                        else:
                            aci_class_identifier = node.split("-")[0]
                            aci_class = self.get_aci_class(aci_class_identifier)
                            if not aci_class:
                                return False
                            data_dic = {}
                            data_dic["attributes"] = dict(dn=curr_node_dn, name=node.split("-", 1)[1])
                            cursor["children"][node] = {"data": (aci_class, data_dic), "children": {}}
                    cursor = cursor["children"][node]
                cursor["data"] = (nm, desc)
                cursor["name"] = path[-1]

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
            if dn[i] == "[":
                while i < len(dn) and dn[i] != "]":
                    buffer += dn[i]
                    i += 1

            if dn[i] == "/":
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
        if tree["data"] is not None:
            return [tree]

        roots = []
        for child in tree["children"].values():
            roots += self.find_tree_roots(child)

        return roots

    def export_tree(self, tree):
        """
        Exports the constructed tree to a hierarchial json representation. (equal to tn-ansible, except for ordering)
        """
        tree_data = {"attributes": tree["data"][1]["attributes"]}
        children = []
        for child in tree["children"].values():
            children.append(self.export_tree(child))

        if len(children) > 0:
            tree_data["children"] = children

        return {tree["data"][0]: tree_data}

    def copy_children(self, tree):
        """
        Copies existing children objects to the built tree
        """
        cmap = self.cmap
        for dn, children in cmap.items():
            aci_class = self.get_aci_class((self.parse_path(dn)[-1]).split("-")[0])
            if not HAS_JSONPATH_NG_PARSE:
                self.nd.fail_json(msg="Cannot use jsonpath-ng parse() because jsonpath-ng module is not available")
            json_path_expr_search = parse("$..children.[*].{0}".format(aci_class))
            json_path_expr_update = parse(
                str([str(match.full_path) for match in json_path_expr_search.find(tree) if match.value["attributes"]["dn"] == dn][0])
            )
            curr_obj = [match.value for match in json_path_expr_update.find(tree)][0]
            if "children" in curr_obj:
                for child in children:
                    curr_obj["children"].append(child)
            elif "children" not in curr_obj:
                curr_obj["children"] = []
                for child in children:
                    curr_obj["children"].append(child)
            json_path_expr_update.update(curr_obj, tree)

        return

    def create_structured_data(self, tree, file):
        if tree is False:
            self.module.fail_json(msg="Error parsing input file, unsupported object found in hierarchy.", **self.result)
        tree_roots = self.find_tree_roots(tree)
        ansible_ds = {}
        for root in tree_roots:
            exp = self.export_tree(root)
            for key, val in exp.items():
                ansible_ds[key] = val
        self.copy_children(ansible_ds)
        toplevel = {"totalCount": "1", "imdata": []}
        toplevel["imdata"].append(ansible_ds)
        with open(file, "w") as f:
            json.dump(toplevel, f)
        self.cmap = {}
        f.close()
