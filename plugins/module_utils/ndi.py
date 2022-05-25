# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Lionel Hercot (@lhercot) <lhercot@cisco.com>
# Copyright: (c) 2022, Cindy Zhao (@cizhao) <cizhao@cisco.com>
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

class NDI:

    def __init__(self, nd_module):
        self.nd = nd_module
        self.prefix = "/sedgeapi/v1/cisco-nir/api/api/telemetry/v2"

    def get_pcv_results(self, path, **kwargs):
        obj = self.nd.query_obj(path, **kwargs)
        return obj['value']['data']

    def get_site_id(self, path, site_name, **kwargs):
        obj = self.nd.query_obj(path, **kwargs)
        for site in obj['value']['data'][0]['assuranceEntities']:
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

    def get_epochs(self, path, **kwargs):
        obj = self.nd.query_obj(path, **kwargs)
        return obj['value']['data'][0]

    def query_data(self, path, **kwargs):
        obj = self.nd.query_obj(path, **kwargs)
        return obj['value']['data']

    def query_entry(self, path, **kwargs):
        obj = self.nd.query_obj(path, **kwargs)
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

    def query_event_severity(self, path, **kwargs):
        event_severity = self.query_data(path, **kwargs)
        formated_event_severity = self.format_event_severity(event_severity)
        return formated_event_severity

    def query_impacted_resource(self, path, **kwargs):
        impacted_resource = self.query_data(path, **kwargs)
        formated_impacted_resource = self.format_impacted_resource(impacted_resource)
        return formated_impacted_resource

    def query_messages(self, path, **kwargs):
        result = {}
        self.nd.stdout = self.nd.stdout + "query obj in query message \n"
        self.nd.stdout = self.nd.stdout + "path is " + str(path) + "\n"
        obj = self.nd.query_obj(path, **kwargs)
        for message in obj.get("messages"):
            msg = message.get("message")
            severity = message.get("severity").lower()
            result[severity] = msg
        return result

    def query_compliance_smart_event(self, path, **kwargs):
        self.nd.stdout = self.nd.stdout + "inside query compliance smart event \n"
        smart_event = self.query_messages(path, **kwargs)
        return smart_event

    def query_msg_with_data(self, path, **kwargs):
        result = {}
        msg = self.query_messages(path, **kwargs)
        if len(msg) > 0:
            result["messages"] = self.query_messages(path, **kwargs)
        data = self.query_data(path, **kwargs)
        if len(data) > 0:
            result["data"] = data
        return result

    def query_unhealthy_resources(self, path, **kwargs):
        result = {}
        objs = self.query_data(path, **kwargs)
        for obj in objs:
            result[obj.get("bucket")] = {"count": obj.get("count"), "total": obj.get("total")}
        return result

    def query_pcvs(self, ig_name):
        ndi_prefix = self.prefix
        path = 'config/insightsGroup'
        pcvs_path = '{0}/{1}/prechangeAnalysis?$sort=-analysisSubmissionTime'.format(path, ig_name)
        pcv_results = self.get_pcv_results(pcvs_path, prefix=ndi_prefix)
        return pcv_results

    def query_pcv(self, ig_name, site_name, pcv_name):
        path = 'config/insightsGroup'
        ndi_prefix = self.prefix
        pcv_results = self.query_pcvs(ig_name)
        if pcv_name is not None and site_name is not None:
            site_id = self.get_site_id(path, site_name, prefix=ndi_prefix)
            pcv_path = '{0}/{1}/fabric/{2}/prechangeAnalysis'.format(path, ig_name, site_name)
            pcv_result = self.get_pre_change_result(pcv_results, pcv_name, site_id, pcv_path, prefix=ndi_prefix)
        else:
            self.nd.fail_json(msg="site name and prechange validation job name are required")
        return pcv_result
