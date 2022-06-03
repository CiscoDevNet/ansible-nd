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
        self.config_ig_path = "config/insightsGroup"
        self.event_insight_group_path = "events/insightsGroup/{0}/fabric/{1}"
        self.compliance_path = "model/aciPolicy/complianceAnalysis"

    def get_pcv_results(self, path, **kwargs):
        obj = self.nd.query_obj(path, **kwargs)
        return obj['value']['data']

    def get_site_id(self, site_name, **kwargs):
        obj = self.nd.query_obj(self.config_ig_path, **kwargs)
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
        compliance_score = self.query_data(path)
        return compliance_score

    def query_compliance_count(self, ig_name, site_name, compliance_epoch_id):
        path = "events/insightsGroup/{0}/fabric/{1}/model/aciPolicy/complianceAnalysis/count?%24epochId={2}".format(ig_name, site_name, compliance_epoch_id)
        compliance_count = self.query_data(path)
        return compliance_count


    def query_entry(self, ig_name, site_name, epoch_delta_job_id):
        path = "epochDelta/insightsGroup/{0}/fabric/{1}/job/{2}/health/view/individualTable?epochStatus=BOTH_EPOCHS".format(ig_name, site_name, epoch_delta_job_id)
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
        path = "epochDelta/insightsGroup/{0}/fabric/{1}/job/{2}/health/view/eventSeverity".format(ig_name, site_name, epoch_delta_job_id)
        event_severity = self.query_data(path)
        formated_event_severity = self.format_event_severity(event_severity)
        return formated_event_severity

    def query_impacted_resource(self, ig_name, site_name, epoch_delta_job_id):
        path = "epochDelta/insightsGroup/{0}/fabric/{1}/job/{2}/health/view/impactedResource".format(ig_name, site_name, epoch_delta_job_id)
        impacted_resource = self.query_data(path)
        formated_impacted_resource = self.format_impacted_resource(impacted_resource)
        return formated_impacted_resource

    def query_messages(self, path):
        result = {}
        obj = self.nd.query_obj(path, prefix = self.prefix)
        if obj.get("messages") is not None:
            for message in obj.get("messages"):
                msg = message.get("message")
                severity = message.get("severity").lower()
                result[severity] = msg
        return result

    def query_compliance_smart_event(self, ig_name, site_name, compliance_epoch_id):
        path = "events/insightsGroup/{0}/fabric/{1}/smartEvents?%24epochId={2}&%24page=0&%24size=10&%24sort=-severity&category=COMPLIANCE".format(ig_name, site_name, compliance_epoch_id)
        smart_event = self.query_messages(path)
        return smart_event

    def query_msg_with_data(self, ig_name, site_name, compliance_epoch_id):
        path = "events/insightsGroup/{0}/fabric/{1}/model/aciPolicy/complianceAnalysis/eventsBySeverity?%24epochId={2}".format(ig_name, site_name, compliance_epoch_id)
        result = {}
        msg = self.query_messages(path)
        if len(msg) > 0:
            result["messages"] = msg
        data = self.query_data(path)
        if len(data) > 0:
            result["data"] = data
        return result

    def query_unhealthy_resources(self, ig_name, site_name, compliance_epoch_id):
        result = {}
        path = "events/insightsGroup/{0}/fabric/{1}/model/aciPolicy/complianceAnalysis/eventUnhealthyResources?%24epochId={2}".format(ig_name, site_name, compliance_epoch_id)
        objs = self.query_data(path)
        for obj in objs:
            result[obj.get("bucket")] = {"count": obj.get("count"), "total": obj.get("total")}
        return result

    def query_pcvs(self, ig_name):
        pcvs_path = 'config/insightsGroup/{0}/prechangeAnalysis?$sort=-analysisSubmissionTime'.format(ig_name)
        pcv_results = self.get_pcv_results(pcvs_path, prefix=self.prefix)
        return pcv_results

    def query_pcv(self, ig_name, site_name, pcv_name):
        pcv_results = self.query_pcvs(ig_name)
        if pcv_name is not None and site_name is not None:
            site_id = self.get_site_id(site_name, prefix=self.prefix)
            pcv_path = '{0}/{1}/fabric/{2}/prechangeAnalysis'.format(self.config_ig_path, ig_name, site_name)
            pcv_result = self.get_pre_change_result(pcv_results, pcv_name, site_id, pcv_path, prefix=self.prefix)
        else:
            self.nd.fail_json(msg="site name and prechange validation job name are required")
        return pcv_result
