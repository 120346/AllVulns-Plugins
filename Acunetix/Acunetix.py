#!/usr/bin/env python
import datetime
import json
import logging
import ssl
import sys
from http.client import HTTPSConnection
import psycopg2
from django.utils.dateparse import parse_datetime
from AllVulnsApp.com.core.plugins.BaseWebScanner import BaseWebScanner
from AllVulnsApp.com.core.plugins.BaseWebScanner import BaseScanner

# are we running inside Blender?
bpy = sys.modules.get("bpy")
if bpy is not None:
    sys.executable = bpy.app.binary_path_python
    # get the text-block's filepath
    __file__ = bpy.data.texts[__file__[1:]].filepath
del bpy

log = logging.getLogger(__name__)

targets = {}
targetIDs = []

severity = ["Medium", "Medium", "High", "Critical"]


class Scanner(BaseWebScanner):
    def __init__(self,pluginconfig):
        super().__init__(pluginconfig)
        self.connection=None
        if self.pluginconfig.host:
            context = ssl._create_unverified_context()
            now = datetime.datetime.now()
            self.summaryDate = now.strftime("%Y%m%d")
            self.headers = {'X-Auth': self.pluginconfig.apiKey, 'content-type': "application/json"}
            self.connection = HTTPSConnection(host=self.pluginconfig.host, port=self.pluginconfig.port, context=context)

    def getAdditionalConfigNames(self):
        return ['apiKey','scanProfileId','reportTemplateId','dbName','dbUser','dbPassword','dbHost','dbPort']

    def scan(self, appName, scanDate, pentest, nmapInfo=None, hostString=None):
        if self.connection:
            for ip in nmapInfo:
                for entry in nmapInfo[ip]:
                    if entry == 'reverseDNS':
                        url = nmapInfo[ip]['reverseDNS']
                    else:
                        port = entry
                        url = nmapInfo[ip][port]['url']
                    url = nmapInfo[ip][port]['url']
                    if url != '':
                        if isinstance(url, list):
                            for uri_entry in url:
                                targetId = self.getTargetId(uri_entry.domain, appName)
                                self.scanTarget(targetId, scanDate)
                                self.addTargetToPentest(targetId, pentest)

                        else:
                            targetId = self.getTargetId(url, appName)
                            self.scanTarget(targetId, scanDate)
                            self.addTargetToPentest(targetId, pentest)

    def getVulnerabilities(self, targetId, pentest):
        if self.connection:
            startTime = pentest.startDate
            webTarget = self.getWebTarget(targetId, pentest)

            vulns = super(Scanner, self).getVulnerabilitiesByTarget(webTarget)
            # vulns=None
            if vulns and (
                    webTarget.status == 'completed' or webTarget.status == 'failed' or webTarget.status == 'aborted'):
                for vuln in vulns:
                    json_data = vuln.references
                    if json_data:
                        vuln.references = json.loads(json_data)
                return vulns
            else:
                payload = ""
                self.connection.request("GET", "/api/v1/vulnerabilities?q=target_id:" + targetId + ";status:open", payload,
                                        self.headers)
                res = self.connection.getresponse()
                data = res.read()
                vulnerabilities = self.getDetails(json.loads(data)["vulnerabilities"], startTime, webTarget)
                for vuln in vulnerabilities:
                    json_data = vuln.references
                    if json_data:
                        vuln.references = json.loads(json_data)
                return vulnerabilities



    def getStatus(self, target):
        if self.connection:
            if target.status != 'completed' and target.status != 'failed':
                payload = ""
                self.connection.request("GET",
                                        "/api/v1/scans?q=profile_id:" + self.pluginconfig.scanProfileId + ";target_id:" + target.target,
                                        payload, self.headers)
                res = self.connection.getresponse()
                data = res.read()
                response = json.loads(data)
                status = {}
                status['address'] = response['scans'][0]['target']['address']
                status['status'] = response['scans'][0]['current_session']['status']
                target.status = status['status']
                target.address = status['address']
                if (target.address):
                    log.debug("Scanning... Status:" + str(target.status) + " URL:" + str(target.address))
                    self.checkDefaultPage(target)
                status['defaultScreenShot'] = target.defaultScreenShot
                target.save()
            else:
                status = {}
                status['address'] = target.address
                status['status'] = target.status
                status['defaultScreenShot'] = target.defaultScreenShot
            return status

    def getAcunetixDBCon(self):
        conn = psycopg2.connect(
            dbname=self.pluginconfig.dbName,
            user=self.pluginconfig.dbUser,
            password=self.pluginconfig.dbPassword,
            host=self.pluginconfig.dbHost,
            port=self.pluginconfig.dbPort)
        return conn


    def loadAllTargets(self):
        try:
            conn = self.getAcunetixDBCon()
            cur = conn.cursor()
            cur.execute("SELECT target_id,address FROM targets;")
            results = cur.fetchall()
            conn.close()
            for target in results:
                targets[target[1]] = target[0]
        except Exception as e:
            log.error(e)


    def getTargetId(self, address, appName):
        if len(targets) < 1:
            self.loadAllTargets()
        if address in targets:
            return targets[address]
        request_body = {}
        request_body['address'] = address
        request_body['criticality'] = '10'
        request_body['description'] = appName
        bodyData = bytes(json.dumps(request_body), encoding="utf-8")
        self.connection.request("POST", "/api/v1/targets", headers=self.headers, body=bodyData)
        res = self.connection.getresponse()
        data = json.loads(res.read())
        targets[address] = data['target_id']
        return targets[address]

    def scanTarget(self, targetId, scanDate):
        payload = {
            'profile_id': self.pluginconfig.scanProfileId,
            'report_template_id': self.pluginconfig.reportTemplateId,
            "schedule": {
                "start_date": scanDate,
                "disable": False,
                "time_sensitive": True
            },
            'target_id': targetId,
        }

        bodyData = bytes(json.dumps(payload), encoding="utf-8")
        self.connection.request("POST", "/api/v1/scans", bodyData, self.headers)
        res = self.connection.getresponse()
        data = res.read()
        readableData = json.loads(data)
        return readableData


    def closeVulnerabilty(self, vunlerability):
        payload = "{status:fixed}"
        self.connection.request("PUT", "/api/v1/vulnerabilities/" + vunlerability['vuln_id'] + "/status", payload,
                                self.headers)
        res = self.connection.getresponse()
        data = res.read()
        response = json.loads(data)
        return response


    def getDetails(self, vulnerabilities, startTime, webTarget):
        status = self.getStatus(webTarget)
        if status:
            if status['status'] == "completed" or status['status'] == "failed" or webTarget.status == 'aborted':
                for vulnerability in vulnerabilities:
                    if parse_datetime(vulnerability["last_seen"]).timestamp() >= startTime.timestamp():
                        vulnerability["severity"] = severity[vulnerability["severity"]]
                        payload = ""
                        self.connection.request("GET", "/api/v1/vulnerabilities/" + vulnerability['vuln_id'], payload,self.headers)
                        res = self.connection.getresponse()
                        data = res.read()
                        vulnDetail = json.loads(data)
                        vulnerability['affects_url'] = vulnDetail['affects_url']
                        vulnerability['recommendation'] = vulnDetail['recommendation']
                        vulnerability['request'] = vulnDetail['request']
                        vulnerability['references'] = vulnDetail['references']
                        self.storeVulnerability(webTarget,vulnerability["severity"],vulnerability['vt_name'],vulnerability['affects_url'],vulnerability['recommendation'],vulnerability['request'],json.dumps(vulnerability['references']).encode("utf-8"))
                    else:
                        self.closeVulnerabilty(vulnerability)
                self.gatherEvidence()
        return self.getVulnerabilitiesByTarget(webTarget)
