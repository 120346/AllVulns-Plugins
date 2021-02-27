import datetime
import json
import time
from http.client import HTTPConnection
from AllVulnsApp.com.core.plugins import BaseCodeScanner
import logging
log=logging.getLogger(__name__)

severityMap = {"High": "Critical", "Medium": "High", "Low": "Medium"}


class CodeScanner(BaseCodeScanner.CodeScanner):
    def __init__(self, pluginconfig):
        super().__init__(pluginconfig)
        self.connection=None
        if self.pluginconfig.host:
            self.connection = HTTPConnection(self.pluginconfig.host, self.pluginconfig.port)
            self.headers = {"Accept-Encoding": "gzip, deflate", 'content-type': "application/json;charset=UTF-8",
                            "Accept": "*/*"}
            body = '{"username":"' + self.pluginconfig.user.username + '","password":"' + self.pluginconfig.user.password + '"}'
            self.connection.request('POST', "/api/users/auth", body, self.headers)
            res = self.connection.getresponse()
            data = res.read()
            readableData = json.loads(data)
            self.headers["Authorization"] = readableData["tokenType"] + " " + readableData["token"]


    def createApp(self, appName):
        #Not needed
        pass


    def getApplicationId(self, appName):
        if self.connection:
            self.connection.request('GET', "/api/scans", "", self.headers)
            res = self.connection.getresponse()
            data = res.read()
            readableData = json.loads(data)
            for summary in readableData:
                if summary["scanName"] == appName:
                    return summary["scanId"]

    def getScanId(self, project):
        return self.getApplicationId(project.appName)



    def getIssuesByApp(self, project):
        if self.connection:
            self.connection.request('GET', "/api/scans", "", self.headers)
            res = self.connection.getresponse()
            data = res.read()
            readableData = json.loads(data)
            appName = project.appName
            selectedScan = {}
            for summary in readableData:
                if summary["scanName"] == appName:
                    if selectedScan.get("createdTime"):
                        createdTime = datetime.datetime.strptime(summary["createdTime"], '%d/%m/%Y %I:%M:%S %p')
                        if createdTime > selectedScan["createdTime"]:
                            selectedScan["scanId"] = summary["scanId"]
                            selectedScan["createdTime"] = createdTime
                    else:
                        selectedScan["scanId"] = summary["scanId"]
                        selectedScan["createdTime"] = datetime.datetime.strptime(summary["createdTime"],
                                                                                 '%d/%m/%Y %I:%M:%S %p')
            if selectedScan:
                self.poll(selectedScan.get("scanId"), selectedScan.get("createdTime"), project)

    def poll(self, scanId, createdTime, project):
        self.connection.request('GET', "/api/scans/" + str(scanId), "", self.headers)
        res = self.connection.getresponse()
        data = res.read()
        readableData = json.loads(data)
        while readableData["status"] != "Finished":
            time.sleep(1)
            self.poll(scanId, createdTime, project)
        for summary in readableData["scanSummary"]:
            if summary["count"] > 0:
                self.connection.request('GET', "/api/scans/" + str(scanId) + "/results/vuln-type/" + str(
                    summary["vulnerabilityTypeId"]), "", self.headers)
                res = self.connection.getresponse()
                data = res.read()
                try:
                    readableData = json.loads(data)
                    severity = readableData["risk"]
                    type = readableData["name"]
                    status = "Open"
                    remediation = readableData["recommendation"]
                    for vulnerability in readableData["vulnerabilities"]:
                        description = vulnerability["description"]
                        if description == "":
                            description = readableData["description"]
                        function = vulnerability["functionCalls"][0]
                        location = function["file"] + ":" + function["name"] + ":" + function["line"]
                        inputFlow = vulnerability["userInputFlow"][len(vulnerability["userInputFlow"]) - 1]
                        flow = inputFlow["file"] + ":" + inputFlow["name"] + ":" + inputFlow["line"]
                        if location != flow:
                            location = location + "\n" + flow
                        self.storeVulnerability(project,vulnerability["uniqueId"],severity,type,location,description,remediation,status,createdTime)
                except Exception as e:
                    log.error(e)
                    log.error("Request Status="+str(res.status)+" Request Reason="+str(res.reason)+ " Data="+str(data))
                    pass
