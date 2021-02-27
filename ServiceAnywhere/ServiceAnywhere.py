import sys
from http.client import HTTPSConnection
import ssl
import json
import logging
import datetime
import calendar
from AllVulnsApp.com.core.plugins.BasePlugin import BasePlugin



log=logging.getLogger(__name__)

CREATE_CHANGE="""{{
    "entities": [
        {{
            "entity_type": "Change",
            "properties": {{
                "DisplayLabel": "Remove Unused Firewall Rules",
                "ImpactScopeCC_c": "Enterprise_c",
                "OwnedByPerson": "26956",
                "RequestedEndTime": {endTime},
                "BreachStatus": "NotInBreach",
                "Justification": "<p>Algosec Determined that these firewall rules are no longer being utilized.<br>Networking has reviewed these rules and determined they can be removed.</p>",
                "PhaseId": "ApprovePlan",
                "AffectsActualService": "24112",
                "ImplementationPlan": "<p>Algosec Determined that these firewall rules are no longer being utilized.<br>Networking has reviewed these rules and determined they can be removed.",
                "Priority": "HighPriority",
                "OwnedByGroup": "20343",
                "RiskAssessment": "SomeRisk",
                "Description": "<p>Remove firewall rules delineated in 'Plan and execute'</p>",
                "Category": "20492",
                "ScheduledEndTime": {endTime},
                "BackoutPlan": "<p>Reinstate firewall rules</p>",
                "RequestedByPerson": "270424",
                "NumberOfAttachments": 1,
                "ReasonForChange": "SecurityPatchSecurityVulnerability_c",
                "BasedOnChangeModel": "19765",
                "NumberOfRelatedRecords": 0,
                "ChangeWorkflowType": "NormalChange",
                "ProcessId": "Normal",
                "ScheduledStartTime": {startTime},
                "ModelWorkflow": "0",
                "Urgency": "SlightDisruption"
            }}
        }}
    ],
    "operation":"CREATE"
}}"""

class serviceAnywhereIntegration(BasePlugin):
    def __init__(self,pluginconfig):
        super().__init__(pluginconfig)
        if self.pluginconfig.host:
            context = ssl._create_unverified_context()
            self.connection=HTTPSConnection(host=self.pluginconfig.host, port=self.pluginconfig.port, context=context)
            payload = {"Login":self.pluginconfig.user.username, "Password":self.pluginconfig.user.password}
            bodyData=bytes(json.dumps(payload), encoding="utf-8")
            headers={}
            self.connection.request("POST", "/auth/authentication-endpoint/authenticate/login", bodyData, headers)
            res = self.connection.getresponse()
            data = res.read()
            self.LWSSO_COOKIE_KEY = data.decode("utf-8")
            log.debug("Logged into Change Control")


    def getHeaders(self):
        cookieString="LWSSO_COOKIE_KEY="+self.LWSSO_COOKIE_KEY+ "; path=/; Secure; HttpOnly;"
        headers = {'Cookie':cookieString,"Content-Type":"application/json"}
        
        return headers
    
    def createRemoveRulesChangeRequest(self,rules,user):
        if self.connection:
            tommorrow = datetime.date.today () + datetime.timedelta (days=1)
            startTime = datetime.time(hour=10, minute=0)
            endTime = datetime.time(hour=12, minute=0)

            while tommorrow.weekday() != 3:
                tommorrow += datetime.timedelta(1)

            startTime = calendar.timegm(datetime.datetime.combine(tommorrow, startTime).timetuple())
            endTime = calendar.timegm(datetime.datetime.combine(tommorrow, endTime).timetuple())
            startTime=startTime*1000
            endTime=endTime*1000

            changeRequest=CREATE_CHANGE.format(endTime=endTime, startTime=startTime)
            log.info("Created Service Anywhere Ticke # "+str(changeRequest))
            conn=self.connection
            jsonData= json.loads(changeRequest)
            signature="<b>[Reviewed By: "+user.username+"]</b>"
            rulesTable=self.createTable(rules)
            appendData="<br>"+signature+"<br>"+rulesTable
            jsonData['entities'][0]['properties']['Justification']=jsonData['entities'][0]['properties']['Justification']+appendData
            jsonData['entities'][0]['properties']['ImplementationPlan']=jsonData['entities'][0]['properties']['ImplementationPlan']+appendData
            payload = json.dumps(jsonData)
            headers = self.getHeaders()
            conn.request("POST", "/rest/674946639/ems/bulk", payload, headers)
            res = conn.getresponse()
            data = res.read()
            stringData=data.decode("utf-8")
            jsonData=json.loads(stringData)
            changeId=jsonData["entity_result_list"][0]["entity"]["properties"]["Id"]
            return changeId
     
    def createTable(self,rules):
        tableHeader="""<table><thead><tr>
        <th>DeviceID</th>
        <th>DeviceIP</th>
        <th>Rule</th>
        <th>Source</th>
        <th>Destination</th>
        <th>Service</th>
        <th>Comment</th>
        <th>LastUse</th>
        </tr></thead>"""
        tableRows=""
        for rule in rules:
            tableRows = tableRows+"<tr><td>"+str(rule.DeviceID)+"<tr><td>"+str(rule.DeviceIP)+"</td><td>"+str(rule.Rule)
            tableRows = tableRows+"</td><td>"+str(rule.Source)+"</td><td>"+str(rule.Destination)+"</td><td>"+str(rule.Service)
            tableRows = tableRows+"</td><td>"+str(rule.Comment)+"</td><td>"+str(rule.LastUse)+"</tr>"
        tableFooter="</table>"
        return tableHeader+tableRows+tableFooter