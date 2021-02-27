#!/usr/bin/env python
import html
import json
import ssl
import urllib
from datetime import datetime, timedelta
from html import unescape
from http.client import HTTPSConnection

import dateutil.parser

from AllVulnsApp.models import AppScanIssueTypeIDMap
from AllVulnsApp.com.core.plugins.BaseCodeScanner import CodeScanner
import logging
log=logging.getLogger(__name__)

ISSUE_COLUMN_MAP = {}
ISSUE_COLUMN_MAP['12'] = 'severity'
ISSUE_COLUMN_MAP['14'] = 'issuetype'
ISSUE_COLUMN_MAP['16'] = 'location'
ISSUE_COLUMN_MAP['32'] = 'line'

ISSUE_TYPE = {}


class AppScanScanner(CodeScanner):
    def __init__(self, pluginconfig):
        super().__init__(pluginconfig)
        self.connection=None
        if self.pluginconfig.host:
            context = ssl._create_unverified_context()
            self.connection = HTTPSConnection(host=self.pluginconfig.host, port=self.pluginconfig.port, context=context)
            self.connection.request("GET", "/")
            res = self.connection.getresponse()
            if res.status != 200:
                raise Exception("AppScan Not Available")
            if self.TOKEN == '':
                headers = self.getHeaders()
                request_body = {}
                request_body['userId'] = self.pluginconfig.user.username
                request_body['password'] = self.pluginconfig.user.password
                request_body['featureKey'] = self.pluginconfig.featureKey
                bodyData = bytes(json.dumps(request_body), encoding="utf-8")
                self.connection.request("POST", "/ase/api/login", bodyData, headers)
                res = self.connection.getresponse()
                responseHeaders = res.getheaders();
                headers = self.getHeaders()
                for value in responseHeaders:
                    if value[0] == 'Set-Cookie':
                        self.headers['Cookie'] += value[1] + ";"
                data = json.loads(res.read())
                self.TOKEN = data['sessionId']
                self.headers['Asc_xsrf_token'] = self.TOKEN

    TOKEN = ''
    headers = {}

    def getAdditionalConfigNames(self):
        return ['featureKey']


    def getHeaders(self):
        if self.headers == {}:
            self.headers = {'Asc_xsrf_token': self.TOKEN,
                            'content-type': "application/json",
                            'Range': 'items=0-99',
                            'Cookie': '',
                            'Connection': 'keep-alive',
                            'X-Requested-With': 'XMLHttpRequest'
                            }
        return self.headers

    def getScanId(self, project):
        return None

    def getIssuesByApp(self, project):
        if self.connection:
            timeRangestring = ""
            objectList = self.getStoredVulnerabilities(project)
            if objectList:
                latestDate = objectList[0].date_discovered
                timeRangestring = "Last Updated=" + (latestDate + timedelta(days=1)).strftime(
                    '%Y-%m-%d') + "\," + datetime.now().strftime('%Y-%m-%d')
            appName = project.appName
            headers = self.getHeaders()
            payload = ""
            query = urllib.parse.quote("Application Name=" + appName
                                       + ",severity=medium,"
                                       + "severity=high,"
                                       + "severity=critical,"
                                       + "severity=low,"
                                       + "status=open,"
                                       + "status=inprogress,"
                                       + "status=fixed,"
                                       + "status=reopened,"
                                       + "status=new," + timeRangestring)

            columns = "issuetype,location,severity,line,status,lastupdated,description"
            sortBy = "location"
            URL = "/ase/api/issues?query=" + query + "&columns=" + columns + "&sortBy=+" + sortBy
            self.connection.request("GET", URL, payload, headers)
            res = self.connection.getresponse()
            if res.status == 200:
                data = res.read()
                readableData = json.loads(data)
                appId = self.getApplicationId(appName)
                if appId:
                    if len(readableData) == 0 and len(objectList) == 0:
                        return

                    for issue in readableData:
                        issue['16'] = html.unescape(issue['16'])
                        if '39' not in issue:
                            issueTypeId = self.getIssueTypeId(appId, issue['id'], self.connection, headers)
                            details = self.getIssueType(issueTypeId)
                            if details:
                                issue['remediations'] = details['remediations'][0]['remediation']
                                issue['39'] = details['risks'][0]['risk']
                        if not issue.get('remediations'):
                            issue['remediations'] = ""
                        self.storeVulnerability(project, issue['id'], issue['12'], unescape(issue['14']), issue['16'],
                                                issue['39'], issue['remediations'], issue['2'],
                                                dateutil.parser.parse(issue['36']))

    def getIssueType(self, issueTypeId):
        if self.connection:
            if issueTypeId in ISSUE_TYPE.keys():
                return ISSUE_TYPE[issueTypeId]
            headers = self.getHeaders()
            payload = ""
            try:
                self.connection.request("GET", "/ase/api/issuetypes/" + str(issueTypeId), payload, headers)
                res = self.connection.getresponse()
                if res.status == 200:
                    data = res.read()
                    readableData = json.loads(data)
                    ISSUE_TYPE[issueTypeId] = readableData
                    return ISSUE_TYPE[issueTypeId]
            except Exception:
                log.error(Exception)

    def getIssueTypeId(self, appId, issueId, conn, headers):
        if self.connection:
            payload = ""
            issueTypeId = None
            try:
                issueTypeId = AppScanIssueTypeIDMap.objects.get(applicationId=appId, issueId=issueId).issueTypeId
                return issueTypeId
            except:
                self.connection.request("GET", "/ase/api/issues/" + issueId + "/application/" + appId + "/", payload, headers)
                res = conn.getresponse()
                data = res.read()
                readableData = json.loads(data)
                issueTypeId = readableData['issueTypeId']
                IssueTypeIDMap = AppScanIssueTypeIDMap.objects.create(applicationId=appId, issueId=issueId,
                                                                      issueTypeId=issueTypeId)
                IssueTypeIDMap.save()
                return issueTypeId

    def getApplicationId(self, appName):
        if self.connection:
            headers = self.getHeaders()
            payload = ""
            query = urllib.parse.quote("name=" + appName)
            columns = "name"
            URL = "/ase/api/applications?query=" + query + "&columns=" + columns
            self.connection.request("GET", URL, payload, headers)
            res = self.connection.getresponse()
            data = res.read()
            readableData = json.loads(data)
            if readableData:
                return readableData[0]['id']

    def createApp(self, appName):
        if self.connection:
            headers = self.getHeaders()
            request_body = {}
            request_body['name'] = appName
            payload = bytes(json.dumps(request_body), encoding="utf-8")
            self.connection.request("POST", "/ase/api/applications", payload, headers)
