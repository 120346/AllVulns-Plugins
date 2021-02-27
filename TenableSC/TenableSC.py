import datetime
import json

from tenable.sc import TenableSC
import logging
from AllVulnsApp.com.core.plugins import BaseInfrastructureScanner
log = logging.getLogger(__name__)

thirtyDaysAgo = "0:" + str(int((datetime.datetime.now() - datetime.timedelta(days=30)).timestamp()))


class Scanner(BaseInfrastructureScanner.BaseInfrastructureScanner):

    def __init__(self,pluginconfig):
        super().__init__(pluginconfig)
        self.connection = None
        if self.pluginconfig.host:
            self.connection = TenableSC(host=self.pluginconfig.host,port=self.pluginconfig.port)
            log.info('logging into SecurityCenter...')
            self.connection.login(self.pluginconfig.user.username, self.pluginconfig.user.password)
            now = datetime.datetime.now()
            self.summaryDate = now.strftime("%Y%m%d")

    def getAdditionalConfigNames(self):
        return ['copyScanUserId','copyScanName','copyScanId','excludedPlugins']

    def getPluginIconFileName(self):
        return


    def getStatus(self, pentest):
        if pentest.infrastructureScanStatus == "Completed" or pentest.infrastructureScanStatus == "Partial":
            return pentest.infrastructureScanStatus
        else:
            pentest=self.findScanResult(pentest)
            return pentest.infrastructureScanStatus

    def scan(self, appName, scanDate, pentest, nmapInfo=None, hostString=None):
        if self.connection:
            hostString = hostString.replace(' ', ',')
            conn = self.connection
            scanCopy = conn.post('scan/' + self.pluginconfig.copyScanId + '/copy', json={
                'name': self.pluginconfig.copyScanName, 'targetUser': {'id': self.pluginconfig.copyScanUserId}
            }).json()['response']['scan']

            log.debug('Renaming Copy to ' + appName + '...')
            results = conn.patch('scan/{}'.format(scanCopy['id']), json={
                'assets': [],
                'ipList': hostString,
                'plugin': {'id': -1},
                'policy': {'id': scanCopy['policy']['id']},
                'name': appName,
                'schedule': {
                    'starttime': scanDate,
                    'type': 'now'
                }
            })
            content = json.loads(results.content.decode('utf8'))
            nessusStartTime = content['response']['modifiedTime']
            self.store_scan_information(pentest, status="Scanning",start_time=nessusStartTime)

    def getVulnerabilities(self, targetId, pentest):
        if self.connection:
            if pentest.infrastructureScanStatus == "Completed" or pentest.infrastructureScanStatus == "Partial":
                scanId = pentest.infrastructureScanId
                if scanId:
                    try:
                        conn = self.connection
                        resp = conn.analysis.vulns(
                            ('severity', '=', '2,3,4'),
                            ('pluginID', '!=', self.pluginconfig.excludedPlugins),
                            ('patchPublished', '=', thirtyDaysAgo),
                            tool='vulndetails',
                            scan_id=scanId,
                            columns=[
                                {"name": "severity"},
                                {"name": "ip"},
                                {"name": "port"},
                                {"name": "pluginID"},
                                {"name": "pluginName"},
                                {"name": "description"},
                                {"name": "pluginText"},
                                {"name": "solution"},
                                {"name": "cve"}
                            ])
                        if resp != None:
                            for vuln in resp:
                                if vuln['pluginID'] not in self.pluginconfig.excludedPlugins:
                                    self.storeVulnerability(
                                        pentest=pentest,
                                        severity=vuln['severity']['name'],
                                        ip=vuln['ip'],
                                        port=vuln['port'],
                                        pluginName=vuln['pluginName'],
                                        description=vuln['description'],
                                        pluginText=vuln['pluginText'],
                                        solution=vuln['solution']
                                    )
                    except Exception as e:
                        log.error(e)
                        pass

    def findScanResult(self, pentest):
        if self.connection:
            appName = pentest.project.appName
            startTime = pentest.nessusStartTime
            conn = self.connection
            endTime = str(int(startTime) + 10)
            searchString = "scanResult?startTime=" + startTime + "&endTime=" + endTime + "&fields=id,name,startTime,status"
            results = conn.get(searchString)
            content = json.loads(results.content.decode('utf8'))
            resp = content['response']
            foundScanResult = {}
            for scanresult in resp['usable']:
                if scanresult['name'] == appName:
                    if not foundScanResult:
                        foundScanResult = scanresult
                        log.debug('first result found')
                    elif int(scanresult['startTime']) > int(foundScanResult['startTime']):
                        foundScanResult = scanresult
            if foundScanResult:
                log.debug("found scan. status=" + foundScanResult['status'])
                self.store_scan_information(pentest, scan_id=foundScanResult['id'], status=foundScanResult['status'])
        return pentest
