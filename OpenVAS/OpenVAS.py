from openvas_lib import VulnscanManager, VulnscanException
import openvas_lib
import logging
log = logging.getLogger(__name__)
from AllVulnsApp.com.core.plugins import BaseInfrastructureScanner
from openvas_lib.common import *
import xmltodict

class Scanner(BaseInfrastructureScanner.BaseInfrastructureScanner):

    def __init__(self,pluginconfig):
        super().__init__(pluginconfig)
        self.connection = None
        if self.pluginconfig.host:
            log.info('logging into OpenVas...')
            self.connection = VSMOverride(host=self.pluginconfig.host, user=self.pluginconfig.user.username, password=self.pluginconfig.user.password, port=int(self.pluginconfig.port))


    def scan(self, appName, scanDate, pentest, nmapInfo=None, hostString=None):
        if  self.connection:
            hostString = hostString.replace(" ", ",")
            scan_id, target_id = self.connection.launch_scan(target=hostString, profile="Full and fast")
            if scan_id:
                self.store_scan_information(pentest,scan_id=scan_id,status="Scanning",start_time=scanDate)

    def getVulnerabilities(self, targetId, pentest):
        if self.connection:
            if pentest.infrastructureScanStatus != "Done" and pentest.infrastructureScanStatus != "Stopped":
                self.getStatus(pentest)
            else:
                results = self.connection.get_results(task_id=pentest.infrastructureScanId)
                if 'result' in results['get_results_response']:
                    for vuln in results['get_results_response']['result']:
                        if vuln['threat'] in ['Critical','High','Medium']:
                            json_tags = {}
                            tag_array = vuln['nvt']['tags'].split("|")
                            for tag in tag_array:
                                arr = tag.split('=');
                                json_tags[arr[0]] = arr[1]
                            vuln['nvt']['tags'] = json_tags
                            summary = ''
                            if 'summary' in vuln['nvt']['tags']:
                                summary = vuln['nvt']['tags']['summary']

                            solution = ''
                            if 'solution' in vuln['nvt']['tags']:
                                solution_type = ''
                                if 'solution_type' in vuln['nvt']['tags']:
                                    solution_type = "Solution Type: " + vuln['nvt']['tags']['solution_type'] + "\n\n"
                                xref = ''
                                if 'xref' in vuln['nvt'] and vuln['nvt']['xref'] != "NOXREF":
                                    xref = "\n\n References:\n" + vuln['nvt']['xref']
                                solution = solution_type + vuln['nvt']['tags']['solution'] + xref
                            description = ''
                            if 'description' in vuln and vuln['description']:
                                description = vuln['description']

                            self.storeVulnerability(
                                pentest=pentest,
                                severity=vuln['threat'],
                                ip=vuln['host']['#text'],
                                port=vuln['port'],
                                pluginName=vuln['name'],
                                description=summary,
                                pluginText=description,
                                solution=solution
                            )

    def getStatus(self, pentest):
        if self.connection:
            if pentest.infrastructureScanId:
                status = self.connection.get_scan_status(pentest.infrastructureScanId)
                if status:
                    log.info(str(status))
                    self.store_scan_information(pentest, status=status)
                    return status

class VSMOverride(VulnscanManager):
    def __init__(self, host, user, password, port=9390, timeout=None, ssl_verify=False):
        super().__init__(host, user, password, port, timeout, ssl_verify)

    def get_results(self, task_id):
        try:
            m_response =self._VulnscanManager__manager.get_results(task_id)
        except ServerError as e:
            raise Exception("Can't get the results for the task %s. Error: %s" % (task_id, e.message))
        m_response = etree.tostring(m_response)
        return xmltodict.parse(m_response.decode("utf-8"))


