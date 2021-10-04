import multiprocessing

from AllVulnsApp.com.core.plugins.BaseWebScanner import BaseWebScanner
from Plugins.lib.AllVulnsWebScanner import allVulnsWebScanner
import uuid
import logging
log=logging.getLogger(__name__)

all_Vulns_Web_Scanner=None
class Scanner(BaseWebScanner):
    def scan(self, appName, scanDate, pentest, nmapInfo=None, hostString=None ):
        for ip in nmapInfo:
            for entry in nmapInfo[ip]:
                if entry == 'reverseDNS':
                    url = nmapInfo[ip]['reverseDNS']
                else:
                    port = entry
                    url = nmapInfo[ip][port]['url']
                if url and url != '':
                    if isinstance(url, list):
                        for uri_entry in url:
                            self.scan_target(pentest, uri_entry.domain)
                    else:
                        self.scan_target(pentest, url)
        log.info("gathering evidence")
        self.gatherEvidence()

    def scan_target(self, pentest, url):
        target = self.addTargetToPentest(str(uuid.uuid1()), pentest, url, "Initializing")
        try:
            vulns = {}
            allVulns_Web_Scanner = allVulnsWebScanner.Scanner()
            log.info("Scanning " + url)
            target.status = "scanning"
            target.save()
            vulns = allVulns_Web_Scanner.scan(url)
            target.status = "completed"
            for affects_url in vulns:
                for _type in vulns[affects_url]:
                    payload = vulns[affects_url][_type]['Payload']
                    element = vulns[affects_url][_type]['Element']
                    severity = vulns[affects_url][_type]['Severity']
                    recommendation = vulns[affects_url][_type]['Recommendation']
                    reference = vulns[affects_url][_type]['References']
                    references = [{'href': vulns[affects_url][_type]['References'], 'rel': reference}]
                    request = payload + " " + element
                    self.storeVulnerability(target, severity, _type, affects_url, recommendation, request, references)

        except Exception as e:
            log.error(e)
            target.status = "failed"
        target.save()


    def getStatus(self, target):
        if all_Vulns_Web_Scanner:
            return all_Vulns_Web_Scanner.getStatus()
        return super().getStatus(target)