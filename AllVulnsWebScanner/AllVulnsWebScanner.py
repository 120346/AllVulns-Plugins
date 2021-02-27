from AllVulnsApp.com.core.plugins.BaseWebScanner import BaseWebScanner
from Plugins.lib.AllVulnsWebScanner import allVulnsWebScanner
import uuid
import logging
log=logging.getLogger(__name__)

all_Vulns_Web_Scanner=None
class Scanner(BaseWebScanner):
    def scan(self, appName, scanDate, pentest, nmapInfo=None, hostString=None ):
        for ip in nmapInfo:
            for port in nmapInfo[ip]:
                url = nmapInfo[ip][port]['url']
                if url != '':
                    target = self.addTargetToPentest(str(uuid.uuid1()), pentest, url, "Initializing")
                    try:
                        vulns={}
                        allVulns_Web_Scanner= allVulnsWebScanner.Scanner()
                        vulns = allVulns_Web_Scanner.scan(url)
                        target.status="completed"
                        for affects_url in vulns:
                            for _type in vulns[affects_url]:
                                payload = vulns[affects_url][_type]['Payload']
                                element = vulns[affects_url][_type]['Element']
                                severity = vulns[affects_url][_type]['Severity']
                                recomendation = vulns[affects_url][_type]['Recommendation']
                                reference = vulns[affects_url][_type]['References']
                                references = [{'href': vulns[affects_url][_type]['References'], 'rel': reference}]
                                request = payload + " " + element
                                self.storeVulnerability(target, severity, _type, affects_url, recomendation, request, references)

                    except Exception as e:
                        log.error(e)
                        target.status = "failed"
                    target.save()
        log.info("gathering evidence")
        self.gatherEvidence()
