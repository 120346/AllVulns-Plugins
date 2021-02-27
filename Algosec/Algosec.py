from algosec.api_clients.firewall_analyzer import FirewallAnalyzerAPIClient
from AllVulnsApp.models import Rule, RuleReport
from AllVulnsApp.com.core.plugins.NetworkUtility import FirewallAnalyzer
import datetime
import logging
log=logging.getLogger(__name__)

class ReportGenerator(FirewallAnalyzer):
    def runStaleFirewallRulesReport(self):
        log.info("Running Algosec Report...")
        ruleReport = RuleReport.objects.create(startDate=datetime.datetime.now().isoformat(),reportStatus = "Initializing...")
        ruleReport.save()
        client=None
        try:
            client = FirewallAnalyzerAPIClient(server_ip=self.pluginconfig.host, user=self.pluginconfig.user.username, password=self.pluginconfig.user.password, verify_ssl=False)
        except Exception as e:
            ruleReport.reportStatus="Error Initializing Client!"
            ruleReport.save()
            return
        rules =[]
        ruleReport.reportStatus="Searching Devices..."
        ruleReport.save()
        devices=None
        try:
            devices = client.client.service.get_devices_list(SessionID=client._session_id)
        except Exception as e:
            ruleReport.reportStatus="Error While Executing Client! " + str(e)
            ruleReport.save()
            return
        index=1
        for device in devices:
            length=len(devices)
            percent=str(round(index/length*100))
            ruleReport.reportStatus=percent+"% Complete"
            ruleReport.save()
            try:
                returnedRules = client.client.service.get_unused_rules(SessionID=client._session_id,EntityID=device['ID'],EntityType="device")
                for ruleset in returnedRules:
                    for rule in ruleset[1]:
                        if rule["DeviceID"]:
                            Rule.objects.create(ruleReport=ruleReport,
                                                DeviceID=rule["DeviceID"],
                                                DeviceIP=device['IP'],
                                                Report=rule["Report"],
                                                Analyzed_On=rule["Analyzed_On"],
                                                RuleID=rule["RuleID"],
                                                RuleNum=rule["RuleNum"],
                                                Rule=rule["Rule"],
                                                Name=rule["Name"],
                                                Source=rule["Source"],
                                                Destination=rule["Destination"],
                                                Service=rule["Service"],
                                                Action=rule["Action"],
                                                Enable=rule["Enable"],
                                                Interface=rule["Interface"],
                                                Log=rule["Log"],
                                                Comment=rule["Comment"],
                                                ACL=rule["ACL"],
                                                Line=rule["Line"],
                                                LineNum=rule["LineNum"],
                                                LastUse=rule["LastUse"])
                rules.extend(returnedRules)
            except Exception as e:
                log.error(str(e))
            index=index+1

    
    