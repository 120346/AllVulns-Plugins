import orionsdk
import sys
import re
from AllVulnsApp.com.core.plugins.NetworkUtility import NetworkUtility


class SolarWinds(NetworkUtility):
    def __init__(self, pluginconfig):
        super().__init__(pluginconfig)
        if self.pluginconfig.user:
            self.swis = orionsdk.SwisClient(self.pluginconfig.host, self.pluginconfig.user.username, self.pluginconfig.user.password)
    
    def getDeadIPs(self,IPsToCheck):
        IPs=str(IPsToCheck)[1:-1]
        IPs = re.sub('[!@#$\[\]]', '', IPs)
        
        query="SELECT IPAddress FROM IPAM.IPNode where IPAddress in("+IPs+") and status=2"
        aliases = self.swis.query(query)
        
        deadIPs=[]
        for entry in aliases['results']:
            deadIPs.append(entry['IPAddress'])
        return deadIPs