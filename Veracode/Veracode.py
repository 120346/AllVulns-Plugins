import json
import ssl
from http.client import HTTPSConnection

from veracode_api_signing import veracode_hmac_auth
from AllVulnsApp.com.core.plugins.BaseCodeScanner import CodeScanner

severity_map=['None','Informational','Low','Medium','High','Critical']

"https://api.veracode.com"
"/appsec/v1/applications"
"/appsec/v1/applications/{application}/findings"
ID = "5cc96309f2aa9f74f457a20fcd7f913a"
SECRET = "03586fb7cc982521269ac6785abc9d2f66a0a6d94a1bfcbf94681001206737c35ed0959b25b7ba43c3ddb726681e0785f89988dc30ab92265ba8d7d2e6b5b97f"



class VeracodIntegration(CodeScanner):
    def __init__(self, pluginconfig):
        super().__init__(pluginconfig)
        self.connection=None
        if self.pluginconfig.host:
            context = ssl._create_unverified_context()
            self.connection = HTTPSConnection(self.pluginconfig.host, self.pluginconfig.port, context=context)

    def getScanId(self, project):
        return None

    def getIssuesByApp(self, project):
        if self.connection:
            guid = self.getApplicationId(project.appName)
            if guid:
                url="/appsec/v1/applications/" + guid + "/findings"
                authheader = veracode_hmac_auth.generate_veracode_hmac_header(host=self.pluginconfig.host,
                                                                              path=url, method='GET',
                                                                              api_key_id=self.pluginconfig.api_key_id,
                                                                              api_key_secret=self.pluginconfig.api_key_secret)

                headers = {"Accept-Encoding": "gzip, deflate", 'content-type': "application/json;charset=UTF-8",
                           "Accept": "*/*", "Authorization": authheader}
                self.connection.request('GET', url, "", headers)
                res = self.connection.getresponse()
                data = res.read()
                readableData = json.loads(data)
                for issue in readableData["_embedded"]["findings"]:
                    self.storeVulnerability(
                        project,
                        issue['guid'],
                        severity_map[int(issue['severity'])],
                        issue['finding_category']['name'],
                        issue['finding_status'][guid]['finding_source']['file_path'] + ":" +issue['finding_status'][guid]['finding_source']['file_line_number'],
                        issue['description'],
                        issue['finding_category']['recommendation'],
                        issue['finding_status'][guid]['status'],
                        issue['finding_status'][guid]['found_date']
                )

    def createApp(self, appName):
        #Not needed
        pass

    def getApplicationId(self, appName):
        if self.connection:
            authheader = veracode_hmac_auth.generate_veracode_hmac_header(host=self.pluginconfig.host,
                                                                          path='/appsec/v1/applications', method='GET',
                                                                          api_key_id=self.pluginconfig.api_key_id,
                                                                          api_key_secret=self.pluginconfig.api_key_secret)
            headers = {"Accept-Encoding": "gzip, deflate", 'content-type': "application/json;charset=UTF-8",
                       "Accept": "*/*", "Authorization": authheader}
            self.connection.request('GET', "/appsec/v1/applications", "", headers)
            res = self.connection.getresponse()
            data = res.read()
            readableData = json.loads(data)
            for application in readableData["_embedded"]["applications"]:
                guid = application["guid"]
                name = application["profile"]["name"]
                if name.lower() == appName.lower():
                    return guid
            return None

    def getAdditionalConfigNames(self):
        # Override to store more configuration
        return ['api_key_id', 'api_key_secret']
