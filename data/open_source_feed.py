import requests

class VirusTotal:
    def __init__(self, api_key):
        self.api_key  = api_key
        self.base_url = 'https://www.virustotal.com/api/v3/'

    def get_ioc_data(self, ioc):


        pass

class  AlientVaultOTX:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url =  'https://otx.alienvault.com/api/v1/'

    def get_ioc_data(self, ioc):

        pass

def collect_data(inputs):

    # initialize threat intel classes
    vt = VirusTotal(inputs['config']['API_KEYS']['virustotal_api_key'])
    otx = AlientVaultOTX(inputs['config']['API_KEYS']['alientvaultotx_api_key'])


    # run the IOC query
    vt_ioc_data = vt.get_ioc_data(inputs['ioc'])
    otx_ioc_data =  vt.get_ioc_data(inputs['ioc'])

    open_source_intel = {
        "virustotal": vt_ioc_data,
        "alientvault_otx": otx_ioc_data
    }

    return open_source_intel