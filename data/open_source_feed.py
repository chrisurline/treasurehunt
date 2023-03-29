import requests

class VirusTotal:
    def __init__(self, api_key):
        self.api_key  = api_key
        self.base_url = 'https://www.virustotal.com/api/v3/'

    def get_ioc_data(self, ioc, ioc_type):
        match ioc_type:
            case 'ipv4' | 'ipv6':
                ioc_type = 'ip_addresses'
            case 'url':
                ioc_type = 'urls'
            case 'domain':
                ioc_type = 'domains'
            case 'md5' | 'sha1' | 'sha256' | 'sha512':
                ioc_type = 'hashes'

        url = f'{self.base_url}{ioc_type}{ioc}'
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        response = requests.get(url, headers=headers)
        return response.text

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
    vt_ioc_data = vt.get_ioc_data(inputs['ioc'], inputs['ioc_type'])
    otx_ioc_data =  otx.get_ioc_data(inputs['ioc'])

    open_source_intel = {
        "virustotal": vt_ioc_data,
        "alientvault_otx": otx_ioc_data
    }

    return open_source_intel