import requests
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes

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
            case 'md5' | 'sha1' | 'sha256':
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

    def get_ioc_data(self, ioc, ioc_type):
        otx = OTXv2(self.api_key)
        match ioc_type:
            case 'ipv4':
                query = otx.get_indicator_details_full(IndicatorTypes.IPv4, ioc)
            case 'ipv6':
                query = otx.get_indicator_details_full(IndicatorTypes.IPv6, ioc)
            case 'url':
                query = otx.get_indicator_details_full(IndicatorTypes.URL, ioc)
            case 'domain':
                query = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, ioc)
            case 'md5':
                query = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_MD5, ioc)
            case 'sha1':
                query = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_SHA1, ioc)
            case 'sha256':
                query = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_SHA256, ioc)
            case other:
                query = 'An error occured with AlienVault OTX'
        
        return query


def collect_data(inputs):

    # initialize threat intel classes
    vt = VirusTotal(inputs['config']['API_KEYS']['virustotal_api_key'])
    otx = AlientVaultOTX(inputs['config']['API_KEYS']['alienvault_otx_api_key'])


    # run the IOC query
    vt_ioc_data = vt.get_ioc_data(inputs['ioc'], inputs['ioc_type'])
    otx_ioc_data =  otx.get_ioc_data(inputs['ioc'], inputs['ioc_type'])

    open_source_intel = {
        "virustotal": vt_ioc_data,
        "alientvault_otx": otx_ioc_data
    }

    return open_source_intel