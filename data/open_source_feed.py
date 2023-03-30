import requests
from utils import input_parser
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes

class VirusTotal:
    def __init__(self, api_key):
        self.api_key  = api_key
        self.base_url = 'https://www.virustotal.com/api/v3/'

    def get_ioc_data(self, ioc, ioc_type):
        match ioc_type:
            case ('ipv4' | 'ipv6'):
                ioc_type = 'ip_addresses'
            case ('domain' | 'email'):
                if ioc_type == 'email':
                    ioc = input_parser.parse_email_to_domain(ioc)
                ioc_type = 'domains'
            case 'url':
                ioc_type = 'urls'
            case ('md5' | 'sha1' | 'sha256'):
                ioc_type = 'hashes'

        url = f'{self.base_url}{ioc_type}/{ioc}'
        print(url)
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
            case 'email':
                query = otx.get_indicator_details_full(IndicatorTypes.EMAIL, ioc)
            case 'md5':
                query = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_MD5, ioc)
            case 'sha1':
                query = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_SHA1, ioc)
            case 'sha256':
                query = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_SHA256, ioc)
            case other:
                query = 'An error occured with AlienVault OTX'
        
        return query

class MetaDefender:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = 'https://api.metadefender.com/v4/'
    
    def get_ioc_data(self, ioc, ioc_type):
        match ioc_type:
            case 'ipv4' | 'ipv6':
                ioc_type = 'ip'
            case 'domain' | 'email':
                if ioc_type == 'email':
                    ioc = input_parser.parse_email_to_domain(ioc)
                ioc_type = 'domain'
            case 'url':
                pass
            case 'md5' | 'sha1' | 'sha256':
                ioc_type = 'hash'

        url = f'{self.base_url}{ioc_type}/{ioc}'
        headers = {
            'apikey': self.api_key
        }
        response = requests.get(url,  headers=headers)
        return response.text
    
class AbuseIPDB:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = 'https://api.abuseipdb.com/api/v2/check/'

    def get_ioc_data(self, ioc, ioc_type):
        if ioc_type ==  'ipv4' or 'ipv6':
            url = f'{self.base_url}/{ioc}'
            headers = {
                'Accept': 'application/json',
                'Key': self.api_key
            }
            response = requests.get(url, headers=headers)
            return response.text
        else:
            return 'AbuseIPDB only accepts IP queries'

def collect_data(inputs):

    data_sources = [
        VirusTotal(inputs['config']['API_KEYS']['virustotal_api_key']),
        AlientVaultOTX(inputs['config']['API_KEYS']['alienvault_otx_api_key']),
        MetaDefender(inputs['config']['API_KEYS']['metadefender_api_key']),
        AbuseIPDB(inputs['config']['API_KEYS']['abuseipdb_api_key'])
    ]

    open_source_intel = {}
    for source in data_sources:
        ioc_data = source.get_ioc_data(inputs['ioc'], inputs['ioc_type'])
        source_name = type(source).__name__.lower()
        open_source_intel[source_name] = ioc_data

    return open_source_intel