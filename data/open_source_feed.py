import requests
import json
from utils import input_parser
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from censys.search import CensysHosts

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
                ioc_type = 'files'

        url = f'{self.base_url}{ioc_type}/{ioc}'
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        response = requests.get(url, headers=headers)
        return json.loads(response.text)

class AlientVaultOTX:
    def __init__(self, api_key):
        self.api_key = api_key

    def get_ioc_data(self, ioc, ioc_type):
        otx = OTXv2(self.api_key)
        query = ''
        try:
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
                    if not bool(query):
                        # If no results from email search run against the emails domain
                        ioc = input_parser.parse_email_to_domain(ioc)
                        query = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, ioc)
                case 'md5':
                    query = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_MD5, ioc)
                case 'sha1':
                    query = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_SHA1, ioc)
                case 'sha256':
                    query = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_SHA256, ioc)

            return query
        except:
            pass

class MetaDefender:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = 'https://api.metadefender.com/v4/'
    
    def get_ioc_data(self, ioc, ioc_type):
        match ioc_type:
            case ('ipv4' | 'ipv6'):
                ioc_type = 'ip'
            case ('domain' | 'email'):
                if ioc_type == 'email':
                    ioc = input_parser.parse_email_to_domain(ioc)
                ioc_type = 'domain'
            case 'url':
                pass
            case ('md5' | 'sha1' | 'sha256'):
                ioc_type = 'hash'

        url = f'{self.base_url}{ioc_type}/{ioc}'
        headers = {
            'apikey': self.api_key
        }
        response = requests.get(url,  headers=headers)
        return json.loads(response.text)
    
    
class AbuseIPDB:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = 'https://api.abuseipdb.com/api/v2/check/'

    def get_ioc_data(self, ioc, ioc_type):
        if ioc_type in ['ipv4', 'ipv6']:
            params = {
                'ipAddress': ioc,
            }
            headers = {
                'Accept': 'application/json',
                'Key': self.api_key
            }
            response = requests.get(self.base_url, headers=headers, params=params)
            return response.text
        else:
            pass

class ShodanIO:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = 'https://api.shodan.io/shodan/host/search'

    def get_ioc_data(self, ioc, ioc_type):
        if ioc_type in ['ipv4', 'ipv6']:
            params = {
                'key': self.api_key,
                'query': ioc
            }
            response = requests.get(self.base_url, params=params)
            return response.text
        else:
            pass

class URLHaus:
    def __init__(self):
        # No API key needed for database queries
        self.base_url = 'https://urlhaus-api.abuse.ch/v1'

    def get_ioc_data(self, ioc, ioc_type):
        if ioc_type in ['domain', 'ipv4', 'ipv6', 'url', 'email']:
            match ioc_type:
                case ('domain' | 'ipv4' | 'ipv6'): 
                    ioc_type = 'host' 
                case 'email':
                    ioc_type = 'host'
                    ioc = input_parser.parse_email_to_domain(ioc)
            
            url = f'{self.base_url}/{ioc_type}/'
            data = {
                ioc_type: ioc
            }
            response = requests.post(url, data)
            return json.loads(response.text)
        else:
            pass

class CensysIO:
    def __init__(self):
        self.censys = CensysHosts()

    def get_ioc_data(self, ioc, ioc_type):
        if ioc_type in ['ipv4', 'ipv6']:
            response = self.censys.view(ioc)
            return response
        else:
            pass

def collect_data(inputs):

    data_sources = [
        VirusTotal(inputs['config']['API_KEYS']['virustotal_api_key']),
        AlientVaultOTX(inputs['config']['API_KEYS']['alienvault_otx_api_key']),
        MetaDefender(inputs['config']['API_KEYS']['metadefender_api_key']),
        AbuseIPDB(inputs['config']['API_KEYS']['abuseipdb_api_key']),
        ShodanIO(inputs['config']['API_KEYS']['shodan_api_key']),
        URLHaus(),
        CensysIO()
    ]

    open_source_intel = {}
    for source in data_sources:
        ioc_data = source.get_ioc_data(inputs['ioc'], inputs['ioc_type'])
        source_name = type(source).__name__.lower()
        open_source_intel[source_name] = ioc_data

    return open_source_intel