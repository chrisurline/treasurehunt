import configparser
import re
from urllib.parse import urlparse

EMAIL_DOMAIN_REGEX = r'[^@]+@([\w.-]+)' # Extracting domains from email addresses
URL_REGEX = r'^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)'
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
IPV4_REGEX = r'^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?!$)|$)){4}$'
IPV6_REGEX = r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'
MD5_REGEX = r'\b([a-fA-F\d]{32})\b'
SHA1_REGEX = r'\b([a-fA-F\d]{40})\b'
SHA256_REGEX = r'\b([a-fA-F\d]{64})\b'
SHA512_REGEX  = r'\b([a-fA-F\d]{128})\b'

ioc_regex = {
    'ipv4': IPV4_REGEX,
    'ipv6': IPV6_REGEX,
    'url': URL_REGEX,
    'email': EMAIL_REGEX,
    'md5': MD5_REGEX,
    'sha1': SHA1_REGEX,
    'sha256': SHA256_REGEX,
    'sha512': SHA512_REGEX
}

''' open configuration file '''
def read_config(config_file_path):
    config = configparser.ConfigParser()
    config.read(config_file_path)
    return config

def parse_configured_apis(apis):
    pass

def detect_ioc_type(ioc: str) -> str:
    for ioc_type, regex in ioc_regex.items():
        if re.match(regex, ioc):
            if ioc_type == 'url':
                parsed_url = urlparse(ioc)
                # Add a default scheme if it's missing otherwise it won't be
                # evaluated properly in the next step. 
                if not parsed_url.scheme:
                    ioc = 'http://' + ioc
                    parsed_url = urlparse(ioc)

                if parsed_url.netloc and parsed_url.path:
                    return 'url'
                elif parsed_url.netloc:
                    return 'domain'
                else:
                    print('There was an error parsing Domain/URL (input_parser.py)')
                    return 'url'

            return ioc_type

    return ''

def parse_email_to_domain(email):
    domain = re.search(EMAIL_DOMAIN_REGEX, email)
    return domain

def parse_arguments(args):
    inputs = {
        "config": read_config(args.config),
        "ioc":  args.ioc,
        "ioc_type": detect_ioc_type(args.ioc),
        "output": args.output
    }

    return inputs