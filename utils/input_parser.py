import configparser
import re

URL_REGEX = r'(?:http(?:s?)://)?(?:[\w]+\.)+[a-zA-Z]+(?::\d{1,5})?'
DOMAIN_REGEX = r'^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)'
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
    'domain': DOMAIN_REGEX,
    'md5': MD5_REGEX,
    'sha1': SHA1_REGEX,
    'sha256': SHA256_REGEX,
    'sha512': SHA512_REGEX
}

def read_config(config_file_path):
    config = configparser.ConfigParser()
    config.read(config_file_path)
    return config

def detect_ioc_type(ioc: str) -> str:
    for ioc_type, regex in ioc_regex.items():
        if re.match(regex, ioc):
            return ioc_type
    return 'unknown'

def parse_arguments(args):
    inputs = {
        "config": read_config(args.config),
        "ioc":  args.ioc,
        "ioc_type": detect_ioc_type(args.ioc),
        "output": args.output
    }

    return inputs