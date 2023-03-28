import argparse
from data import open_source_feed, social_media, dark_web, malware_sample
from analysis import threat_analysis
from utils import input_parser, output_handler

def main(args):
    
    inputs = input_parser.parse_arguments(args)

    open_source_intel = open_source_feed.collect_data(inputs)
    social_media_intel = social_media.collect_data(inputs)
    dark_web_intel = dark_web.collect_data(inputs)
    malware_samples_intel = malware_sample.collect_data(inputs)

    consolidated_intel =  threat_analysis.consolidate_intelligence(
        open_source_intel,
        social_media_intel,
        dark_web_intel,
        malware_samples_intel
    )

    enriched_ioc = threat_analysis.enrich_ioc(consolidated_intel, inputs.ioc)

    output_handler.output_enriched_ioc(enriched_ioc, inputs)


if __name__ ==  '__main__':

    parser = argparse.ArgumentParser(description='TreasureHunt - IOC Enrichment and Threat Hunting Tool')
    parser.add_argument('--config', default='config/config.ini', help='Path to configuration file')
    parser.add_argument('--ioc', required=True, help="Indicator of Compromise (IOC) to be enriched")
    parser.add_argument('--output', default='output.json', help='Path to output file')

    args = parser.parse_args()

    main(args)