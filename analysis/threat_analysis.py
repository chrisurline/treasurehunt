
def consolidate_intelligence(open_source_data, social_media_data, dark_web_data, malware_sample_data):
    """
    Consolidate threat intelligence from various data sources into a single structure.

    :param open_source_data: Collected data from open-source feeds
    :param social_media_data: Collected data from social media and forums
    :param dark_web_data: Collected data from dark web sources
    :param malware_sample_data: Collected data from malware sample repositories
    :return: A dictionary containing the consolidated threat intelligence
    """
    consolidated_intel = {
        "open_source_feeds": open_source_data,
        "social_media": social_media_data,
        "dark_web": dark_web_data,
        "malware_samples": malware_sample_data
    }

    return consolidated_intel
