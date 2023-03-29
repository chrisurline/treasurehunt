
def consolidate_intelligence(open_source_data, social_media_data, dark_web_data, malware_sample_data):
   
    consolidated_intel = {
        "open_source_feeds": open_source_data,
        "social_media": social_media_data,
        "dark_web": dark_web_data,
        "malware_samples": malware_sample_data
    }

    return consolidated_intel
