Ongoing notes to journal changes and any other relevant information made during development.

### 3/29 - Change Notes

- Added functionality to VirusTotal (Only applicable source at this time) search to parse domain from email address IOCs in cases where the Threat Intel source provides domain queries but not HTML. 
- AbuseIPDB and MetaDefender added

***

### 3/30 - Change Notes

- Modified the order that 'detect_ioc_type' evaluates IOCs in. This was causing domains to be evaluated as URLs and could cause issues with some APIs (VirusTotal).
