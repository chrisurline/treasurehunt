Ongoing notes to journal changes and any other relevant information made during development.

### 3/29 - Change Notes

- Added functionality to VirusTotal (Only applicable source at this time) search to parse domain from email address IOCs in cases where the Threat Intel source provides domain queries but not HTML. 
- AbuseIPDB and MetaDefender added

***

### 3/30 - Change Notes

- Modified the order that 'detect_ioc_type' evaluates IOCs in. This was causing domains to be evaluated as URLs and could cause issues with some APIs (VirusTotal).
- Added Shodan
- AbuseIPDB fixed (It wasn't returning data -> added query to params instead of url)

***

### 3/31 + 4/1 - Change Notes

- Added Censys Search
- Some IF statements were evaluating incorrectly.. 
- Had issues with regex evaluating URL vs Domain in `detect_ioc_type` (Some TI sources need explicit distinction between the two)
    - Changed it from using exclusively regex to a combination of urllib parse and regex. Seems to be working so far. 
