# TreasureHunt - IOC Enrichment and Threat Hunting Tool

## Overview

Started on 3/28/2023, this is project is in very early stages.

The aim is to develop a tool that can be used to enrich IOCs and provide as much context as possible to a security analyst. Furthermore, I would like to automate as much of this process as possible to improve analyst efficiency and reduce burnout caused by repetitive tasks. There are plenty of other tools that already provide the functionality planned for this project, this is intended as an exercise in improving my skillset and exploring various APIs, python libraries, and programming techniques. 

### Use Cases

__With this information the analyst could:__
- Compile a list of related IOCs for Threat Hunting purposes or for improving the configuration of security tools (Firewalls, IPS/IDS, DLP, etc).
- Identify potential threat actors and gather information about their TTPs
- Improve their use cases and the logic used to generate security events
- Identify patterns of behavior that can be used to keep their team and end users informed
- Gather information about the attack and be better equipped to ensure the attack did not move further down the kill chain unnoticed

### Basic Rules

- All file based searches will be designed to query publicly available information based on a provided file hash. 
    - No functionality will be added for uploading files to eliminate the possibilty of accidental data exposure by an analyst. 
- The tool is intended to provide additional context related to known bad IOCs discovered during investigations. 
    - __**Beware:**__ Some file sharing services link directly to documents - blindly querying URLs may lead to these documents being publicly available. Use caution when utilizing the URL search functionality. 
- I will do my best to ensure links/IPs in the output are sanitized/fanged, but always exercise caution while reviewing the results.

### Short Term Goals

- Complete a CLI based tool that can be used as a standalone tool, integrated into a SOAR platform, or be leveraged as part of a larger project. 
- Find a way to effectively take the massive amount of data that may be ingested by one of these searches and output it in a way that is consistently useful. (Easier said than done)
- Provide at least a couple different options for the format of the results (CSV, JSON, HTML, PDF, etc.)
- Make at least one person's job a little bit easier. 

### Long Term Goals 

- Implement functionality to compile the results in a centralized location/database (within the confines of the org) so it can be used to identify patterns for threat hunting, and provide performance metrics for the SecOps teams. 
- Create a web-based dashboard that will display metrics and provide a GUI for submitting queries.
- Have at least one "pew pew" visual tool that big wigs will enjoy when they stop into a SOC for a visit. (See: https://threatmap.checkpoint.com/)
