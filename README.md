# APT3-detection-project
Detection engineering project based on APT3 emulation logs. Writing granular, SIEM-agnostic Sigma rules mapped to MITRE ATT&amp;CK, with a full written analysis of the intrusion chain.

**Status:** Still in progress

# Detection Philosophy
Sigma rules are designed as granular, SIEM-agnostic behavioural signals. Higher-level context, including event frequency, temporal relationships and multi-stage attack correlation, is intended to be implemented at the SIEM level. Each rule represents a discrete behavioral indicator that should be chained with others to build attack-stage detections and full intrusion narratives.

This approach allows for:
- SIEM-agnostic portability (Sigma → any SIEM)
- Flexible correlation logic (implement in your SIEM's native language)
- Reduced false positives (granular signals, smart aggregation)
- Attack-stage visibility (follow the intrusion chain)

# Detection rules:
  /rules

# Quick overview:
  findings-summary.md

## Credits
**APT3 emulation logs provided by [nboubakr](https://github.com/nboubakr)**

-logs were cleaned and normalised for analysis original raw logs can be found in '/raw_logs'
