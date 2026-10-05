# APT3-detection-project
Detection engineering project based on APT3 emulation logs. Writing granular, SIEM-agnostic Sigma rules mapped to MITRE ATT&amp;CK, with a full written analysis of the intrusion chain.

**Status:** Still in progress

# Detection Philosophy
Sigma rules are designed as granular, SIEM-agnostic behavioural signals. Higher-level context, including event frequency, temporal relationships and multi-stage attack correlation, is intended to be handled by the target SIEM.

# quick overview found in:
  findings-summary.md

# rules found in:
  /rules

## Credits
- **APT3 emulation logs:** [nboubakr](https://github.com/nboubakr)
  -logs where cleaned and normalised for analysis original raw logs can be found in '/raw_logs'
