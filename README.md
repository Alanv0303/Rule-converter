# Rule-converter
This tool converts Sigma detection rules into Wazuh-compatible XML rules, applying necessary adjustments to ensure proper compatibility. Its main goal is to simplify and standardize XML rule creation in Wazuh SIEM, reducing manual effort, errors, and time required to implement Sigma-based use cases.

Note : 
- This is a pragmatic converter aimed at creating a good starting point for manual refinement. Sigma -> Wazuh is not a 1:1 mapping in general because Sigma is higher-level and expressive.
- You should review & test generated rules before deploying to production. Use ID range 100000-120000 for custom rules.
