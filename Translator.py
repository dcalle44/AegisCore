# Translator Function --> translates raw data from Wazuh SIEM Json to Clean, Easier data to read/interpret. 

def normalize_event(alert):
    source = alert.get("_source", {}) 
    rule = source.get("rule", {})
    data = source.get("data", {})
    alert_data = source.get("data", {})
    description = rule.get("description", "").lower()
    groups = rule.get("groups", [])
    command = data.get("command", "").lower()
    signature = alert_data.get("signature", "").lower() if (alert_data := alert.get("data", {})) else ""
    full_log = source.get("full_log", "").lower()
    
 
    # AUTHENTICATION / SSH

    if "login" in description and "failed" in description:
        return "SSH Brute Force"

    if "authentication failed" in description:
        return "Potential SSH Brute Force"

    if "invalid password" in description:
        return "Credential Stuffing"

    if "invalid user" in description:
        return "Account Enumeration"

    if "non-existent user" in description:
        return "Account Enumeration"

    if "cowrie.login.success" in full_log:
        return "Unauthorized Access"

    if "successful login" in description:
        return "Unauthorized Access"

    if "session opened" in description:
        return "Successful Login"

    if "session closed" in description:
        return "Session Closed"
    if "connection reset" in description:
        return "Connection Reset"
    if "pam: user login failed" in description:
        return "Failed Login Attempt"
    
    
    
    # RECON / SCANNING

    if "nmap" in signature:
        return "Port Scan"
    if "masscan" in signature:
        return "Port Scan"
    if "recon" in description:
        return "Reconnaissance"
    if "ssh-2.0-go" in signature:
        return "SSH Enumeration"
    if "syn flood" in signature:
        return "Denial of Service Attempt"
    if "scan" in signature:
        return "Network Scan"
    
    



    # SURICATA / IDS

    if "poor reputation ip" in signature:
        return "Threat Intelligence Match"

    if "spamhaus" in signature:
        return "Known Malicious Traffic"

    if "dshield" in signature:
        return "Known Malicious Traffic"

    if "cins" in signature:
        return "Threat Intelligence Match"

    if "et scan" in signature:
        return "Network Scanning"




    # =========================
    # PRIVILEGE ESCALATION
    # =========================

    if "sudo" in groups:
        return "Privilege Escalation Attempt"

    if "sudo to root executed" in description:
        return "Privilege Escalation Attempt"

    if "chmod" in command or "chown" in command:
        return "Privilege Escalation Attempt"

    if "iptables" in command and "redirect" in command:
        return "Network Traffic Redirection"


    # =========================
    # PAYLOAD / MALWARE
    # =========================

    if "wget" in command or "curl" in command:
        return "Payload Download"

    if ".sh" in command or ".exe" in command or ".bin" in command:
        return "Suspicious File Download"

    if "malware" in description:
        return "Malware Activity"

    if "shell" in description and "upload" in description:
        return "Web Shell Activity"


    # =========================
    # PERSISTENCE
    # =========================

    if "useradd" in command or "adduser" in command:
        return "Persistence Attempt"

    if "crontab" in command:
        return "Persistence Attempt"

    if "backdoor" in command:
        return "Backdoor Installation"


    # =========================
    # POST-EXPLOITATION
    # =========================

    if "lateral movement" in description:
        return "Lateral Movement"

    if "internal scan" in description:
        return "Internal Reconnaissance"

    if "script execution" in description:
        return "Script Execution"

    if "tool execution" in description:
        return "Tool Execution"


    # =========================
    # EXFIL / C2
    # =========================

    if "exfiltration" in description:
        return "Data Exfiltration"

    if "dns tunneling" in description:
        return "DNS Tunneling"

    if "command and control" in description:
        return "C2 Communication"

    if "c2" in description:
        return "C2 Communication"

    if "outbound" in description and "suspicious" in description:
        return "Suspicious Outbound Traffic"


    # =========================
    # ANOMALIES
    # =========================

    if "impossible travel" in description:
        return "Impossible Travel"

    if "anomalous" in description:
        return "Anomalous Behavior"

    if "unusual" in description:
        return "Unusual Activity Pattern"


    return "Unknown Suspicious Activity"
 