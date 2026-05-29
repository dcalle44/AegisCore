# Threat event score rating 

threat_event_score = {

    # Authentication Attacks
    "Brute Force": 4,
    "Credential Stuffing": 4.5,
    "Suspicious Login": 3,
    "Account Enumeration": 3.5,
    "Password Spraying": 4,

    # Reconnaissance
    "Port Scan": 2.5,
    "Network Scan": 2.5,
    "Service Enumeration": 3,
    "Banner Grabbing": 2,
    "DNS Enumeration": 2,

    # Exploitation
    "SQL Injection": 5,
    "Command Injection": 5,
    "Remote Code Execution": 5,
    "Exploit Attempt": 5,
    "File Inclusion": 4.5,

    # Malware / Payload Activity
    "Malware Detected": 5,
    "Payload Download": 4.5,
    "Suspicious File Download": 4,
    "Shell Upload": 5,
    "Web Shell Activity": 5,

    # Honeypot-Specific (VERY IMPORTANT FOR YOU)
    "SSH Login Attempt": 3.5,
    "SSH Brute Force": 4.5,
    "Command Execution": 5,
    "Privilege Escalation Attempt": 5,
    "Persistence Attempt": 5,
    "Unauthorized Access": 4.5,

    # Data Movement / Impact
    "Data Exfiltration": 5,
    "Large Data Transfer": 4,
    "Suspicious Outbound Traffic": 4,
    "C2 Communication": 5,

    # Behavioral / Anomaly
    "Impossible Travel": 3.5,
    "Anomalous Behavior": 3,
    "Unusual Activity Pattern": 3,
    "Time-based Anomaly": 2.5,

    # Post-Exploitation / Attacker Actions
    "Lateral Movement": 5,
    "Internal Reconnaissance": 4,
    "Tool Execution": 4,
    "Script Execution": 4,
    "Cron Job Modification": 5,
    "Backdoor Installation": 5,

    # General / Fallback
    "Unknown Suspicious Activity": 3,
}

# Severity ranking for sorting
severity_map = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1
}

mitre_map = {


    # AUTHENTICATION / ACCESS

    "SSH Brute Force": "T1110 - Brute Force",
    "Potential SSH Brute Force": "T1110 - Brute Force",
    "Credential Stuffing": "T1110.004 - Credential Stuffing",
    "Account Enumeration": "T1087 - Account Discovery",
    "Unauthorized Access": "T1078 - Valid Accounts",
    "Successful Login": "T1078 - Valid Accounts",
    "Failed Login Attempt": "T1110 - Brute Force",

    # RECON / SCANNING

    "Port Scan": "T1046 - Network Service Discovery",
    "Network Scan": "T1046 - Network Service Discovery",
    "Network Scanning": "T1046 - Network Service Discovery",
    "Reconnaissance": "T1595 - Active Scanning",
    "SSH Enumeration": "T1046 - Network Service Discovery",
    "Internal Reconnaissance": "T1595 - Active Scanning",

    # DOS

    "Denial of Service Attempt": "T1498 - Network Denial of Service",

    # THREAT INTEL MATCHES


    "Threat Intelligence Match": "T1583 - Infrastructure Acquisition",
    "Known Malicious Traffic": "T1583 - Infrastructure Acquisition",

    # COMMAND EXECUTION

    "Script Execution": "T1059 - Command and Scripting Interpreter",
    "Tool Execution": "T1059 - Command and Scripting Interpreter",

    # PRIVILEGE ESCALATION

    "Privilege Escalation Attempt":
        "T1068 - Exploitation for Privilege Escalation",

    "Network Traffic Redirection":
        "T1565 - Network Traffic Manipulation",

    # PAYLOADS / MALWARE

    "Payload Download": "T1105 - Ingress Tool Transfer",

    "Suspicious File Download":
        "T1105 - Ingress Tool Transfer",

    "Malware Activity":
        "T1204 - User Execution",

    "Web Shell Activity":
        "T1505.003 - Web Shell",

    # PERSISTENCE


    "Persistence Attempt":
        "T1053 - Scheduled Task/Job",

    "Backdoor Installation":
        "T1505 - Server Software Component",


    # LATERAL MOVEMENT


    "Lateral Movement":
        "T1021 - Remote Services",


    # EXFILTRATION / C2
 

    "Data Exfiltration":
        "T1041 - Exfiltration Over C2 Channel",

    "DNS Tunneling":
        "T1071.004 - DNS",

    "C2 Communication":
        "T1071 - Application Layer Protocol",

    "Suspicious Outbound Traffic":
        "T1071 - Application Layer Protocol",


    # ANOMALIES


    "Impossible Travel":
        "T1078 - Valid Accounts",

    "Anomalous Behavior":
        "T1036 - Masquerading",

    "Unusual Activity Pattern":
        "T1036 - Masquerading",


    # BENIGN EVENTS


    "Session Closed": "Informational",
    "Connection Reset": "Informational",

    # DEFAULT

    "Unknown Suspicious Activity":
        "T1589 - Gather Victim Identity Information"
}

def calculate_score(event_type, attempts, abuse_score, vt_score_number, rule_level):
    reasons = []

    # 1. Event type score
    score_event = threat_event_score.get(event_type, 5)

    if score_event >= 5:
        reasons.append("High-risk event type detected")

    # 2. Attempts score
    if attempts >= 25:
        threat_score_attempts = 5
        reasons.append("High attempt volume")
    elif attempts >= 15:
        threat_score_attempts = 3.5
        reasons.append("Moderate attempt volume")
    elif attempts >= 5:
        threat_score_attempts = 2
    else:
        threat_score_attempts = 0

    # 3. VirusTotal score
    if vt_score_number == "Malicious":
        vt_score_number = 5
        reasons.append("VirusTotal flagged source as malicious")
    elif vt_score_number == "Likely Malicious":
        vt_score_number = 4
        reasons.append("VirusTotal indicates likely malicious activity")
    elif vt_score_number == "Suspicious":
        vt_score_number = 3
        reasons.append("VirusTotal shows suspicious indicators")
    elif vt_score_number == "Low Suspicion":
        vt_score_number = 2
        reasons.append("VirusTotal shows low-level suspicion")
    else:
        vt_score_number = 0

    # 4. AbuseIPDB score
    if abuse_score >= 90:
        abuse_score_points = 5
        reasons.append("High AbuseIPDB reputation score")
    elif abuse_score >= 70:
        abuse_score_points = 3.5
        reasons.append("Elevated AbuseIPDB reputation score")
    elif abuse_score >= 40:
        abuse_score_points = 2
        reasons.append("Moderate AbuseIPDB reputation score")
    else:
        abuse_score_points = 0
   
    # Rule Level Scoring 

    if rule_level >= 12:
        rule_score = 5
        reasons.append("High severity rule triggered")
    elif rule_level >= 10:
        rule_score = 4
        reasons.append("Moderate severity rule triggered")
    elif rule_level >= 7:
        rule_score = 3
        reasons.append("Low severity rule triggered")
    elif rule_level >= 4:
        rule_score = 2
        reasons.append("Very low severity rule triggered")
    elif rule_level >= 1:
        rule_score = 1
        reasons.append("Informational rule triggered")
    else:
        rule_score = 0

    # 5. Total score
    threat_score = score_event + threat_score_attempts + vt_score_number + abuse_score_points + rule_score
    threat_score_percent = round((threat_score / 25) * 100, 1)

    # 6. Severity
    if threat_score >= 20:
        severity = "Critical"
    elif threat_score >= 15:
        severity = "High"
    elif threat_score >= 8:
        severity = "Medium"
    else:
        severity = "Low"

    reason = " | ".join(reasons) if reasons else "No major risk indicators"

    # MITRE ATT&CK Framework Integration 
    mitre_technique = mitre_map.get(event_type, "Unknown")


    return {
        "threat_score": threat_score,
        "threat_score_percent": threat_score_percent,
        "severity": severity,
        "reason": reason,
        "mitre": mitre_technique
    }