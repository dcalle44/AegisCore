# AegisCore
A cybersecurity detection and analysis platform that automates threat intelligence enrichment, alert correlation, risk scoring, MITRE ATT&amp;CK mapping, and incident reporting for security operations workflows.

## Key Features
- Correlates repeated security events by source IP to reduce alert noise
- Builds attacker profiles from aggregated activity and threat intelligence
- Enriches indicators using AbuseIPDB and VirusTotal
- Maps detections to MITRE ATT&CK techniques
- Calculates risk scores based on event severity, frequency, and threat intelligence
- Generates executive-ready HTML incident reports
- Integrates with Wazuh SIEM and Cowrie honeypot telemetry

### OpenSearch Integration
- Connects directly to the Wazuh OpenSearch API
- Executes custom queries against security event indices
- Retrieves real-world security telemetry from SIEM data stores
- Processes JSON alert data for enrichment and analysis
- Supports automated ingestion of attacker activity from monitored environments
  
### Alert Correlation
- Aggregates repeated events from the same source IP
- Correlates multiple security events into attacker profiles
- Reduces duplicate alert noise
- Prioritizes attackers based on activity and threat intelligence

### Risk Scoring Engine
- Calculates threat scores using:
  - Event frequency
  - Rule severity
  - AbuseIPDB reputation
  - VirusTotal detections
  - Contextual attack information

- Assigns severity classifications:
  - Critical
  - High
  - Medium
  - Low
---
### MITRE ATT&CK Mapping
- Maps observed attacker behavior to MITRE ATT&CK techniques
- Provides contextual understanding of adversary tactics and techniques
- Supports analyst investigation workflows

### Executive Reporting
- Generates professional HTML reports
- Summarizes attack activity and threat intelligence findings
- Displays attacker information in an easily consumable format
- Supports both technical and non-technical audiences

---

## System Architecture
AegisCore operates through the following workflow:

```text
Internet Attackers
        ↓
Cowrie Honeypot
        ↓
Wazuh SIEM
        ↓
OpenSearch API
        ↓
AegisCore
   ↙     ↓      ↘
AbuseIPDB MITRE VirusTotal
        ↓
Risk Scoring Engine
        ↓
HTML Incident Report
```

---

## Example Workflow

1. Wazuh detects suspicious activity.
2. Alert data is collected and processed by AegisCore.
3. Source IP addresses are extracted.
4. Threat intelligence enrichment is performed using:
   - AbuseIPDB
   - VirusTotal
   - Geolocation data
5. Related events are correlated into attacker profiles.
6. MITRE ATT&CK techniques are assigned.
7. Risk scores are calculated.
8. A professional HTML report is generated.

---

## Technologies Used

### Programming

- Python

### Security Platforms

- Wazuh SIEM
- Cowrie Honeypot

### Threat Intelligence

- AbuseIPDB API
- VirusTotal API

### Frameworks & Libraries

- Requests
- JSON
- HTML
- CSS
- JavaScript

### Security Frameworks

- MITRE ATT&CK

---

## Screenshots

### Architecture Diagram



### Wazuh Integration



### Threat Intelligence Enrichment




### Risk Scoring Dashboard



### Generated Incident Report
<img width="3439" height="874" alt="Screenshot 2026-05-28 231130" src="https://github.com/user-attachments/assets/84087ea8-6304-4abf-9c00-184b1a5c2bd3" />
<img width="3438" height="809" alt="Screenshot 2026-05-28 231114" src="https://github.com/user-attachments/assets/d962a226-d7a9-4ef6-b038-1accdbe5350e" />
<img width="2906" height="1012" alt="Screenshot 2026-05-28 231102" src="https://github.com/user-attachments/assets/a7a2c7bb-577a-4ef7-bff0-405d41b0eaef" />
<img width="3439" height="1099" alt="Screenshot 2026-05-28 231050" src="https://github.com/user-attachments/assets/572de284-551d-4c5d-a74c-6ae8686bcad7" />
<img width="3397" height="805" alt="Screenshot 2026-05-28 231033" src="https://github.com/user-attachments/assets/70503d50-6cd8-441c-b8a7-0c6509a719e8" />
<img width="3419" height="1055" alt="Screenshot 2026-05-28 231010" src="https://github.com/user-attachments/assets/32bed5a7-60c6-4805-910d-3098f84624d4" />
<img width="3412" height="1071" alt="Screenshot 2026-05-28 230944" src="https://github.com/user-attachments/assets/59a58ac2-a02f-460b-b80f-81c674463ef7" />



## Installation

### Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/AegisCore.git
cd AegisCore
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure Environment Variables

Create a `.env` file and configure the following:

```text
ABUSEIPDB_API_KEY=YOUR_KEY
VT_API_KEY=YOUR_KEY
GEOLOCATION_API_KEY=YOUR_KEY
```

### Run AegisCore

```bash
python main.py
```

---

## Example Output

Generated reports contain:

- Source IP
- Event Type
- Threat Score
- Severity Classification
- AbuseIPDB Reputation
- VirusTotal Results
- Country
- ISP
- Reasoning
- MITRE ATT&CK Mapping

---

## Lessons Learned

This project provided hands-on experience with:

- Security Operations Center (SOC) workflows
- Threat intelligence enrichment
- Alert triage and prioritization
- Detection engineering concepts
- MITRE ATT&CK mapping
- API integration
- Data correlation
- Security reporting automation
- SIEM integration
- Honeypot telemetry analysis

---

## Future Improvements

Planned enhancements include:

- Flask web application interface
- User authentication and role-based access control
- Live dashboard monitoring
- Threat intelligence caching improvements
- Additional threat intelligence providers
- Automated IOC export
- Historical trend analysis
- Email alerting
- REST API support
- Multi-tenant architecture

---

## Disclaimer

This project was developed for educational, research, and defensive cybersecurity purposes. All testing was performed within controlled environments using authorized systems and security monitoring platforms.
