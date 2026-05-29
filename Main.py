from Scoring import calculate_score 
from Enrichment import enrich_ip  # Imports the enrich_ip function which ENRICHES IP ADDRESSES USING THE ABUSEIPDB API. 
from Enrichment import enrich_ip_virustotal  # Imports the enrich_ip_virustotal function which ENRICHES IP ADDRESSES USING THE VIRUSTOTAL API. 
from Translator import normalize_event # Imports the normalize_event function to translate RAW SIEM DATA to readable data. 
from Geolocation import geolocate_ip # Imports the geolocation function. 
import json # Imports the json module to work with JSON data. WAZUH SIEM uses JSON format for alerts!
from datetime import datetime # Imports the datetime module to eventually make a timestamp for the report. 
from collections import Counter # Imports the counter module to count most common events and countries for executive summary. 
import requests
from requests.auth import HTTPBasicAuth
import urllib3
import os
WAZUH_USER = os.getenv("WAZUH_USER") # Retrieves Wazuh username from environment variable. SECURE CODE PRACTICE!
WAZUH_PASS = os.getenv("WAZUH_PASS") # Retrieves Wazuh password from environment variable. SECURE CODE PRACTICE!

# Disable SSL warnings
urllib3.disable_warnings()

indexer_url = "https://localhost:9200" # URL for Elasticsearch Indexer.
endpoint = "/wazuh-alerts-*/_search" # Endpoint for searching Wazuh alerts in Elasticsearch.
url = indexer_url + endpoint

headers = {
    "Content-Type": "application/json"}
payload = {
    "size": 800,
    "sort": [
        {
            "timestamp": {
                "order": "desc"
            }
        }
    ],
    "query": {
        "match_all": {}
    }
}
response = requests.get(url, headers=headers, data=json.dumps(payload), auth=HTTPBasicAuth(WAZUH_USER, WAZUH_PASS), verify=False)
response.raise_for_status()  # Raise an exception for HTTP errors
result = response.json()  # Parse the JSON response
alerts = result.get("hits", {}).get("hits", [])  # Extract the list of alerts from the response


run_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S") # Creates a timestamp for when the report is generated.


threat_event_score = {
    "Brute Force": 4,
    "Malware Detected": 5,
    "Port Scan": 2.5,
    "Impossible travel": 3.5,
    "SQL Injection": 5,
    "Data Exfiltration": 5
}

# 🔹 Severity ranking for sorting
severity_map = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1
}

rows = ""

# Limits the number of alerts to 15 to prevent overwhelming the report.
alerts = alerts[0:15] 

processed_alerts = [] # Creates an empty list to store processed alerts after enrichment and scoring. This will be used for generating the report and map data.

aggregated_alerts = {} # Creates an empty dictionary to store aggregated alerts based on source IP and event type. This will be used to count the number of attempts for each unique combination of source IP and event type.

# 🔹 LOOP 1 — Enrich alerts (calculate + store values)
for alert in alerts:
    # Translate JSON Output from SIEM to Readable Data
    source = alert.get("_source", {})  # Get the _source field from each alert which contains the actual alert data.
    data = source.get("data", {})  # Get the data field from the _source which contains specific details about the alert.
    rule = source.get("rule", {})  # Get the rule field from the _source which contains information about the rule that triggered the alert.
    rule_level = rule.get("level", 0) # Get the level of the rule which can be used as a factor in scoring.
    alert_data = data.get("alert", {})  # Get the alert field from the data which contains specific information about the alert such as signature and command.
    src_ip = (
    data.get("src_ip")
    or data.get("srcip")
    or source.get("src_ip")
    or source.get("srcip")
    ) 

    timestamp = source.get("timestamp") # Get the timestamp of the alert for potential use in the report.
    timestamp_updated = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")

    description = rule.get("description", "") # Get the description of the rule and convert it to lowercase for easier analysis.
    fired_times = rule.get("firedtimes", 1) # Get the number of times this rule has been fired for this alert. This can be used as a factor in scoring.
    signature = alert_data.get("signature", "") 
    


    alert["attempts"] = fired_times # Store the number of attempts in the alert dictionary for later use in scoring and reporting.
   
    # Enrichment with AbuseIPDB
    enrichment = enrich_ip(src_ip) 
    abuse_score = enrichment['abuse_score']
    isp = enrichment['isp']
    # Enrichment with VirusTotal
    vt_data = enrich_ip_virustotal(src_ip)
    vt_score = vt_data["label"]
    vt_score_number = vt_score
    # Extract necessary fields for scoring  
    attempts = fired_times 
    
    # Determine event type
    event_type = alert_data.get("signature") # Changed to .get because it allows conditionals and flexibility when SIEM is Integrated. 
    if not event_type:
        event_type = normalize_event(alert)
    
    # MITRE ATT&CK 
    mitre_data = rule.get("mitre", {})
    fallback_mitre = calculate_score(event_type, attempts, abuse_score, vt_score_number, rule_level).get("mitre") # If MITRE data is not available in the rule, it will be determined based on the event type and other factors using the calculate_score function.
    if mitre_data:
        ids = mitre_data.get("id", [])
        techniques = mitre_data.get("technique", [])
        pairs = []
        for i in range(min(len(ids), len(techniques))):
            pairs.append(f"{ids[i]} - {techniques[i]}")
        if pairs:
            mitre = ", ".join(pairs)
        else: mitre = fallback_mitre
    else:
        mitre = fallback_mitre 
   


    # Import the function from Scoring.py
    score_data = calculate_score(event_type, attempts, abuse_score, vt_score_number, rule_level) # Passes the necessary parameters to the calculate_score function to get the threat score and severity.

    # Geolocation enrichment
    geo_data = geolocate_ip(src_ip)
    if geo_data:
        alert["latitude"] = geo_data["latitude"]
        alert["longitude"] = geo_data["longitude"]
        alert["country"] = geo_data["country"]
    else:
            alert["latitude"] = None
            alert["longitude"] = None
            alert["country"] = None 
    country = geo_data["country"] if geo_data else "Unknown" # Stores country from IP Geolocation API. 
    #  STORE values inside alert (CRITICAL STEP)
    alert["severity"] = score_data["severity"]
    alert["threat_score"] = score_data["threat_score"]
    alert["abuse_score"] = abuse_score
    alert["country"] = country
    alert["isp"] = isp  
    alert["vt_score"] = vt_score
    alert["threat_score_percent"] = score_data["threat_score_percent"]
    alert["reason"] = score_data["reason"]
    alert["mitre"] = score_data["mitre"]
    alert["src_ip"] = src_ip
    alert["timestamp"] = timestamp
    alert["event_type"] = event_type
    alert["timestamp_updated"] = timestamp_updated.strftime("%Y-%m-%d %H:%M:%S") 
    
    if src_ip not in aggregated_alerts:
        aggregated_alerts[src_ip] = {
             "event_type": event_type,
             "attempts": fired_times,
              "severity": score_data["severity"],
              "threat_score": score_data["threat_score"],
              "country": country,
              "isp": isp,
              "vt_score": vt_score,
              "reason": score_data["reason"],
              "mitre": score_data["mitre"],
              "timestamp": timestamp,
              "latitude": alert["latitude"],
              "longitude": alert["longitude"],
              "threat_score_percent": score_data["threat_score_percent"],
              "abuse_score": abuse_score,
              "src_ip": src_ip,
              "timestamp_updated": timestamp_updated.strftime("%Y-%m-%d %H:%M:%S") 
              

        }
    else:
        aggregated_alerts[src_ip]["attempts"] += fired_times
    
processed_alerts = list(aggregated_alerts.values()) # Update the processed_alerts list with the aggregated alert data based on source IP and event type. This will ensure that the report reflects the total number of attempts for each unique combination of source IP and event type, rather than treating each alert as a separate entry.

# Counts for executive summary (most common event type and country)
event_counter = Counter( 
     alert["event_type"] for alert in processed_alerts
)
country_counter = Counter(
     alert["country"] for alert in processed_alerts
)
top_event = event_counter.most_common(1)[0][0] if event_counter else "N/A" # Gets the most common event type. 
top_country = country_counter.most_common(1)[0][0] if country_counter else "N/A" # Gets the most common country.

# Highest Priority Alert 
highest_priority_alert = max(processed_alerts, key=lambda alert: alert["threat_score"]) if processed_alerts else None # Gets the alerts with the highest threat score. 
highest_priority_alert_ip = highest_priority_alert["src_ip"] if highest_priority_alert else "N/A"
highest_priority_alert_event = highest_priority_alert["event_type"] if highest_priority_alert else "N/A"
highest_priority_alert_score = highest_priority_alert["threat_score"] if highest_priority_alert else "N/A"
highest_priority_alert_country = highest_priority_alert["country"] if highest_priority_alert else "N/A"
highest_priority_alert_longitude = highest_priority_alert["longitude"] if highest_priority_alert else "N/A"
highest_priority_alert_latitude = highest_priority_alert["latitude"] if highest_priority_alert else "N/A"
highest_priority_alert_reason = highest_priority_alert["reason"] if highest_priority_alert else "N/A"
highest_priority_alert_mitre = highest_priority_alert["mitre"] if highest_priority_alert else "N/A"
highest_priority_alert_severity = highest_priority_alert["severity"] if highest_priority_alert else "N/A"
# 🔹 SORT alerts AFTER enrichment
processed_alerts.sort(
    key=lambda x: severity_map.get(x["severity"], 0), #SORTS BY SEVERITY RANKING.
    reverse=True)
processed_alerts.sort(
    key=lambda x: x["threat_score"], reverse = True) #SORTS BY THREAT SCORE.



# 🔹 LOOP 2 — Build HTML from sorted alerts
for alert in processed_alerts:
    rows += f""" 
    <tr>
        <td>{alert["src_ip"]}</td>
        <td>{alert["event_type"]}</td>
        <td class="{alert["severity"].lower()}">{alert["severity"]}</td> 
        <td>{alert["attempts"]}</td>
        <td>{alert["timestamp_updated"]}</td>
        <td>{alert["threat_score_percent"]}%</td>
        <td>{alert["abuse_score"]}</td>
        <td>{alert["vt_score"]}</td>
        <td>{alert["country"]}</td>
        <td>{alert["isp"]}</td>
        <td>{alert["reason"]}</td>
        <td>{alert["mitre"]}</td>
        
      
    </tr>
    """
    # Severity can be either Critical, High, Medium, or Low. 
    # rows+= is used to add rows to the empty string. 

alerts_json = json.dumps(processed_alerts) # Converts alerts to Json String for JS. Then make a const on JS to use it. 


map_data = f"""
<script> 
const alerts = {alerts_json}; // Puts alerts into a JS variable for use. 

</script>

"""

#FOOTER 

with open("FrontEnd.html", "r") as f:
    html = f.read() # Reads the content of the FrontEnd.html file and stores it in the variable html. 

html = html.replace("{{ROWS}}", rows) # Replaces placehold from HTML file. 
html = html.replace("{{total}}", str(len(processed_alerts))) # Labels the total amount of alerts 
html = html.replace("{{critical}}", str(len([alert for alert in processed_alerts if alert["severity"] == "Critical"])))
html = html.replace("{{high}}", str(len([alert for alert in processed_alerts if alert["severity"] == "High"])))
html = html.replace("{{medium}}", str(len([alert for alert in processed_alerts if alert["severity"] == "Medium"])))
html = html.replace("{{low}}", str(len([alert for alert in processed_alerts if alert["severity"] == "Low"])))
html = html.replace("{{run_time}}", run_time) # Replaces placeholder with timestamp.
html = html.replace("map_data", alerts_json) # Replaces placeholder with alerts_json.
html = html.replace("{{top_event}}", top_event) # Labels the most common event type in executive summary.
html = html.replace("{{country_counter}}", str(len(country_counter))) # Labels the number of unique countries in executive summary.
html = html.replace("{{top_country}}", top_country) # Labels the most common country in executive summary.
html = html.replace("{{highest_priority_ip}}", highest_priority_alert_ip) 
html = html.replace("{{highest_priority_event}}", highest_priority_alert_event) 
html = html.replace("{{highest_priority_score}}", str(highest_priority_alert_score)) 
html = html.replace("{{highest_priority_severity}}", highest_priority_alert_severity) 
html = html.replace("{{highest_priority_country}}", highest_priority_alert_country) 
html = html.replace("{{highest_priority_mitre}}", highest_priority_alert_mitre) 
html = html.replace("{{highest_priority_reason}}", highest_priority_alert_reason)
with open("Incident_Report.html", "w") as f: # Opens a new file called Incident_Report.html in write mode. This is where the HTML report will be saved. 
    f.write(html)

#ALL INFORMATION IS STORED UNDER THE PYTHON AUTOMATION PROJECT FOLDER!