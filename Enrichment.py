import os 
import requests
import time 

API_KEY = os.getenv("ABUSEIPDB_KEY") # Retrieves the API Key from the environment variable. SECURE CODE PRACTICE! | ABUSEIPDB API
API_KEY2 = os.getenv("VT_API_KEY") # Retrieves the second API Key from environment variable | VIRUSTOTAL API USING ENV VARIABLE FROM VPS!!!
USE_VIRUSTOTAL_API_KEY = True # FLIP SWITCH FOR VIRUSTOTAL API 
import requests 

#ABUSEIPDB CODE 

def enrich_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"

    params = { # The input in the request
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }

    headers = { # What will be need for authentication 
        "Accept": "application/json",
        "Key": API_KEY
    }

    response = requests.get(url, headers=headers, params=params) # TEMP VARIABLE
    data = response.json().get("data", {}) # Gets specific data from the API response. DATA IS NOW A DICTIONARY 

    return {
        "abuse_score": data.get("abuseConfidenceScore", 0),
        "country": data.get("countryCode"),
        "isp": data.get("isp")
    } #ONLY RETURN THESE 3 THINGS 

#VIRUSTOTAL CODE

vt_cache = {}

def enrich_ip_virustotal(ip):
    if not USE_VIRUSTOTAL_API_KEY:
        return { 
            "vt_malicious": 0,
            "vt_suspicious": 0,
            "vt_harmless": 0,
            "vt_undetected": 0,
            "label": "Testing Mode"} # WHEN FLIP SWITCH IS OFF, EVERYTHING WILL APPEAR AS TESTING MODE. 
    # Check Cache First 
    if ip in vt_cache:
        return vt_cache[ip] # Returns cached result if available
    
    # If not in cache, make API call
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY2
    }
    response = requests.get(url, headers=headers)
    stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) # Gets the last analysis stats from api response.
    result = {
        "vt_harmless": stats.get("harmless", 0),
        "vt_malicious": stats.get("malicious", 0),
        "vt_suspicious": stats.get("suspicious", 0),
        "vt_undetected": stats.get("undetected", 0)
    }
    if result["vt_malicious"] >= 5:
        label = "Malicious"
    elif result["vt_malicious"] >= 2:
        label = "Likely Malicious"
    elif result["vt_malicious"] == 1 and result["vt_suspicious"] >= 2:
        label = "Likely Malicious"
    elif result["vt_malicious"] == 1:
        label = "Suspicious"
    elif result["vt_suspicious"] >= 3:
        label = "Suspicious"
    elif result["vt_suspicious"] >= 1:
        label = "Low Suspicion"
    else:
        label = "Clean"
    
        
    result["label"] = label
    
    vt_cache[ip] = result # Cache the result for future use
    time.sleep(15) # Sleep to respect API Rate Limits (4 PER MIN) --> VirusTotal API 
    
    return result 






