import os
import requests

Geolocation_API_KEY = os.getenv("Geolocation_API_KEY") 

def geolocate_ip(ip):
    response = requests.get(f"https://api.ipgeolocation.io/v3/ipgeo?apiKey={Geolocation_API_KEY}&ip={ip}")
    data = response.json()
    location = data.get("location", {})

    if not location:
        print(f"[GEOLOCATION ERROR] No location data for IP: {ip}")
        return None
    
    return {
        "country": location.get("country_name"),
        "city": location.get("city"),
        "latitude": float(location.get("latitude")) if location.get("latitude") else None,
        "longitude": float(location.get("longitude")) if location.get("longitude") else None
    }
    
    




    
