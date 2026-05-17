import asyncio
import json
import random
import time
from datetime import datetime
import uuid
import aiohttp

# Sample local data
USERS = ["alice.smith", "bob.jones", "charlie.brown", "admin.david"]
NORMAL_LOCATIONS = [
    {"city": "Chennai", "country": "IN", "ip": "103.21.32.14"},
    {"city": "Bangalore", "country": "IN", "ip": "115.112.55.12"},
    {"city": "Mumbai", "country": "IN", "ip": "122.15.1.2"},
]

async def fetch_real_threats():
    """Fetches real attacking IPs from SANS ISC DShield API."""
    try:
        headers = {"User-Agent": "SOC-Agent/1.0"}
        async with aiohttp.ClientSession(headers=headers) as session:
            # Get top 100 attacking IPs
            async with session.get("https://isc.sans.edu/api/sources/attacks/100?json") as response:
                if response.status == 200:
                    data = await response.json(content_type=None)
                    # Filter and extract just the IPs
                    ips = [item['ip'] for item in data if 'ip' in item]
                    print(f"Fetched {len(ips)} real malicious IPs from OSINT feed.")
                    return ips
                else:
                    print("Failed to fetch from SANS ISC API.")
                    return []
    except Exception as e:
        print(f"Error fetching threats: {e}")
        return []

async def resolve_ip_location(ip: str):
    """Resolves IP to City/Country using ip-api.com."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://ip-api.com/json/{ip}") as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("status") == "success":
                        return {
                            "city": data.get("city", "Unknown"),
                            "country": data.get("countryCode", "Unknown"),
                            "isp": data.get("isp", "Unknown ISP")
                        }
    except Exception:
        pass
    return {"city": "Unknown", "country": "Unknown", "isp": "Unknown ISP"}

async def start_log_generation(queue: asyncio.Queue):
    """
    Generates logs, mixing local simulated traffic with REAL attacks 
    pulled from live OSINT feeds.
    """
    event_counter = 0
    malicious_ips = await fetch_real_threats()
    
    while True:
        event_counter += 1
        user = random.choice(USERS)
        
        # Every 10th event, generate a REAL OSINT anomaly
        if event_counter % 10 == 0 and malicious_ips:
            # Pick a real attacking IP
            real_malicious_ip = random.choice(malicious_ips)
            # Resolve its real-world location
            location_info = await resolve_ip_location(real_malicious_ip)
            
            # Use common brute-force target usernames for real threats
            brute_force_users = ["root", "admin", "administrator", "guest", "postgres"]
            threat_user = random.choice(brute_force_users)
            
            suspicious_log = {
                "event_id": str(uuid.uuid4()),
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": "login_success",
                "user": threat_user,
                "ip_address": real_malicious_ip,
                "location": f"{location_info['city']}, {location_info['country']}",
                "device": "Unknown Device",
                "isp": location_info['isp']
            }
            await queue.put(suspicious_log)
            print(f"[*] Injected REAL OSINT event for {threat_user} from {real_malicious_ip} ({location_info['country']})")
            
        else:
            # Normal log
            loc = random.choice(NORMAL_LOCATIONS)
            log = {
                "event_id": str(uuid.uuid4()),
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": "login_success",
                "user": user,
                "ip_address": loc["ip"],
                "location": f"{loc['city']}, {loc['country']}",
                "device": "Corporate Laptop",
                "isp": "Local ISP"
            }
            await queue.put(log)
            
        # Wait a bit before generating the next log
        await asyncio.sleep(random.uniform(1.0, 3.0))
