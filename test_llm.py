import os
import json
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-2.5-flash')

log = {
    "event_id": "123",
    "timestamp": "2026-05-17T19:00:00Z",
    "event_type": "login_success",
    "user": "root",
    "ip_address": "167.94.146.74",
    "location": "Frankfurt am Main, DE",
    "device": "Unknown Device",
    "isp": "Censys, Inc."
}

prompt = f"""
You are an expert AI Cybersecurity SOC Agent.
Analyze the following login event to determine if it's an anomaly or a real attack.
Pay close attention to the IP Address, Location, and ISP.

Current Event:
{json.dumps(log, indent=2)}

Previous Session Data (from cache):
None

Relevant Threat Intelligence (from Vector DB):
Login from two distant geographic locations within a short time frame is highly indicative of an impossible travel anomaly or compromised account. Recommended action: BLOCK_IP or LOCK_ACCOUNT.

Determine if this represents a threat (like impossible travel or a known malicious OSINT ISP/Location). 
If yes, what action should be taken?

Respond in strict JSON format:
{{
    "is_threat": true/false,
    "threat_type": "string or null",
    "severity": "HIGH/MEDIUM/LOW or null",
    "reasoning": "explanation",
    "recommended_action": "e.g., BLOCK_IP, LOCK_ACCOUNT, NONE"
}}
"""

try:
    response = model.generate_content(prompt)
    print("RAW RESPONSE:")
    print(response.text)
    text = response.text.replace('```json\n', '').replace('\n```', '').strip()
    result = json.loads(text)
    print("PARSED JSON:")
    print(json.dumps(result, indent=2))
except Exception as e:
    print(f"Error: {e}")
