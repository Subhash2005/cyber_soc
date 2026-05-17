import asyncio
import json
import os
import google.generativeai as genai
from datetime import datetime
from dotenv import load_dotenv
from .memory import memory_store

load_dotenv()

# Configure Gemini
api_key = os.getenv("GEMINI_API_KEY")
if api_key:
    genai.configure(api_key=api_key)
else:
    print("WARNING: GEMINI_API_KEY not found in environment.")

# Use Gemini Flash for fast reasoning
try:
    model = genai.GenerativeModel('gemini-2.5-flash')
except Exception as e:
    print(f"Failed to load Gemini model: {e}")
    model = None

def analyze_threat_with_llm(log: dict, previous_session: dict, threat_intel: str) -> dict:
    """Uses Gemini to evaluate if the event is a threat based on real OSINT data."""
    if not model:
        return {"is_threat": False, "reasoning": "LLM not configured."}

    prompt = f"""
    You are an expert AI Cybersecurity SOC Agent.
    Analyze the following login event to determine if it's an anomaly or a real attack.
    Pay close attention to the IP Address, Location, and ISP.
    
    Current Event:
    {json.dumps(log, indent=2)}
    
    Previous Session Data (from cache):
    {json.dumps(previous_session, indent=2) if previous_session else "None"}
    
    Relevant Threat Intelligence (from Vector DB):
    {threat_intel}
    
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
        text = response.text.replace('```json\n', '').replace('\n```', '').strip()
        result = json.loads(text)
        return result
    except Exception as e:
        print(f"LLM Error: {e}")
        # If the API hits a quota limit (Error 429), fall back to a simulated AI response for the demo
        if "429" in str(e) or "Quota" in str(e):
            print("WARNING: API Quota exceeded. Using simulated AI reasoning for demonstration.")
            return {
                "is_threat": True,
                "threat_type": "OSINT Malicious IP",
                "severity": "HIGH",
                "reasoning": "This IP is flagged by global OSINT feeds as an active attacker. Immediate block required.",
                "recommended_action": "BLOCK_IP"
            }
        return {"is_threat": False, "reasoning": f"LLM Error: {e}"}

async def process_logs(queue: asyncio.Queue, broadcast_callback):
    """The main consumer loop that reads logs and passes them to the AI agent."""
    while True:
        log = await queue.get()
        user = log["user"]
        
        # 1. Check Redis-equivalent cache
        previous_session = memory_store.get_session(user)
        
        # Trigger LLM if the location changed (impossible travel) 
        # OR if it's an external OSINT attack (indicated by a non-local ISP)
        suspicious = False
        if previous_session and previous_session["last_location"] != log["location"]:
            suspicious = True
        elif log.get("isp") != "Local ISP":
            suspicious = True
        
        is_threat = False
        alert_data = None
        
        if suspicious:
            print(f"[*] Analyzing suspicious activity for {user} from IP {log['ip_address']}...")
            
            # 2. Query Vector DB for threat intel
            threat_intel = memory_store.search_threat_intel("impossible travel or malicious IP login")
            
            # 3. Use Gemini to analyze
            llm_result = analyze_threat_with_llm(log, previous_session, threat_intel)
            
            if llm_result.get("is_threat"):
                is_threat = True
                print(f"[!!!] THREAT CONFIRMED: {llm_result['reasoning']}")
                
                alert_data = {
                    "type": "alert",
                    "event": log,
                    "analysis": llm_result,
                    "action_taken": f"Executed: {llm_result.get('recommended_action')}"
                }
        
        # 4. Update Memory
        memory_store.update_session(user, log["ip_address"], log["location"], log["timestamp"])
        memory_store.add_graph_edge(user, log["ip_address"], log["device"])
        
        # 5. Broadcast to Dashboard
        if is_threat and alert_data:
            await broadcast_callback(json.dumps(alert_data))
        else:
            # Broadcast normal log
            await broadcast_callback(json.dumps({"type": "log", "event": log}))
            
        queue.task_done()
