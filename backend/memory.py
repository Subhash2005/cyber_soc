import networkx as nx
from typing import Dict, Any

class MemoryStore:
    def __init__(self):
        # 1. Graph Database Alternative (NetworkX)
        self.graph = nx.DiGraph()
        
        # 2. Redis Alternative (In-Memory Session Cache)
        self.sessions: Dict[str, Dict[str, Any]] = {}

    def initialize(self):
        print("Memory Store Initialized.")

    def update_session(self, user: str, ip: str, location: str, timestamp: str):
        """Updates the short-term cache for user sessions."""
        self.sessions[user] = {
            "last_ip": ip,
            "last_location": location,
            "last_login_time": timestamp
        }

    def get_session(self, user: str):
        return self.sessions.get(user)

    def add_graph_edge(self, user: str, ip: str, device: str):
        """Updates the attack graph."""
        self.graph.add_node(user, type="user")
        self.graph.add_node(ip, type="ip")
        self.graph.add_node(device, type="device")
        
        self.graph.add_edge(user, ip, relation="logged_in_from")
        self.graph.add_edge(user, device, relation="used_device")

    def search_threat_intel(self, query: str):
        """Returns hardcoded threat intelligence to avoid blocking model downloads."""
        return "Login from two distant geographic locations within a short time frame is highly indicative of an impossible travel anomaly or compromised account. Recommended action: BLOCK_IP or LOCK_ACCOUNT."

memory_store = MemoryStore()
