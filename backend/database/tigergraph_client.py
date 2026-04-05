import requests
import json
from typing import List, Dict, Any
from config import Config

class TigerGraphClient:
    def __init__(self):
        self.host = Config.TIGERGRAPH_HOST.rstrip('/')
        self.username = Config.TIGERGRAPH_USERNAME
        self.password = Config.TIGERGRAPH_PASSWORD
        self.graphname = Config.TIGERGRAPH_GRAPHNAME
        self.token = None
        
        # Try to authenticate
        self._authenticate()
    
    def _authenticate(self):
        """Authenticate using REST API"""
        try:
            url = f"{self.host}/restpp/requesttoken"
            response = requests.post(
                url,
                json={"username": self.username, "password": self.password},
                headers={"Content-Type": "application/json"}
            )
            if response.status_code == 200:
                self.token = response.json().get("token")
                print("✅ TigerGraph authenticated successfully!")
            else:
                print(f"⚠️ Authentication failed: {response.status_code}")
        except Exception as e:
            print(f"⚠️ Could not authenticate: {e}")
            print("Will try unauthenticated queries...")
    
    def _get_headers(self):
        """Get headers with auth token"""
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers
    
    def _run_query(self, query: str) -> List[Dict]:
        """Run a query using REST API"""
        try:
            url = f"{self.host}/gsqlserver/gsql"
            response = requests.post(
                url,
                data=query,
                headers=self._get_headers()
            )
            if response.status_code == 200:
                result = response.json()
                return result if result else []
        except Exception as e:
            print(f"Query error: {e}")
        return []
    
    # ========== VERTEX QUERIES ==========
    def get_all_assets(self) -> List[Dict]:
        query = "USE GRAPH CyberDefense\nINTERPRET QUERY () FOR GRAPH CyberDefense {\n  assets = {Asset.*};\n  PRINT assets;\n}"
        result = self._run_query(query)
        if result and "assets" in result:
            return result["assets"]
        return self._get_mock_assets()
    
    def _get_mock_assets(self) -> List[Dict]:
        """Fallback mock data when TigerGraph is not accessible"""
        return [
            {"asset_id": "asset_001", "name": "prod-web-01", "ip": "172.16.1.10", "asset_type": "web_server", "is_critical": False, "os": "Ubuntu 22.04"},
            {"asset_id": "asset_002", "name": "prod-api-01", "ip": "172.16.2.10", "asset_type": "api_server", "is_critical": True, "os": "Ubuntu 20.04"},
            {"asset_id": "asset_003", "name": "customer-db", "ip": "10.0.1.10", "asset_type": "database", "is_critical": True, "os": "Red Hat 8"},
            {"asset_id": "asset_004", "name": "finance-workstation", "ip": "192.168.1.101", "asset_type": "workstation", "is_critical": False, "os": "Windows 10"},
            {"asset_id": "asset_005", "name": "core-banking-db", "ip": "10.0.2.10", "asset_type": "database", "is_critical": True, "os": "Oracle Linux"},
        ]
    
    def get_asset_by_id(self, asset_id: str) -> Dict:
        assets = self.get_all_assets()
        for a in assets:
            if a.get("asset_id") == asset_id:
                return a
        return None
    
    def get_asset_vulnerabilities(self, asset_id: str) -> List[Dict]:
        # Mock vulnerabilities for testing
        mock_vulns = {
            "asset_001": [
                {"cve_id": "CVE-2021-44228", "name": "Log4Shell", "cvss_score": 10.0, "is_patched": False, "discovered_date": "2022-01-15"},
                {"cve_id": "CVE-2024-6387", "name": "OpenSSH RCE", "cvss_score": 8.1, "is_patched": False, "discovered_date": "2024-07-10"},
            ],
            "asset_002": [
                {"cve_id": "CVE-2022-22965", "name": "Spring4Shell", "cvss_score": 9.8, "is_patched": False, "discovered_date": "2022-04-10"},
            ],
            "asset_005": [
                {"cve_id": "CVE-2024-6387", "name": "OpenSSH RCE", "cvss_score": 8.1, "is_patched": True, "discovered_date": "2024-07-15"},
            ],
        }
        return mock_vulns.get(asset_id, [])
    
    def get_asset_connections(self, asset_id: str, direction: str = "out") -> List[Dict]:
        mock_connections = {
            "asset_001": [
                {"connected_asset": "asset_002", "port": 443, "protocol": "tcp"},
                {"connected_asset": "asset_005", "port": 3306, "protocol": "tcp"},
            ],
            "asset_002": [
                {"connected_asset": "asset_005", "port": 5432, "protocol": "tcp"},
            ],
        }
        if direction == "out":
            return mock_connections.get(asset_id, [])
        return []
    
    def get_all_connections(self) -> List[Dict]:
        return [
            {"from_asset_id": "asset_001", "to_asset_id": "asset_002", "port": 443, "protocol": "tcp"},
            {"from_asset_id": "asset_001", "to_asset_id": "asset_005", "port": 3306, "protocol": "tcp"},
            {"from_asset_id": "asset_002", "to_asset_id": "asset_005", "port": 5432, "protocol": "tcp"},
        ]
    
    def get_threat_actors_targeting(self, asset_id: str) -> List[Dict]:
        return [
            {"name": "Lazarus Group", "motivation": "Financial", "known_tools": "Mimikatz, Cobalt Strike"},
            {"name": "LockBit", "motivation": "Ransomware", "known_tools": "LockBit encryptor"},
        ]
    
    def get_incident_by_id(self, incident_id: str) -> Dict:
        return {
            "incident_id": incident_id,
            "timestamp": "2024-03-12T09:47:00Z",
            "attack_type": "phishing",
            "description": "Spear-phishing email with malicious Excel attachment"
        }
    
    def get_incident_asset(self, incident_id: str) -> Dict:
        return {"asset_id": "asset_001", "name": "prod-web-01", "ip": "172.16.1.10", "asset_type": "web_server"}
    
    def get_all_incidents(self) -> List[Dict]:
        return [
            {"incident_id": "INC-2024-001", "timestamp": "2024-03-12T09:47:00Z", "attack_type": "phishing", "description": "Phishing attack on finance workstation"},
            {"incident_id": "INC-2024-002", "timestamp": "2024-04-22T14:10:00Z", "attack_type": "exploit", "description": "OpenSSH RCE exploitation"},
        ]
    
    def get_critical_risks(self) -> List[Dict]:
        return [
            {"name": "prod-web-01", "ip": "172.16.1.10", "cve_id": "CVE-2021-44228", "cvss_score": 10.0},
            {"name": "prod-api-01", "ip": "172.16.2.10", "cve_id": "CVE-2022-22965", "cvss_score": 9.8},
        ]