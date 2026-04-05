import pyTigerGraph as tg
from backend.config import Config
from typing import List, Dict, Any

class TigerGraphClient:
    def __init__(self):
        self.conn = tg.TigerGraphConnection(
            host=Config.TIGERGRAPH_HOST,
            graphname=Config.TIGERGRAPH_GRAPHNAME,
            username=Config.TIGERGRAPH_USERNAME,
            password=Config.TIGERGRAPH_PASSWORD,
            useCert=True
        )
        self.conn.getToken(self.conn.secret, setToken=True)
    
    # ========== VERTEX QUERIES ==========
    def get_all_assets(self) -> List[Dict]:
        query = "SELECT asset_id, name, ip, asset_type, is_critical, os FROM Asset"
        return self.conn.runInstalledQuery(query) or []
    
    def get_asset_by_id(self, asset_id: str) -> Dict:
        query = f"""
        SELECT asset_id, name, ip, asset_type, is_critical, os 
        FROM Asset WHERE asset_id == "{asset_id}"
        """
        result = self.conn.runInstalledQuery(query)
        return result[0] if result else None
    
    def get_asset_vulnerabilities(self, asset_id: str) -> List[Dict]:
        query = f"""
        SELECT Vulnerability.cve_id, Vulnerability.name, Vulnerability.cvss_score,
               HAS_VULN.is_patched, HAS_VULN.discovered_date
        FROM Asset -[HAS_VULN]-> Vulnerability
        WHERE Asset.asset_id == "{asset_id}"
        """
        return self.conn.runInstalledQuery(query) or []
    
    def get_asset_connections(self, asset_id: str, direction: str = "out") -> List[Dict]:
        """
        direction: 'out' (from asset) or 'in' (to asset) or 'both'
        """
        if direction == "out":
            query = f"""
            SELECT CONNECTS_TO.to_asset_id AS connected_asset, 
                   CONNECTS_TO.port, CONNECTS_TO.protocol
            FROM Asset -[CONNECTS_TO]-> Asset:connected
            WHERE Asset.asset_id == "{asset_id}"
            """
        elif direction == "in":
            query = f"""
            SELECT CONNECTS_TO.from_asset_id AS connected_asset,
                   CONNECTS_TO.port, CONNECTS_TO.protocol
            FROM Asset <-[CONNECTS_TO]- Asset:connected
            WHERE Asset.asset_id == "{asset_id}"
            """
        else:
            # both directions
            query = f"""
            SELECT CONNECTS_TO.from_asset_id, CONNECTS_TO.to_asset_id,
                   CONNECTS_TO.port, CONNECTS_TO.protocol
            FROM Asset -[CONNECTS_TO]- Asset
            WHERE Asset.asset_id == "{asset_id}"
            """
        return self.conn.runInstalledQuery(query) or []
    
    def get_all_connections(self) -> List[Dict]:
        """Get all CONNECTS_TO edges for red team simulation"""
        query = "SELECT from_asset_id, to_asset_id, port, protocol FROM CONNECTS_TO"
        return self.conn.runInstalledQuery(query) or []
    
    def get_threat_actors_targeting(self, asset_id: str) -> List[Dict]:
        query = f"""
        SELECT ThreatActor.name, ThreatActor.motivation, ThreatActor.known_tools
        FROM ThreatActor -[TARGETS]-> Asset
        WHERE Asset.asset_id == "{asset_id}"
        """
        return self.conn.runInstalledQuery(query) or []
    
    def get_incident_by_id(self, incident_id: str) -> Dict:
        query = f"""
        SELECT incident_id, timestamp, attack_type, description
        FROM Incident WHERE incident_id == "{incident_id}"
        """
        result = self.conn.runInstalledQuery(query)
        return result[0] if result else None
    
    def get_incident_asset(self, incident_id: str) -> Dict:
        query = f"""
        SELECT Asset.asset_id, Asset.name, Asset.ip, Asset.asset_type
        FROM Incident -[CAUSED]-> Asset
        WHERE Incident.incident_id == "{incident_id}"
        """
        result = self.conn.runInstalledQuery(query)
        return result[0] if result else None
    
    def get_all_incidents(self) -> List[Dict]:
        query = "SELECT incident_id, timestamp, attack_type, description FROM Incident"
        return self.conn.runInstalledQuery(query) or []
    
    # ========== PATHFINDING ==========
    def shortest_path(self, start_asset_id: str, target_asset_id: str) -> List[str]:
        """
        Returns list of asset IDs along the shortest path.
        Requires installed query 'shortest_attack_path'
        """
        try:
            result = self.conn.runInstalledQuery("shortest_attack_path", {
                "start": start_asset_id,
                "target": target_asset_id
            })
            # Parse result to extract path (depends on TigerGraph output format)
            # Assuming result[0]['path'] contains list of vertices
            if result and "path" in result[0]:
                return [v["attributes"]["asset_id"] for v in result[0]["path"]]
        except:
            # Fallback: use simple BFS via GSQL
            query = f"""
            USE GRAPH CyberDefense
            INTERPRET QUERY () {{
                ListAccum<VERTEX> @@path;
                @@path = shortest_path(("{start_asset_id}", "{target_asset_id}"), "CONNECTS_TO", true);
                PRINT @@path;
            }}
            """
            # This is simplified; in practice you'd parse the output.
            pass
        return []
    
    # ========== CRITICAL RISKS ==========
    def get_critical_risks(self) -> List[Dict]:
        query = """
        SELECT Asset.name, Asset.ip, Vulnerability.cve_id, Vulnerability.cvss_score
        FROM Asset -[HAS_VULN]-> Vulnerability
        WHERE Asset.is_critical == true 
          AND HAS_VULN.is_patched == false 
          AND Vulnerability.cvss_score > 8.0
        """
        return self.conn.runInstalledQuery(query) or []