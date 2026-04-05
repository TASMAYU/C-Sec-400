from agents.base_agent import BaseAgent
from database.tigergraph_client import TigerGraphClient


class PredictorAgent(BaseAgent):
    def __init__(self):
        super().__init__()
        self.tg = TigerGraphClient()
    
    def predict_attack(self, asset_id: str) -> dict:
        """
        Generate an attack prediction narrative for a specific asset.
        """
        asset = self.tg.get_asset_by_id(asset_id)
        if not asset:
            return {"error": f"Asset {asset_id} not found"}
        
        vulnerabilities = self.tg.get_asset_vulnerabilities(asset_id)
        unpatched = [v for v in vulnerabilities if not v.get("is_patched")]
        
        incoming_connections = self.tg.get_asset_connections(asset_id, direction="in")
        outgoing_connections = self.tg.get_asset_connections(asset_id, direction="out")
        threat_actors = self.tg.get_threat_actors_targeting(asset_id)
        
        # Get reachable critical assets
        reachable_critical = self._get_reachable_critical_assets(asset_id)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(asset, unpatched, incoming_connections, outgoing_connections)
        
        # Build detailed clean prompt
        prompt = self._build_detailed_prompt(
            asset, unpatched, incoming_connections, 
            outgoing_connections, threat_actors, reachable_critical
        )
        
        narrative = self._call_llm(prompt, temperature=0.3)
        
        return {
            "asset": asset,
            "risk_score": risk_score,
            "risk_level": self._get_risk_level(risk_score),
            "unpatched_vulnerabilities": unpatched,
            "outgoing_connections": outgoing_connections,
            "reachable_critical_assets": reachable_critical,
            "prediction": narrative
        }
    
    def _build_detailed_prompt(self, asset, unpatched, incoming, outgoing, threat_actors, reachable_critical):
        """Build detailed but clean prompt - no markdown, no emojis"""
        
        # Format vulnerabilities
        vuln_text = "None found"
        if unpatched:
            vuln_list = []
            for v in unpatched:
                vuln_list.append(f"  - {v.get('cve_id')}: CVSS {v.get('cvss_score')} - {v.get('name')}")
                vuln_list.append(f"    Description: {v.get('description', 'No description')[:200]}")
            vuln_text = "\n".join(vuln_list)
        
        # Format outgoing connections
        outgoing_text = "None"
        if outgoing:
            out_list = []
            for c in outgoing:
                out_list.append(f"  - {c.get('connected_asset')} (port {c.get('port')}/{c.get('protocol')})")
            outgoing_text = "\n".join(out_list)
        
        # Format reachable critical assets
        critical_text = "None reachable"
        if reachable_critical:
            crit_list = []
            for c in reachable_critical:
                crit_list.append(f"  - {c.get('name')} ({c.get('asset_type')}) - {c.get('path_length')} hops away via {c.get('access_via')}")
            critical_text = "\n".join(crit_list)
        
        # Format threat actors
        threat_text = "None identified"
        if threat_actors:
            threat_list = []
            for t in threat_actors:
                threat_list.append(f"  - {t.get('name')}: {t.get('motivation')} (Tools: {t.get('known_tools', 'Unknown')})")
            threat_text = "\n".join(threat_list)
        
        return f"""You are a security analyst. Write a detailed attack prediction for this asset.

ASSET DETAILS
Name: {asset.get('name')}
Type: {asset.get('asset_type')}
IP: {asset.get('ip')}
OS: {asset.get('os')}
Critical: {'Yes - This asset handles sensitive banking data' if asset.get('is_critical') else 'No'}

UNPATCHED VULNERABILITIES
{vuln_text}

ASSETS THIS ASSET CAN REACH (Lateral Movement Risk)
{outgoing_text}

CRITICAL ASSETS AT RISK (What attacker can ultimately reach)
{critical_text}

THREAT ACTORS INTERESTED IN THIS ASSET
{threat_text}

Write a detailed attack prediction with these 6 sections. Use plain text. No markdown. No emojis. No bold.

ATTACK SUMMARY
Write 3-4 sentences explaining:
- Can this asset be compromised?
- What is the most dangerous vulnerability?
- What is the worst-case outcome?

ATTACKER PATH
Write numbered steps:
1. Initial Access: Which vulnerability and how?
2. Privilege Escalation: How would they gain more control?
3. Lateral Movement: Which assets would they move to and why?
4. Data Access: What specific data would they steal?

LIKELY THREAT ACTOR
Based on the data, which threat actor group would likely execute this attack? Explain their motivation and typical methods.

IMPACT ASSESSMENT
List:
- Data at risk: (specific types)
- Business impact: (operational, financial, reputational)
- Estimated time to compromise:

DEFENSIVE RECOMMENDATIONS
List 4 specific actions in priority order:
1. Highest Priority:
2. Medium Priority:
3. Low Priority:
4. Detection Method:

 ATTACKER'S PERSPECTIVE
Write 2-3 sentences from the attacker's point of view explaining why they would target this asset.

Be specific using the actual CVE IDs, asset names, and connection details provided. Keep the response detailed but concise. Total length around 400-500 words.

Now write the prediction:"""
    
    def _get_reachable_critical_assets(self, asset_id: str) -> list:
        """Find critical assets reachable from this asset via BFS"""
        connections = self.tg.get_all_connections()
        
        graph = {}
        for conn in connections:
            from_id = conn.get("from_asset_id")
            to_id = conn.get("to_asset_id")
            if from_id and to_id:
                graph.setdefault(from_id, []).append(to_id)
        
        visited = set()
        queue = [(asset_id, 0, [asset_id])]
        critical_assets = []
        
        while queue:
            current, depth, path = queue.pop(0)
            if current in visited or depth > 5:
                continue
            visited.add(current)
            
            if depth > 0 and current != asset_id:
                asset = self.tg.get_asset_by_id(current)
                if asset and asset.get("is_critical"):
                    critical_assets.append({
                        "name": asset.get("name"),
                        "asset_type": asset.get("asset_type"),
                        "path_length": depth,
                        "access_via": path[1] if len(path) > 1 else "direct"
                    })
            
            for neighbor in graph.get(current, []):
                if neighbor not in visited:
                    queue.append((neighbor, depth + 1, path + [neighbor]))
        
        return critical_assets[:5]
    
    def _calculate_risk_score(self, asset, unpatched, incoming, outgoing) -> int:
        score = 0
        if unpatched:
            avg_cvss = sum(v.get("cvss_score", 0) for v in unpatched) / len(unpatched)
            score += min(avg_cvss * 5, 50)
        if asset.get("is_critical"):
            score += 25
        if incoming:
            score += min(len(incoming) * 3, 15)
        if outgoing:
            score += min(len(outgoing) * 2, 10)
        return min(int(score), 100)
    
    def _get_risk_level(self, score: int) -> str:
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "NEGLIGIBLE"