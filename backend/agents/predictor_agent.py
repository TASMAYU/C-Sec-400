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
        # Gather data from TigerGraph
        asset = self.tg.get_asset_by_id(asset_id)
        if not asset:
            return {"error": f"Asset {asset_id} not found"}
        
        vulnerabilities = self.tg.get_asset_vulnerabilities(asset_id)
        unpatched = [v for v in vulnerabilities if not v.get("is_patched")]
        patched = [v for v in vulnerabilities if v.get("is_patched")]
        
        incoming_connections = self.tg.get_asset_connections(asset_id, direction="in")
        outgoing_connections = self.tg.get_asset_connections(asset_id, direction="out")
        
        threat_actors = self.tg.get_threat_actors_targeting(asset_id)
        
        # Get critical assets reachable from this asset
        reachable_critical = self._get_reachable_critical_assets(asset_id)
        
        # Calculate detailed risk score
        risk_score = self._calculate_risk_score(
            asset, unpatched, incoming_connections, outgoing_connections
        )
        
        # Build enhanced prompt
        prompt = self._build_enhanced_prompt(
            asset, unpatched, patched, incoming_connections, 
            outgoing_connections, threat_actors, reachable_critical
        )
        
        narrative = self._call_llm(prompt, temperature=0.4)
        
        return {
            "asset": asset,
            "risk_score": risk_score,
            "risk_level": self._get_risk_level(risk_score),
            "unpatched_vulnerabilities": unpatched,
            "patched_vulnerabilities": patched,
            "incoming_connections": incoming_connections,
            "outgoing_connections": outgoing_connections,
            "threat_actors": threat_actors,
            "reachable_critical_assets": reachable_critical,
            "narrative": narrative,
            "recommended_actions": self._extract_recommendations(narrative)
        }
    
    def _build_enhanced_prompt(self, asset, unpatched, patched, incoming, outgoing, threat_actors, reachable_critical):
        """Build the enhanced prompt for LLM"""
        
        # Format vulnerabilities nicely
        vulns_section = self._format_vulnerabilities(unpatched, patched)
        
        # Format connections nicely
        connections_section = self._format_connections(incoming, outgoing)
        
        # Format threat actors
        threat_section = self._format_threat_actors(threat_actors)
        
        # Format reachable critical assets
        critical_section = self._format_reachable_critical(reachable_critical)
        
        return f"""
You are an elite red-team operator and threat intelligence expert at a major bank. Your job is to predict how an attacker would compromise a specific asset and what they would do next. Your analysis must be SPECIFIC, ACTIONABLE, and BASED ON THE DATA PROVIDED.
DO NOT include any thinking, reasoning, or explanations. DO NOT use <think> tags. OUTPUT ONLY the playbook and the response needed.
## ASSET UNDER ANALYSIS
- **Name:** {asset.get('name')}
- **Type:** {asset.get('asset_type')}
- **IP Address:** {asset.get('ip')}
- **Operating System:** {asset.get('os')}
- **Criticality:** {'🔴 CRITICAL - This asset handles sensitive banking data' if asset.get('is_critical') else '🟡 Standard - Non-critical but valuable'}

## VULNERABILITY ASSESSMENT
{vulns_section}

## NETWORK POSITION
{connections_section}

## THREAT LANDSCAPE
{threat_section}

## POTENTIAL DAMAGE (What the attacker can reach from here)
{critical_section}

## YOUR MISSION
Write a **detailed attack prediction report** following this EXACT structure:

### 🔴 ATTACK SUMMARY (2-3 sentences)
Briefly state: Can this asset be compromised? How easily? What's the worst-case scenario?

### 🗺️ ATTACKER PATH (Step-by-step)
Write a numbered list of EXACT steps an attacker would take:
1. **Initial Access:** Which vulnerability or misconfiguration would they exploit? Include the CVE ID if applicable.
2. **Privilege Escalation:** How would they gain higher privileges on this asset?
3. **Persistence:** How would they maintain access (if applicable)?
4. **Lateral Movement:** Which assets would they move to NEXT? Be specific about asset names.
5. **Data Access:** What sensitive data would they ultimately reach?

### 🎯 LIKELY THREAT ACTORS
Based on the data, which threat actor group would most likely execute this attack? Why? Include their motivation and known TTPs (Tactics, Techniques, Procedures).

### 💣 IMPACT ASSESSMENT
- **Data at risk:** Specific data types (e.g., customer PII, transaction keys, credentials)
- **Business impact:** Operational, financial, reputational, regulatory
- **Estimated time to compromise:** (e.g., "15 minutes", "2 hours")

### 🛡️ DEFENSIVE RECOMMENDATIONS (Priority order)
1. **HIGHEST PRIORITY:** Single most important fix
2. **MEDIUM PRIORITY:** Additional hardening measures
3. **LOW PRIORITY:** Defense-in-depth improvements
4. **DETECTION:** Specific logs or alerts to monitor

### 📊 ATTACKER'S VIEW (1 paragraph)
Write from the attacker's perspective: "I would target this asset because..."

## CRITICAL GUIDELINES
- **BE SPECIFIC:** Use the actual asset names, CVE IDs, and connection details provided
- **NO HALLUCINATION:** If data is missing, say "No data available" rather than inventing
- **ACTIONABLE:** Every recommendation should be something a security team can actually do
- **REALISTIC:** Use real-world attack techniques (MITRE ATT&CK framework)
- **LENGTH:** Keep under 600 words

Now write the attack prediction report.
"""
    
    def _format_vulnerabilities(self, unpatched, patched):
        """Format vulnerabilities section"""
        if not unpatched and not patched:
            return "✅ No vulnerability data available for this asset."
        
        result = []
        
        if unpatched:
            result.append("### 🔴 UNPATCHED VULNERABILITIES (CRITICAL)")
            for v in unpatched:
                cvss = v.get('cvss_score', 0)
                severity = "🔴 CRITICAL" if cvss >= 9.0 else "🟠 HIGH" if cvss >= 7.0 else "🟡 MEDIUM"
                result.append(f"- **{v.get('cve_id')}** ({severity}, CVSS {cvss})")
                result.append(f"  - {v.get('name', 'No description')}")
                result.append(f"  - Discovered: {v.get('discovered_date', 'Unknown')}")
                result.append("")
        
        if patched:
            result.append("### ✅ PATCHED VULNERABILITIES (Historical)")
            for v in patched[:3]:  # Limit to 3
                result.append(f"- {v.get('cve_id')} (CVSS {v.get('cvss_score')}) - Fixed")
        
        return "\n".join(result) if result else "No vulnerability data available."
    
    def _format_connections(self, incoming, outgoing):
        """Format network connections section"""
        result = []
        
        if incoming:
            result.append("### 📥 INCOMING CONNECTIONS (Assets that can reach THIS asset)")
            for conn in incoming[:5]:  # Limit to 5
                result.append(f"- **{conn.get('connected_asset')}** (port {conn.get('port')}/{conn.get('protocol')})")
        else:
            result.append("### 📥 INCOMING CONNECTIONS")
            result.append("- No incoming connections found (isolated asset)")
        
        result.append("")
        
        if outgoing:
            result.append("### 📤 OUTGOING CONNECTIONS (Assets THIS asset can reach)")
            for conn in outgoing[:5]:  # Limit to 5
                result.append(f"- **{conn.get('connected_asset')}** (port {conn.get('port')}/{conn.get('protocol')})")
        else:
            result.append("### 📤 OUTGOING CONNECTIONS")
            result.append("- No outgoing connections found (dead end for attacker)")
        
        return "\n".join(result)
    
    def _format_threat_actors(self, threat_actors):
        """Format threat actors section"""
        if not threat_actors:
            return "No specific threat actors are known to target this asset type."
        
        result = ["### 🎭 KNOWN THREAT ACTORS"]
        for ta in threat_actors:
            result.append(f"- **{ta.get('name')}**")
            result.append(f"  - Motivation: {ta.get('motivation', 'Unknown')}")
            result.append(f"  - Known tools: {ta.get('known_tools', 'Unknown')}")
        return "\n".join(result)
    
    def _format_reachable_critical(self, reachable_critical):
        """Format reachable critical assets section"""
        if not reachable_critical:
            return "❌ No critical assets are reachable from this asset (low blast radius)."
        
        result = ["### 💎 CRITICAL ASSETS REACHABLE FROM HERE"]
        for asset in reachable_critical:
            result.append(f"- **{asset.get('name')}** ({asset.get('asset_type')})")
            result.append(f"  - Path length: {asset.get('path_length')} hops")
            result.append(f"  - Access via: {asset.get('access_via')}")
        return "\n".join(result)
    
    def _get_reachable_critical_assets(self, asset_id: str) -> list:
        """
        Find critical assets reachable from this asset via BFS.
        Returns list of dicts with asset details and path length.
        """
        # Get all connections
        connections = self.tg.get_all_connections()
        
        # Build graph
        graph = {}
        for conn in connections:
            from_id = conn.get("from_asset_id")
            to_id = conn.get("to_asset_id")
            if from_id and to_id:
                graph.setdefault(from_id, []).append(to_id)
        
        # BFS to find critical assets
        visited = set()
        queue = [(asset_id, 0, [asset_id])]
        critical_assets = []
        
        while queue:
            current, depth, path = queue.pop(0)
            if current in visited or depth > 5:
                continue
            visited.add(current)
            
            # Check if current is critical (except the starting asset)
            if depth > 0 and current != asset_id:
                asset = self.tg.get_asset_by_id(current)
                if asset and asset.get("is_critical"):
                    critical_assets.append({
                        "name": asset.get("name"),
                        "asset_type": asset.get("asset_type"),
                        "path_length": depth,
                        "access_via": path[1] if len(path) > 1 else "direct"
                    })
            
            # Add neighbors
            for neighbor in graph.get(current, []):
                if neighbor not in visited:
                    queue.append((neighbor, depth + 1, path + [neighbor]))
        
        return critical_assets[:5]  # Return top 5
    
    def _calculate_risk_score(self, asset, unpatched, incoming, outgoing) -> int:
        """
        Calculate detailed risk score (0-100)
        """
        score = 0
        
        # Vulnerability contribution (max 50 points)
        if unpatched:
            avg_cvss = sum(v.get("cvss_score", 0) for v in unpatched) / len(unpatched)
            score += min(avg_cvss * 5, 50)
        
        # Asset criticality (25 points)
        if asset.get("is_critical"):
            score += 25
        
        # Network exposure (15 points)
        if incoming:
            score += min(len(incoming) * 3, 15)
        
        # Outgoing connections (10 points - lateral movement potential)
        if outgoing:
            score += min(len(outgoing) * 2, 10)
        
        # Threat actor targeting (bonus)
        threat_actors = self.tg.get_threat_actors_targeting(asset.get("asset_id"))
        if threat_actors:
            score += min(len(threat_actors) * 2, 10)
        
        return min(int(score), 100)
    
    def _get_risk_level(self, score: int) -> str:
        """Convert numeric score to risk level"""
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
    
    def _extract_recommendations(self, narrative: str) -> list:
        """
        Simple extraction of recommendations from narrative.
        In production, you might want to use a more sophisticated parser.
        """
        recommendations = []
        lines = narrative.split('\n')
        
        # Look for numbered recommendations
        for line in lines:
            line = line.strip()
            # Check for numbered list patterns
            if line.startswith(('1.', '2.', '3.', '4.', '5.', '-', '•')):
                # Clean up the line
                clean_line = line.lstrip('1234567890.-• ').strip()
                if clean_line and len(clean_line) < 200:  # Reasonable length
                    recommendations.append(clean_line)
        
        return recommendations[:5]  # Return top 5 recommendations