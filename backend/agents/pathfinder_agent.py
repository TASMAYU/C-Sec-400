from agents.base_agent import BaseAgent
from database.tigergraph_client import TigerGraphClient


class PathfinderAgent(BaseAgent):
    def __init__(self):
        super().__init__()
        self.tg = TigerGraphClient()
    
    def find_paths(self, start_asset_id: str, target_asset_id: str) -> dict:
        """
        Returns attack paths between two assets with explanation.
        """
        # Get shortest path from TigerGraph
        path_ids = self.tg.shortest_path(start_asset_id, target_asset_id)
        
        if not path_ids:
            return {
                "found": False,
                "message": "No direct path found between these assets.",
                "paths": []
            }
        
        # Fetch asset details for each node in path
        path_details = []
        for aid in path_ids:
            asset = self.tg.get_asset_by_id(aid)
            if asset:
                asset['is_critical'] = asset.get('is_critical', False)
                path_details.append({
                    "asset_id": aid,
                    "name": asset.get("name"),
                    "type": asset.get("asset_type"),
                    "ip": asset.get("ip"),
                    "os": asset.get("os"),
                    "is_critical": asset.get("is_critical")
                })
        
        # Get vulnerabilities on each asset along the path
        vulnerabilities_on_path = []
        for aid in path_ids:
            vulns = self.tg.get_asset_vulnerabilities(aid)
            for v in vulns:
                if not v.get("is_patched", True):
                    vulnerabilities_on_path.append({
                        "asset_id": aid,
                        "cve": v.get("cve_id"),
                        "name": v.get("name"),
                        "cvss": v.get("cvss_score"),
                        "description": v.get("description", "No description available")
                    })
        
        # Check if target is critical
        target_critical = False
        for a in path_details:
            if a['asset_id'] == target_asset_id:
                target_critical = a.get('is_critical', False)
                break
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(
            vulnerabilities_on_path, 
            target_critical, 
            len(path_details)
        )
        
        # Generate LLM explanation with clean prompt
        prompt = self._build_clean_prompt(
            path_details, 
            vulnerabilities_on_path,
            start_asset_id,
            target_asset_id
        )
        
        explanation = self._call_llm(prompt, temperature=0.3)
        
        return {
            "found": True,
            "path": path_details,
            "vulnerabilities": vulnerabilities_on_path,
            "explanation": explanation,
            "length": len(path_details),
            "risk_score": risk_score,
            "risk_level": self._get_risk_level(risk_score),
            "target_is_critical": target_critical
        }
    
    def _build_clean_prompt(self, path_details, vulnerabilities_on_path, start_id, target_id):
        """Build clean prompt - no markdown, no emojis, plain text"""
        
        # Format the path string
        path_str = " -> ".join([f"{a['name']} ({a['type']})" for a in path_details])
        
        # Format asset details
        asset_details = []
        for a in path_details:
            critical_flag = "YES - CRITICAL ASSET" if a.get('is_critical') else "No"
            asset_details.append(f"  - {a['name']} | Type: {a['type']} | IP: {a['ip']} | OS: {a['os']} | Critical: {critical_flag}")
        assets_text = "\n".join(asset_details)
        
        # Format vulnerabilities
        if vulnerabilities_on_path:
            vuln_details = []
            for v in vulnerabilities_on_path:
                asset_name = next((a['name'] for a in path_details if a['asset_id'] == v['asset_id']), v['asset_id'])
                vuln_details.append(f"  - {v['cve']} on {asset_name}: CVSS {v['cvss']} - {v['name']}")
                vuln_details.append(f"    Description: {v['description'][:150]}")
            vulns_text = "\n".join(vuln_details)
        else:
            vulns_text = "  No unpatched vulnerabilities found on this path."
        
        return f"""You are a senior cybersecurity architect. Analyze this attack path and provide a detailed security alert.

ATTACK PATH FOUND
Path: {path_str}
Path length: {len(path_details)} hops

ASSET DETAILS
{assets_text}

VULNERABILITIES ALONG PATH
{vulns_text}

Write a security alert with these 6 sections. Use plain text. No markdown. No emojis. No bold.

EXECUTIVE SUMMARY
Write 2-3 sentences explaining:
- The risk level
- The core problem
- Whether this path leads to critical assets

ATTACK PATH EXPLANATION
Write a step-by-step explanation:
- Step 1: How attacker enters the first asset
- Step 2: How they move to next asset
- Continue for each step in the path
- Final step: What they can do at the target

VULNERABILITIES EXPLAINED
For each vulnerability found:
- Which CVE and on which asset
- Why it is dangerous in this specific path
- How an attacker would exploit it

POTENTIAL IMPACT
List specific impacts:
- Data at risk: (specific types like customer PII, transaction records, credentials)
- Systems affected: (names of critical assets)
- Business consequences: (financial, operational, reputational)

RECOMMENDATIONS FOR THIS
Numbered list of specific actions:
1. Highest priority patch or action
2. Network changes needed
3. Monitoring to enable
4. Long-term hardening

RISK ASSESSMENT
- Overall risk level: (Critical/High/Medium/Low)
- Why this risk level
- Recommended timeline for remediation

RULES:
- Be specific - use actual asset names and CVE IDs
- No markdown formatting
- No emojis or special characters
- Keep professional tone
- Total response 400-600 words

Now write the security alert:"""
    
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
    
    def _calculate_risk_score(self, vulns, target_critical, path_length) -> int:
        """Calculate numeric risk score (0-100)"""
        score = 0
        
        # Vulnerability contribution (max 60 points)
        if vulns:
            avg_cvss = sum(v.get("cvss", 0) for v in vulns) / len(vulns)
            score += min(avg_cvss * 6, 60)
        
        # Target criticality (20 points)
        if target_critical:
            score += 20
        
        # Path length penalty (shorter = more dangerous, max 20 points)
        path_risk = max(0, 20 - (path_length * 4))
        score += path_risk
        
        return min(int(score), 100)