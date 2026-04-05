from backend.agents.base_agent import BaseAgent
from backend.database.tigergraph_client import TigerGraphClient

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
                # Add is_critical to asset details
                asset['is_critical'] = asset.get('is_critical', False)
                path_details.append({
                    "asset_id": aid,
                    "name": asset.get("name"),
                    "type": asset.get("asset_type"),
                    "ip": asset.get("ip"),
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
                        "cvss": v.get("cvss_score")
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
        
        # Generate LLM explanation with enhanced prompt
        prompt = self._build_enhanced_prompt(
            path_details, 
            vulnerabilities_on_path
        )
        
        explanation = self._call_llm(prompt, temperature=0.3)
        
        return {
            "found": True,
            "path": path_details,
            "vulnerabilities": vulnerabilities_on_path,
            "explanation": explanation,
            "length": len(path_details),
            "risk_score": risk_score,
            "target_is_critical": target_critical
        }
    
    def _build_enhanced_prompt(self, path_details, vulnerabilities_on_path):
        """Build the enhanced prompt for LLM"""
        
        # Format the path string
        path_str = ' → '.join([f"{a['name']} ({a['type']})" for a in path_details])
        
        # Format vulnerabilities
        vulns_str = self._format_vulnerabilities(vulnerabilities_on_path, path_details)
        
        # Format criticality
        criticality_str = self._format_criticality(path_details)
        
        return f"""
You are a senior cybersecurity architect at a major bank. Your job is to analyze attack paths and explain them to security analysts in a way that drives immediate action.

## THE ATTACK PATH DISCOVERED
The following path was found from the TigerGraph database:

{path_str}

## VULNERABILITIES ALONG THE PATH
{vulns_str}

## ASSET CRITICALITY
{criticality_str}

## YOUR TASK
Write a **security alert** for the SOC (Security Operations Center) team. Follow this exact structure:

### 🔴 EXECUTIVE SUMMARY (1 sentence)
State the risk level and the core problem.

### 🗺️ ATTACKER MINDSET (2-3 sentences)
Explain step-by-step how an attacker would think while traversing this path. Use phrases like "First, the attacker would..." and "Then, they would pivot to..."

### ⚠️ CRITICAL VULNERABILITIES (bullet points)
List each unpatched vulnerability and EXPLAIN why it's dangerous in this specific context.

### 💥 POTENTIAL IMPACT (2-3 sentences)
What data or systems would be compromised? Be specific (e.g., "customer PII", "transaction signing keys", "SWIFT credentials").

### 🛡️ IMMEDIATE RECOMMENDATIONS (numbered list)
Give 3-5 specific, actionable steps. Include:
- Which vulnerability to patch FIRST
- What network rules to add
- What monitoring to enable

## STYLE GUIDELINES
- Use professional but urgent tone (like a real security alert)
- Assume the analyst has 5 minutes to read and act
- No markdown except for the headers and lists
- Keep total response under 400 words
- Be SPECIFIC using the actual asset and vulnerability names provided

Now write the security alert.
"""
    
    def _format_vulnerabilities(self, vulns, path_details):
        """Format vulnerabilities with asset context"""
        if not vulns:
            return "✅ No unpatched vulnerabilities found along this path."
        
        # Group vulnerabilities by asset
        vulns_by_asset = {}
        for v in vulns:
            asset_id = v.get("asset_id")
            vulns_by_asset.setdefault(asset_id, []).append(v)
        
        formatted = []
        for aid, asset_vulns in vulns_by_asset.items():
            asset_name = next((a['name'] for a in path_details if a['asset_id'] == aid), aid)
            formatted.append(f"\n📌 {asset_name}:")
            for v in asset_vulns:
                cvss = v.get("cvss", 0)
                if cvss >= 9.0:
                    severity = "🔴 CRITICAL"
                elif cvss >= 7.0:
                    severity = "🟠 HIGH"
                else:
                    severity = "🟡 MEDIUM"
                formatted.append(f"   - {severity} {v.get('cve')} (CVSS {cvss})")
        
        return "\n".join(formatted)
    
    def _format_criticality(self, path_details):
        """Highlight critical assets in the path"""
        critical_assets = [a['name'] for a in path_details if a.get('is_critical')]
        if critical_assets:
            return f"⚠️ CRITICAL ASSETS IN PATH: {', '.join(critical_assets)}"
        return "No critical assets in this path."
    
    def _calculate_risk_score(self, vulns, target_critical, path_length):
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
        # Score = 20 - (length * 4), minimum 0
        path_risk = max(0, 20 - (path_length * 4))
        score += path_risk
        
        return min(int(score), 100)