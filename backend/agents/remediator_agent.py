from agents.base_agent import BaseAgent
from database.tigergraph_client import TigerGraphClient


class RemediatorAgent(BaseAgent):
    
    def __init__(self):
        super().__init__()
        self.tg = TigerGraphClient()

    def generate_playbook(self, asset_id: str, incident_context: str = None) -> dict:
        """
        Generate remediation commands for a vulnerable asset.
        """
        asset = self.tg.get_asset_by_id(asset_id)
        if not asset:
            return {"error": f"Asset {asset_id} not found"}

        vulnerabilities = self.tg.get_asset_vulnerabilities(asset_id)
        unpatched = [v for v in vulnerabilities if not v.get("is_patched")]

        if not unpatched:
            return {
                "asset": asset,
                "message": "No unpatched vulnerabilities found.",
                "commands": "No remediation required.",
                "severity": "LOW"
            }

        # Severity calculation
        avg_cvss = sum(v.get("cvss_score", 0) for v in unpatched) / len(unpatched)
        highest_cvss = max(v.get("cvss_score", 0) for v in unpatched)

        if avg_cvss >= 9.0 or highest_cvss >= 9.8:
            severity = "CRITICAL"
        elif avg_cvss >= 7.0 or highest_cvss >= 8.0:
            severity = "HIGH"
        elif avg_cvss >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        prompt = self._build_prompt(asset, unpatched, incident_context, severity)
        commands = self._call_llm(prompt, temperature=0.1)

        return {
            "asset": asset,
            "severity": severity,
            "vulnerabilities": [v.get('cve_id') for v in unpatched],
            "commands": commands
        }

    def _build_prompt(self, asset, unpatched, incident_context, severity):
        """Build clean prompt - plain text output only"""
        
        # Simple list of CVEs
        cve_list = ", ".join([v.get('cve_id') for v in unpatched])
        
        # OS detection
        os_type = asset.get('os', 'Linux').lower()
        if 'ubuntu' in os_type or 'debian' in os_type:
            package_manager = "apt"
        elif 'rhel' in os_type or 'centos' in os_type:
            package_manager = "yum"
        elif 'windows' in os_type:
            package_manager = "winget"
        else:
            package_manager = "apt"

        # Incident context
        incident_text = ""
        if incident_context:
            incident_text = f"ACTIVE BREACH: {incident_context}\n"

        return f"""You are an incident responder. Write remediation commands.
Donot include <think> tokens please as well make sure that  
{incident_text}
ASSET: {asset.get('name')}
OS: {asset.get('os')}
SEVERITY: {severity}
VULNERABILITIES: {cve_list}
PACKAGE MANAGER: {package_manager}

Write plain text commands for these steps:

CONTAINMENT:
- Command to isolate network
- Command to stop vulnerable service

ERADICATION:
- Command to patch using {package_manager}

RECOVERY:
- Command to restart service

VERIFICATION:
- Command to check patch version

ROLLBACK:
- Command to revert changes

RULES:
- Write ONLY commands, and explanations , code blocks if required but not messy it should be clear to read and understand 
- No markdown, no asterisks
- One command per line
- Do not add any extra text

Now write the commands:"""