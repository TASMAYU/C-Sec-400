from agents.base_agent import BaseAgent
from database.tigergraph_client import TigerGraphClient


class RCAAgent(BaseAgent):
    def __init__(self):
        super().__init__()
        self.tg = TigerGraphClient()

    def generate_rca(self, incident_id: str) -> dict:
        """
        Generate root cause analysis report for an incident.
        """
        incident = self.tg.get_incident_by_id(incident_id)
        if not incident:
            return {"error": f"Incident {incident_id} not found"}

        asset_info = self.tg.get_incident_asset(incident_id)
        
        if asset_info:
            asset_id = asset_info.get("asset_id")
            vulnerabilities = self.tg.get_asset_vulnerabilities(asset_id)
            threat_actors = self.tg.get_threat_actors_targeting(asset_id)
            connections = self.tg.get_asset_connections(asset_id, direction="both")
        else:
            asset_id = None
            vulnerabilities = []
            threat_actors = []
            connections = []

        # Calculate severity
        severity = self._calculate_incident_severity(incident, vulnerabilities)

        prompt = self._build_clean_prompt(
            incident, asset_info, vulnerabilities, threat_actors, connections, severity
        )

        report = self._call_llm(prompt, temperature=0.2)

        # Extract key findings for structured output
        key_findings = self._extract_key_findings(report)

        return {
            "incident": incident,
            "affected_asset": asset_info,
            "severity": severity["level"],
            "severity_score": severity["score"],
            "vulnerabilities_involved": [v for v in vulnerabilities if not v.get("is_patched")],
            "suspected_threat_actors": threat_actors,
            "key_findings": key_findings,
            "root_cause_analysis": report
        }

    def _build_clean_prompt(self, incident, asset_info, vulnerabilities, threat_actors, connections, severity):
        """Build clean RCA prompt - no markdown, no emojis, plain text"""
        
        # Format vulnerabilities
        if vulnerabilities:
            vuln_list = []
            for v in vulnerabilities:
                status = "UNPATCHED" if not v.get("is_patched") else "PATCHED"
                vuln_list.append(f"  - {v.get('cve_id')}: CVSS {v.get('cvss_score')} - {v.get('name')} [{status}]")
            vuln_text = "\n".join(vuln_list)
        else:
            vuln_text = "  No vulnerabilities found on this asset"

        # Format threat actors
        if threat_actors:
            threat_list = []
            for ta in threat_actors:
                threat_list.append(f"  - {ta.get('name')}: {ta.get('motivation')} (Tools: {ta.get('known_tools', 'Unknown')})")
            threat_text = "\n".join(threat_list)
        else:
            threat_text = "  No known threat actors target this asset type"

        # Format connections
        if connections:
            conn_list = []
            for conn in connections[:5]:
                conn_list.append(f"  - {conn.get('connected_asset')} (port {conn.get('port')})")
            conn_text = "\n".join(conn_list)
        else:
            conn_text = "  No connection data available"

        # Asset criticality
        asset_critical = "Yes - This is a CRITICAL asset" if asset_info and asset_info.get('is_critical') else "No"

        return f"""You are a senior forensic investigator. Write a Root Cause Analysis report.

DO NOT use markdown. DO NOT use emojis. DO NOT use bold or italics. Use plain text only.
Produce ONLY the report. Do NOT include any thinking, reasoning, or explanations. Do NOT use think tags. Do NOT start with phrases like "Okay, let's start". Start directly with the report content.
like directly with the SUMMARY part 

Use these exact section headers:

SUMMARY OF THE SECURITY BREACH

TIMELINE OF EVENTS

TECHNICAL ROOT CAUSE

IMPACT ASSESSMENT

RECOMMENDED FIXES

Now use this data:

Incident ID: {incident.get('incident_id')}
Timestamp: {incident.get('timestamp')}
Attack Type: {incident.get('attack_type')}
Description: {incident.get('description')}
Severity: {severity['level']} (Score: {severity['score']}/100)

Affected Asset:
- Name: {asset_info.get('name') if asset_info else 'Unknown'}
- IP: {asset_info.get('ip') if asset_info else 'Unknown'}
- Type: {asset_info.get('asset_type') if asset_info else 'Unknown'}
- OS: {asset_info.get('os') if asset_info else 'Unknown'}
- Critical: {asset_critical}

Vulnerabilities on affected asset:
{vuln_text}

Threat actors targeting this asset type:
{threat_text}

Network connections:
{conn_text}

Write a DETAILED long RCA report. Each section must have 3-5 sentences. Be specific using the data above. If data is missing, state "No data available" instead of inventing.

SUMMARY OF THE SECURITY BREACH: Explain what happened in plain English, the root cause in one sentence, and whether customer data was affected.

TIMELINE OF EVENTS: Create a numbered list with estimated times for initial compromise, detection, containment, and eradication.

TECHNICAL ROOT CAUSE: Explain which vulnerability or misconfiguration was exploited, why it wasn't patched, and what security control failed.

IMPACT ASSESSMENT: Describe what data was accessed or exposed, what systems were affected, business impact, and whether customers were affected.

RECOMMENDED FIXES: List immediate fixes with specific commands, long-term improvements, and how to verify each fix worked.

Now write the report in a long and detailed way:"""

    def _calculate_incident_severity(self, incident, vulnerabilities):
        """Calculate incident severity score"""
        score = 0

        # Attack type severity
        attack_type = incident.get('attack_type', '').lower()
        if attack_type == 'ransomware':
            score += 35
        elif attack_type == 'exploit':
            score += 30
        elif attack_type == 'phishing':
            score += 25
        elif attack_type == 'misconfiguration':
            score += 20
        elif attack_type == 'insider':
            score += 30
        elif attack_type == 'ddos':
            score += 15
        else:
            score += 20

        # Vulnerability severity
        if vulnerabilities:
            unpatched_cvss = [v.get('cvss_score', 0) for v in vulnerabilities if not v.get('is_patched')]
            if unpatched_cvss:
                avg_cvss = sum(unpatched_cvss) / len(unpatched_cvss)
                score += min(avg_cvss * 3, 40)

        # Determine level
        if score >= 70:
            level = "CRITICAL"
        elif score >= 50:
            level = "HIGH"
        elif score >= 30:
            level = "MEDIUM"
        elif score >= 15:
            level = "LOW"
        else:
            level = "INFO"

        return {"level": level, "score": min(int(score), 100)}

    def _extract_key_findings(self, report: str) -> list:
        """Extract key findings from the RCA report"""
        findings = []
        lines = report.split('\n')
        
        for line in lines:
            line_lower = line.lower()
            # Look for sentences that indicate root cause or key findings
            if any(keyword in line_lower for keyword in ['root cause', 'vulnerability', 'exploited', 'failed', 'unpatched']):
                clean_line = line.strip()
                if clean_line and len(clean_line) < 200 and len(clean_line) > 20:
                    findings.append(clean_line)
        
        # If no findings extracted, provide default
        if not findings:
            findings = ["Review the full RCA report for detailed findings"]
        
        return findings[:4]





