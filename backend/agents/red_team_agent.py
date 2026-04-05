import random
from collections import Counter, defaultdict
from agents.base_agent import BaseAgent
from database.tigergraph_client import TigerGraphClient


class RedTeamAgent(BaseAgent):
    def __init__(self):
        super().__init__()
        self.tg = TigerGraphClient()

    def run_simulation(self, start_asset_id: str, target_asset_id: str, iterations: int = 500) -> dict:
        """
        Run multiple attack simulations to find success rate and weak points.
        
        This agent simulates an attacker moving through the network,
        tracking success rates, most common paths, and identifying weak points.
        """
        # Get all connections and vulnerabilities
        connections = self.tg.get_all_connections()
        all_assets = self.tg.get_all_assets()
        
        # Build asset lookup dictionary
        asset_lookup = {a.get('asset_id'): a for a in all_assets if a}
        
        # Build graph with weights (vulnerable paths are more likely)
        graph = defaultdict(list)
        for conn in connections:
            from_id = conn.get("from_asset_id")
            to_id = conn.get("to_asset_id")
            if from_id and to_id:
                graph[from_id].append(to_id)
        
        # Get vulnerabilities for weighted probability
        vuln_map = self._get_vulnerability_map()
        
        if start_asset_id not in graph:
            return {
                "error": f"Start asset {start_asset_id} has no outgoing connections",
                "success_rate": 0,
                "successful_simulations": 0
            }
        
        # Run simulations
        successful_paths = []
        all_paths_attempted = []
        step_counts = []
        max_steps = 6
        
        for iteration in range(iterations):
            current = start_asset_id
            path = [current]
            steps_taken = 0
            success = False
            
            for step in range(max_steps):
                neighbors = graph.get(current, [])
                if not neighbors:
                    break
                
                # Choose neighbor with weighted probability (vulnerable nodes more likely)
                current = self._weighted_choice(neighbors, vuln_map)
                path.append(current)
                steps_taken += 1
                
                if current == target_asset_id:
                    success = True
                    successful_paths.append(path)
                    break
            
            all_paths_attempted.append(path)
            step_counts.append(steps_taken)
        
        # Calculate statistics
        success_rate = len(successful_paths) / iterations * 100
        
        # Find most common successful path
        path_strings = [" → ".join(p) for p in successful_paths]
        most_common = Counter(path_strings).most_common(1)
        most_common_path = most_common[0][0] if most_common else None
        
        # Identify weak points (most frequently visited nodes)
        weak_points = self._identify_weak_points(all_paths_attempted, asset_lookup)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(success_rate, len(successful_paths), iterations)
        
        # Build enhanced prompt
        prompt = self._build_prompt(
            start_asset_id, target_asset_id, iterations,
            success_rate, successful_paths, most_common_path,
            weak_points, risk_score, asset_lookup
        )
        
        explanation = self._call_llm(prompt, temperature=0.3)
        
        # Get sample paths with asset names
        named_sample_paths = self._get_named_paths(successful_paths[:3], asset_lookup)
        
        return {
            "success_rate": round(success_rate, 2),
            "successful_simulations": len(successful_paths),
            "total_simulations": iterations,
            "risk_score": risk_score,
            "risk_level": self._get_risk_level(risk_score),
            "most_common_path": most_common_path,
            "most_common_path_named": self._path_to_names(most_common_path, asset_lookup) if most_common_path else None,
            "weak_points": weak_points[:5],
            "average_steps_to_target": sum(step_counts) / len(step_counts) if step_counts else 0,
            "sample_successful_paths": named_sample_paths,
            "explanation": explanation
        }

    def _get_vulnerability_map(self):
        """Create a map of assets to their vulnerability score"""
        vuln_map = {}
        try:
            all_assets = self.tg.get_all_assets()
            for asset in all_assets:
                asset_id = asset.get('asset_id')
                if asset_id:
                    vulns = self.tg.get_asset_vulnerabilities(asset_id)
                    unpatched = [v for v in vulns if not v.get('is_patched')]
                    if unpatched:
                        # Higher CVSS = higher probability of being chosen
                        avg_cvss = sum(v.get('cvss_score', 0) for v in unpatched) / len(unpatched)
                        vuln_map[asset_id] = min(avg_cvss / 10, 1.0)  # Normalize to 0-1
                    else:
                        vuln_map[asset_id] = 0.1  # Low base probability
        except Exception:
            pass
        return vuln_map

    def _weighted_choice(self, neighbors, vuln_map):
        """Choose a neighbor with probability weighted by vulnerability score"""
        if not neighbors:
            return random.choice(neighbors) if neighbors else None
        
        weights = []
        for n in neighbors:
            weight = vuln_map.get(n, 0.1)  # Default low weight
            weights.append(max(weight, 0.01))  # Ensure positive weight
        
        return random.choices(neighbors, weights=weights, k=1)[0]

    def _identify_weak_points(self, all_paths, asset_lookup):
        """Identify most frequently visited nodes (weak points)"""
        node_count = Counter()
        for path in all_paths:
            for node in path:
                node_count[node] += 1
        
        weak_points = []
        for node, count in node_count.most_common(10):
            asset = asset_lookup.get(node, {})
            weak_points.append({
                "asset_id": node,
                "name": asset.get('name', node),
                "asset_type": asset.get('asset_type', 'Unknown'),
                "visit_count": count,
                "is_critical": asset.get('is_critical', False)
            })
        
        return weak_points

    def _calculate_risk_score(self, success_rate, successful_count, total_iterations):
        """Calculate risk score (0-100)"""
        score = 0
        
        # Success rate contribution (max 60)
        score += min(success_rate * 0.6, 60)
        
        # If any successful path exists (20)
        if successful_count > 0:
            score += 20
        
        # Volume contribution (max 20)
        if successful_count > total_iterations * 0.3:
            score += 20
        elif successful_count > total_iterations * 0.1:
            score += 10
        
        return min(int(score), 100)

    def _get_risk_level(self, score):
        """Convert score to risk level"""
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

    def _get_named_paths(self, paths, asset_lookup):
        """Convert path IDs to named paths"""
        named_paths = []
        for path in paths:
            named_path = []
            for node in path:
                asset = asset_lookup.get(node, {})
                named_path.append(asset.get('name', node))
            named_paths.append(" → ".join(named_path))
        return named_paths

    def _path_to_names(self, path_string, asset_lookup):
        """Convert a path string of IDs to names"""
        if not path_string:
            return None
        ids = path_string.split(" → ")
        names = []
        for aid in ids:
            asset = asset_lookup.get(aid, {})
            names.append(asset.get('name', aid))
        return " → ".join(names)

    def _build_prompt(self, start, target, iterations, success_rate, 
                      successful_paths, most_common_path, weak_points, 
                      risk_score, asset_lookup):
        """Build production-grade simulation analysis prompt"""
        
        # Format weak points
        weak_text = ""
        for wp in weak_points[:5]:
            critical = "🔴 CRITICAL" if wp.get('is_critical') else "🟡 Standard"
            weak_text += f"- **{wp.get('name')}** ({critical}): Visited {wp.get('visit_count')} times\n"
        
        if not weak_text:
            weak_text = "No significant weak points identified"
        
        # Format success metrics
        success_text = f"""
- Success Rate: {success_rate:.1f}%
- Successful Compromises: {len(successful_paths)} out of {iterations}
- Risk Score: {risk_score}/100
- Most Common Path: {most_common_path if most_common_path else 'None found'}
"""
        
        # Add note if no successful paths
        no_success_note = ""
        if len(successful_paths) == 0:
            no_success_note = """
⚠️ **IMPORTANT:** No successful paths were found in this simulation. 
This could mean:
1. The target is well-isolated
2. The start asset cannot reach the target
3. More iterations may be needed
"""

        return f"""
You are a red team operator and security analyst. Analyze these simulation results.
DO NOT include any thinking, reasoning, or explanations. DO NOT use <think> tags. OUTPUT ONLY the playbook and the response needed.

## SIMULATION CONFIGURATION
- Start Asset: {start}
- Target Asset: {target}
- Total Simulations Run: {iterations}
- Max Steps per Simulation: 6

## RESULTS SUMMARY
{success_text}

{no_success_note}

## IDENTIFIED WEAK POINTS
Assets most frequently visited during simulations (attacker's preferred targets):

{weak_text}

## YOUR TASK
Write a professional red team analysis report with EXACTLY these 4 sections:

### 1. EXECUTIVE SUMMARY (2-3 sentences)
- What was tested
- Key finding (success rate)
- Overall risk level

### 2. ATTACK PATH ANALYSIS
- Describe the most common attack path (if found)
- Explain why this path works
- Identify the weakest link in the chain

### 3. WEAK POINTS IDENTIFIED
- List the most vulnerable assets from the data above
- Explain why attackers prefer these targets
- Note any critical assets that were frequently accessed

### 4. RECOMMENDATIONS
Provide SPECIFIC, ACTIONABLE fixes:
- Network segmentation improvements
- Patching priorities
- Monitoring rules to detect this attack pattern

## CRITICAL RULES
1. **NO hallucinations.** Use ONLY the data provided above.
2. **Be specific.** Reference actual asset names from the weak points list.
3. **If no path found:** Explain what this means and recommend increasing iterations or checking connectivity.
4. **Return ONLY markdown.** No text before or after the 4 sections.
5. **Keep executive summary short.** Management will read this first.

Now generate the red team analysis report:
"""
