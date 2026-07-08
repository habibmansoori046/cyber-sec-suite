"""AI recommendation engine — uses Anthropic Claude for root cause analysis and remediation."""

import json
import logging
from typing import List, Dict, Optional

from config import settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an expert cybersecurity incident responder and analyst. Given an incident's 
timeline of events, produce a structured root cause analysis with actionable remediation steps.

Respond ONLY with valid JSON in this exact structure:
{
  "root_cause": "One-sentence root cause statement",
  "summary": "2-3 paragraph technical summary of the attack chain",
  "confidence": 0.0-1.0,
  "iocs": ["list of indicators of compromise extracted from the timeline"],
  "remediations": [
    {
      "priority": "P0|P1|P2|P3",
      "action": "Specific remediation action",
      "impact": "What this fixes",
      "effort": "Time estimate"
    }
  ]
}

P0 = must be done within the hour (active threat).
P1 = must be done today (contains the damage).
P2 = must be done this week (hardens the environment).
P3 = should be done within 30 days (long-term improvement).

Be specific and actionable. Reference actual hosts, ports, and CVEs from the data.
Do not include markdown formatting or backticks — return raw JSON only."""


class AIRecommendationEngine:
    """Calls Claude API for AI-powered incident analysis and remediation plans."""

    def __init__(self):
        self.api_key = settings.ANTHROPIC_API_KEY
        self.model = "claude-sonnet-4-6"

    async def analyze_incident(
        self,
        title: str,
        description: str,
        timeline: List[Dict],
        severity: str,
    ) -> Dict:
        """Generate root cause analysis and remediation plan."""
        if not self.api_key:
            logger.warning("ANTHROPIC_API_KEY not set — returning fallback analysis")
            return self._fallback_analysis(title, timeline, severity)

        try:
            return await self._call_claude(title, description, timeline, severity)
        except Exception as e:
            logger.error(f"Claude API call failed: {e}")
            return self._fallback_analysis(title, timeline, severity)

    async def _call_claude(
        self,
        title: str,
        description: str,
        timeline: List[Dict],
        severity: str,
    ) -> Dict:
        """Make async call to Anthropic API."""
        import anthropic

        client = anthropic.AsyncAnthropic(api_key=self.api_key)

        timeline_text = "\n".join(
            f"[{e.get('time', 'N/A')}] [{e.get('severity', 'N/A').upper()}] "
            f"Phase: {e.get('phase', 'Unknown')} | {e.get('event', '')}\n"
            f"  Details: {e.get('details', 'N/A')}"
            for e in timeline
        )

        user_message = f"""Analyze this security incident:

INCIDENT: {title}
SEVERITY: {severity}
DESCRIPTION: {description}

ATTACK TIMELINE:
{timeline_text}

Produce your root cause analysis and remediation plan as JSON."""

        response = await client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )

        # Parse response
        text = response.content[0].text.strip()
        # Strip markdown code fences if present
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

        try:
            result = json.loads(text)
        except json.JSONDecodeError:
            logger.error(f"Failed to parse Claude response as JSON: {text[:200]}")
            return self._fallback_analysis(title, timeline, severity)

        # Validate structure
        if "root_cause" not in result or "remediations" not in result:
            logger.warning("Claude response missing required fields — using fallback")
            return self._fallback_analysis(title, timeline, severity)

        return result

    def _fallback_analysis(self, title: str, timeline: List[Dict], severity: str) -> Dict:
        """Deterministic fallback when Claude API is unavailable."""
        # Extract IOCs from timeline
        iocs = []
        hosts = set()
        for event in timeline:
            details = event.get("details", "")
            if details:
                import re
                ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", details)
                iocs.extend(ips)
            source = event.get("source_host")
            dest = event.get("dest_host")
            if source:
                hosts.add(source)
            if dest:
                hosts.add(dest)

        iocs = list(set(iocs))

        # Build remediation plan based on phases present
        phases = set(e.get("phase", "") for e in timeline if e.get("phase"))
        remediations = []

        if "Initial Access" in phases:
            remediations.append({
                "priority": "P0",
                "action": "Close the initial access vector — patch exposed services and enforce authentication",
                "impact": "Eliminates the attack entry point",
                "effort": "30 min",
            })

        if "Persistence" in phases:
            remediations.append({
                "priority": "P0",
                "action": "Remove all persistence mechanisms — check crontabs, SSH keys, startup scripts, and scheduled tasks",
                "impact": "Prevents attacker from regaining access",
                "effort": "1 hr",
            })

        if "Privilege Escalation" in phases:
            remediations.append({
                "priority": "P0",
                "action": "Rotate all credentials on compromised hosts and revoke elevated sessions",
                "impact": "Invalidates stolen credentials",
                "effort": "30 min",
            })

        if "Command and Control" in phases or "Command & Control" in phases:
            remediations.append({
                "priority": "P1",
                "action": "Block C2 domains/IPs at network edge and enable DNS monitoring",
                "impact": "Cuts attacker communication channel",
                "effort": "1 hr",
            })

        if "Lateral Movement" in phases:
            remediations.append({
                "priority": "P1",
                "action": "Implement network segmentation between tiers and restrict lateral protocols (SMB, SSH, RDP)",
                "impact": "Contains damage to initial foothold",
                "effort": "2-4 hr",
            })

        if "Defense Evasion" in phases:
            remediations.append({
                "priority": "P1",
                "action": "Audit and revert unauthorized firewall, AV exclusion, and log deletion changes",
                "impact": "Restores detection capabilities",
                "effort": "1 hr",
            })

        # Always include hardening steps
        remediations.extend([
            {
                "priority": "P2",
                "action": "Deploy host-based IDS and enable comprehensive audit logging on all affected systems",
                "impact": "Detects future intrusion attempts",
                "effort": "2-4 hr",
            },
            {
                "priority": "P3",
                "action": "Conduct a full security review of all exposed services and implement zero-trust network policies",
                "impact": "Reduces overall attack surface",
                "effort": "1-2 weeks",
            },
        ])

        # Build root cause from first critical event
        critical_events = [e for e in timeline if e.get("severity") == "critical"]
        root_cause = "Unknown — insufficient data for automated root cause determination"
        if critical_events:
            root_cause = critical_events[0].get("event", root_cause)

        return {
            "root_cause": root_cause,
            "summary": (
                f"This {severity}-severity incident involved {len(timeline)} correlated events "
                f"across {len(hosts)} host(s). The attack progressed through {len(phases)} "
                f"distinct MITRE ATT&CK phases: {', '.join(sorted(phases))}. "
                f"Analysis identified {len(iocs)} indicators of compromise. "
                f"Immediate containment actions are required for {len([r for r in remediations if r['priority'] == 'P0'])} "
                f"P0-priority items."
            ),
            "confidence": 0.65,
            "iocs": iocs,
            "remediations": remediations,
        }
