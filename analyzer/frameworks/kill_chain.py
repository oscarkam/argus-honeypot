"""
Lockheed Martin Cyber Kill Chain classifier.

Classifies honeypot sessions into one of the seven kill chain stages based on
observed activity indicators. Purely rules-based — no ML needed at this scope.

Stages:
    1. Reconnaissance          — passive/active info gathering
    2. Weaponization           — (usually external, rarely seen from honeypot vantage)
    3. Delivery                — successful auth or payload delivery
    4. Exploitation            — code execution after entry
    5. Installation            — persistence mechanisms / dropped files
    6. Command and Control     — outbound beaconing / remote shell
    7. Actions on Objectives   — data staging, encryption, lateral movement

Usage:
    classifier = KillChainClassifier()
    stage = classifier.classify_session({
        "auth_success": True,
        "commands_executed": 5,
        "file_downloads": 1,
        ...
    })
"""
from __future__ import annotations

from typing import Dict, List


# Canonical stage ordering for chart rendering
KILL_CHAIN_STAGES = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command and Control",
    "Actions on Objectives",
]


class KillChainClassifier:
    """Rules-based Cyber Kill Chain stage classifier for honeypot sessions."""

    def classify_session(self, session: Dict) -> str:
        """Classify a single session by its observed indicators.

        Session dict is expected to have keys:
            - auth_success (bool)
            - failed_auth_attempts (int)
            - commands_executed (int)
            - file_downloads (int)
            - persistence_actions (int)     (e.g. crontab, authorized_keys writes)
            - c2_indicators (int)           (long-running, periodic beacons)
            - data_staging (int)            (tar/gzip on sensitive dirs)
            - encryption_actions (int)      (openssl enc, ransomware behaviour)
            - lateral_movement (int)        (ssh/psexec attempts to new hosts)
        """
        # Highest stage takes precedence (attacker got farthest)
        if session.get("encryption_actions", 0) > 0 or session.get("data_staging", 0) > 0 or session.get("lateral_movement", 0) > 0:
            return "Actions on Objectives"
        if session.get("c2_indicators", 0) > 0:
            return "Command and Control"
        if session.get("persistence_actions", 0) > 0:
            return "Installation"
        if session.get("commands_executed", 0) > 0 and session.get("auth_success"):
            return "Exploitation"
        if session.get("auth_success"):
            return "Delivery"
        # No successful auth — reconnaissance/probing only
        return "Reconnaissance"

    def classify_batch(self, sessions: List[Dict]) -> Dict[str, int]:
        """Classify a list of sessions and return {stage: count} distribution."""
        counts = {stage: 0 for stage in KILL_CHAIN_STAGES}
        for session in sessions:
            stage = self.classify_session(session)
            counts[stage] = counts.get(stage, 0) + 1
        return counts

    def stage_narrative(self, distribution: Dict[str, int]) -> str:
        """Generate a one-sentence interpretation of the distribution.

        Used as a hint for the LLM prompt — helps the model frame the observation.
        """
        total = sum(distribution.values())
        if total == 0:
            return "No sessions to classify in this window."

        recon_pct = 100 * distribution.get("Reconnaissance", 0) / total
        if recon_pct > 80:
            return f"{recon_pct:.0f}% of activity is Reconnaissance-only — attackers are probing but not breaching."
        if distribution.get("Actions on Objectives", 0) > 0:
            return f"{distribution['Actions on Objectives']} session(s) reached Actions-on-Objectives stage — active engagement observed."
        if distribution.get("Command and Control", 0) > 0:
            return f"{distribution['Command and Control']} session(s) reached C2 stage — post-compromise beacon activity."
        if distribution.get("Installation", 0) > 0:
            return f"Attackers achieved Installation stage in {distribution['Installation']} session(s) — persistence attempts logged."
        if distribution.get("Exploitation", 0) > 0:
            return f"{distribution['Exploitation']} session(s) reached Exploitation — attackers ran commands after successful auth."
        return "Activity mostly clustered in early Kill Chain stages (Recon/Delivery)."