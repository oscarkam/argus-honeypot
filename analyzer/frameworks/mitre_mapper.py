"""
MITRE ATT&CK mapper — classifies raw honeypot observations into ATT&CK techniques.

Approach:
    - Regex-based pattern matching against a curated knowledge base
    - Aggregate technique occurrences into tactic frequencies
    - Provide data structures for downstream chart/report generation

Usage:
    mapper = MitreMapper()
    techniques = mapper.map_commands(["wget http://x.sh", "chmod +x x.sh"])
    frequencies = mapper.tactic_frequency(techniques)
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import List, Dict, Any


# ---------------------------------------------------------------------------
# Reference URL helper — used by templates to hyperlink technique IDs
# ---------------------------------------------------------------------------
def mitre_link(technique_id: str) -> str:
    """Return the canonical ATT&CK reference URL for a technique ID.

    Examples:
        'T1098'      → https://attack.mitre.org/techniques/T1098/
        'T1098.004'  → https://attack.mitre.org/techniques/T1098/004/
    """
    if not technique_id:
        return "https://attack.mitre.org"
    tid = technique_id.strip().upper()
    if "." in tid:
        parent, sub = tid.split(".", 1)
        return f"https://attack.mitre.org/techniques/{parent}/{sub}/"
    return f"https://attack.mitre.org/techniques/{tid}/"


def mitre_tactic_link(tactic_id: str) -> str:
    """Return the reference URL for a tactic ID (e.g. 'TA0001')."""
    if not tactic_id:
        return "https://attack.mitre.org"
    return f"https://attack.mitre.org/tactics/{tactic_id.strip().upper()}/"


class MitreMapper:
    """Maps raw honeypot observations to MITRE ATT&CK techniques and tactics."""

    def __init__(self, knowledge_path: str | None = None) -> None:
        if knowledge_path is None:
            knowledge_path = str(Path(__file__).parent / "attack_knowledge.json")
        with open(knowledge_path, "r") as f:
            self.kb: Dict[str, Any] = json.load(f)
        # Precompile regex patterns for performance
        self._compiled_cmd = [
            (re.compile(item["pattern"], re.IGNORECASE), item)
            for item in self.kb["command_mappings"]
        ]

    # ------------------------------------------------------------------
    # Command-based mapping
    # ------------------------------------------------------------------
    def map_commands(self, commands: List[str]) -> List[Dict[str, str]]:
        """Return the list of ATT&CK techniques observed across a set of commands.

        A single command may match multiple patterns (e.g. `wget http://x` also
        matches Ingress Tool Transfer). We keep all matches so tactic
        frequencies reflect true behaviour density.
        """
        observed: List[Dict[str, str]] = []
        for cmd in commands:
            for pattern, meta in self._compiled_cmd:
                if pattern.search(cmd):
                    observed.append(
                        {
                            "command": cmd,
                            "technique_id": meta["technique_id"],
                            "technique_name": meta["technique_name"],
                            "tactic_id": meta["tactic_id"],
                            "tactic_name": meta["tactic_name"],
                        }
                    )
        return observed

    # ------------------------------------------------------------------
    # Auth / network pattern mapping (for aggregated behaviour categories)
    # ------------------------------------------------------------------
    def map_auth_pattern(self, pattern_key: str) -> Dict[str, str] | None:
        """Map a known auth-behaviour pattern (e.g. 'failed_login_burst') to a technique."""
        for item in self.kb["auth_patterns"]:
            if item["pattern"] == pattern_key:
                return {
                    "technique_id": item["technique_id"],
                    "technique_name": item["technique_name"],
                    "tactic_id": item["tactic_id"],
                    "tactic_name": item["tactic_name"],
                }
        return None

    def map_network_pattern(self, pattern_key: str) -> Dict[str, str] | None:
        """Map a network-behaviour pattern (e.g. 'port_scan') to a technique."""
        for item in self.kb["network_patterns"]:
            if item["pattern"] == pattern_key:
                return {
                    "technique_id": item["technique_id"],
                    "technique_name": item["technique_name"],
                    "tactic_id": item["tactic_id"],
                    "tactic_name": item["tactic_name"],
                }
        return None

    # ------------------------------------------------------------------
    # Aggregation helpers for reporting
    # ------------------------------------------------------------------
    def tactic_frequency(self, observations: List[Dict[str, str]]) -> Dict[str, int]:
        """Count occurrences of each tactic across observations. Returns {tactic_name: count}."""
        counter = Counter(obs["tactic_name"] for obs in observations)
        return dict(counter)

    def technique_frequency(self, observations: List[Dict[str, str]]) -> Dict[str, Dict[str, Any]]:
        """Count occurrences of each unique technique.

        Returns {technique_id: {name, tactic, count}} for stable heatmap rendering.
        """
        result: Dict[str, Dict[str, Any]] = {}
        for obs in observations:
            tid = obs["technique_id"]
            if tid not in result:
                result[tid] = {
                    "name": obs["technique_name"],
                    "tactic": obs["tactic_name"],
                    "count": 0,
                }
            result[tid]["count"] += 1
        return result

    def all_tactics_ordered(self) -> List[Dict[str, str]]:
        """Return the canonical MITRE ATT&CK tactic ordering (Recon → Impact)."""
        return list(self.kb["tactics_order"])

    def heatmap_matrix(self, observations: List[Dict[str, str]]) -> Dict[str, Any]:
        """Prepare Navigator-style heatmap data for matplotlib rendering.

        Returns {
            'tactics': [tactic_names in canonical order],
            'techniques_per_tactic': {tactic_name: [(technique_id, technique_name, count), ...]},
            'max_count': int,
        }
        """
        tactics_ordered = [t["name"] for t in self.all_tactics_ordered()]
        by_tactic: Dict[str, List] = {t: [] for t in tactics_ordered}

        tech_freq = self.technique_frequency(observations)
        for tid, meta in tech_freq.items():
            tactic = meta["tactic"]
            if tactic in by_tactic:
                by_tactic[tactic].append((tid, meta["name"], meta["count"]))

        max_count = max((meta["count"] for meta in tech_freq.values()), default=1)

        return {
            "tactics": tactics_ordered,
            "techniques_per_tactic": by_tactic,
            "max_count": max_count,
        }