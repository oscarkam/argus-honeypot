"""
NIST Cybersecurity Framework (CSF) recommendation generator.

Translates observed threat patterns into actionable recommendations organized
by the five CSF Core Functions (Identify, Protect, Detect, Respond, Recover).

Reference: NIST CSF 2.0 (2024). This module implements a subset of Category
outcomes most relevant to internet-facing SMEs deploying honeypot-derived
threat intelligence.

Usage:
    generator = NistCsfGenerator()
    recs = generator.generate(
        tactic_frequency={"Discovery": 12, "Credential Access": 8, ...},
        kill_chain_distribution={"Reconnaissance": 900, "Delivery": 5, ...},
        top_ports=[22, 445, 3306],
        max_recommendations=5,
    )
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class Recommendation:
    """A single NIST CSF-aligned recommendation for the report."""
    function: str            # Identify | Protect | Detect | Respond | Recover
    category: str            # e.g., "PR.AC-1"
    title: str               # short action title
    detail: str              # concrete guidance for an SME
    priority: str            # High | Medium | Low
    evidence: str            # what in the data triggered this


# The 5 NIST CSF Core Functions (2.0), ordered for report rendering
CSF_FUNCTIONS = ["Identify", "Protect", "Detect", "Respond", "Recover"]


# ---------------------------------------------------------------------------
# Reference URL helpers — used by templates to hyperlink framework IDs
# ---------------------------------------------------------------------------
def csf_link(category: str) -> str:
    """Return a hyperlink to the CSF subcategory reference.

    Example: 'PR.AC-1' → https://csf.tools/reference/nist-cybersecurity-framework/v1-1/pr/pr-ac/pr-ac-1/
    """
    if not category or "." not in category:
        return f"https://www.nist.gov/cyberframework"
    # PR.AC-1 → pr/pr-ac/pr-ac-1
    parts = category.lower().split(".")
    if len(parts) < 2:
        return "https://www.nist.gov/cyberframework"
    function_prefix = parts[0]          # 'pr'
    remainder = parts[1]                # 'ac-1'
    category_slug = remainder.split("-")[0]   # 'ac'
    return (
        f"https://csf.tools/reference/nist-cybersecurity-framework/v1-1/"
        f"{function_prefix}/{function_prefix}-{category_slug}/"
        f"{function_prefix}-{remainder}/"
    )


class NistCsfGenerator:
    """Generates NIST CSF-aligned recommendations from observed threat patterns."""

    def generate(
        self,
        tactic_frequency: Dict[str, int],
        kill_chain_distribution: Dict[str, int],
        top_ports: List[int],
        malware_hashes_captured: int = 0,
        unique_source_ips: int = 0,
        max_recommendations: Optional[int] = None,
        per_function_min: int = 0,
    ) -> List[Recommendation]:
        """Generate a list of recommendations.

        Args:
            tactic_frequency: {tactic_name: count} from MITRE mapper.
            kill_chain_distribution: {stage: count} from Kill Chain classifier.
            top_ports: List of most-targeted ports (int).
            malware_hashes_captured: Count of malicious binaries captured (Dionaea).
            unique_source_ips: Count of unique attacker IPs.
            max_recommendations: If set, truncate to this many (used for brief report).
            per_function_min: If set, ensure at least this many recs per CSF Function
                              (used for detailed report; 1 → 5 total, 2 → 10 total).
        """
        pool: List[Recommendation] = []

        # -------------------- Identify --------------------
        if unique_source_ips > 200:
            pool.append(Recommendation(
                function="Identify",
                category="ID.RA-3",
                title="Document your threat landscape",
                detail=(
                    f"Your honeypot observed {unique_source_ips} unique source IPs. "
                    "For an SME with no international user base, consider whether geographic "
                    "access restrictions on management ports would reduce noise materially."
                ),
                priority="Medium",
                evidence=f"{unique_source_ips} unique source IPs observed",
            ))

        pool.append(Recommendation(
            function="Identify",
            category="ID.AM-1",
            title="Inventory internet-facing assets",
            detail=(
                "Maintain a current list of every server, service and port exposed to the "
                "internet. This dataset is the input to every subsequent protection decision."
            ),
            priority="High",
            evidence="Baseline recommendation for any SME with public infrastructure",
        ))

        # -------------------- Protect --------------------
        if tactic_frequency.get("Credential Access", 0) > 0 or 22 in top_ports:
            pool.append(Recommendation(
                function="Protect",
                category="PR.AC-1",
                title="Enforce strong authentication on remote-access services",
                detail=(
                    "Disable password authentication for SSH; require SSH key pairs. "
                    "Enable MFA on any management interface that supports it. "
                    "Consider rate-limiting failed auth attempts (fail2ban)."
                ),
                priority="High",
                evidence="Credential Access techniques observed / port 22 among top targets",
            ))

        if tactic_frequency.get("Command and Control", 0) > 0:
            pool.append(Recommendation(
                function="Protect",
                category="PR.PT-4",
                title="Restrict outbound network traffic",
                detail=(
                    "Servers should have egress firewall rules by default — only allow "
                    "outbound traffic to explicitly whitelisted destinations. Enable DNS "
                    "filtering (e.g., NextDNS, Cloudflare Zero Trust) to block C2 domain "
                    "resolution."
                ),
                priority="High",
                evidence="Command and Control activity indicators observed",
            ))

        if 22 in top_ports:
            pool.append(Recommendation(
                function="Protect",
                category="PR.AC-4",
                title="Move SSH away from port 22 if operationally feasible",
                detail=(
                    "Automated scanners target port 22 heavily. Moving SSH to a non-standard "
                    "port dramatically reduces noise (though it is security-through-obscurity, "
                    "not real protection). Pair with key-only auth for real hardening."
                ),
                priority="Medium",
                evidence="Port 22 among most-targeted services",
            ))

        # -------------------- Detect --------------------
        if tactic_frequency.get("Discovery", 0) > 0:
            pool.append(Recommendation(
                function="Detect",
                category="DE.CM-4",
                title="Enable command-line auditing on production servers",
                detail=(
                    "Attackers were observed running system-discovery commands "
                    "(uname, cat /proc/cpuinfo, whoami, id). Enable auditd rules on "
                    "production hosts to log the same commands — this gives you real "
                    "detection signal for the same behaviour, not just on the decoy."
                ),
                priority="High",
                evidence=f"{tactic_frequency['Discovery']} Discovery-tactic events observed",
            ))

        if tactic_frequency.get("Defense Evasion", 0) > 0:
            pool.append(Recommendation(
                function="Detect",
                category="DE.CM-1",
                title="Alert on shell-history manipulation and log deletion",
                detail=(
                    "Configure SIEM or auditd to alert when .bash_history is cleared, "
                    "when large numbers of files are deleted from /var/log, or when "
                    "iptables rules are flushed."
                ),
                priority="Medium",
                evidence="Defense Evasion techniques observed in honeypot sessions",
            ))

        pool.append(Recommendation(
            function="Detect",
            category="DE.CM-8",
            title="Subscribe to vulnerability scanning against your own IPs",
            detail=(
                "Use tools like Shodan Monitor or ONYPHE alerts on your ASN/IPs so you "
                "see what attackers see about you. Fixes the 'you don't know what's exposed' "
                "problem for free-tier scans."
            ),
            priority="Low",
            evidence="General SME baseline detection recommendation",
        ))

        # -------------------- Respond --------------------
        if malware_hashes_captured > 0:
            pool.append(Recommendation(
                function="Respond",
                category="RS.MI-1",
                title="Add captured malware hashes to your EDR/AV blocklist",
                detail=(
                    f"{malware_hashes_captured} binary payload(s) were captured by the "
                    "honeypot in this window. Extract their SHA-256 hashes and push them "
                    "to your endpoint protection blocklist — you now have per-day IOCs "
                    "tuned to your actual threat exposure."
                ),
                priority="High",
                evidence=f"{malware_hashes_captured} malware sample(s) captured",
            ))

        pool.append(Recommendation(
            function="Respond",
            category="RS.RP-1",
            title="Document and rehearse an incident response runbook",
            detail=(
                "For an SME without a dedicated SOC, a two-page IR runbook covering: "
                "(1) who to call, (2) which systems to isolate, (3) how to preserve logs "
                "— is disproportionately effective. Test it once per quarter."
            ),
            priority="Medium",
            evidence="Baseline organizational readiness",
        ))

        pool.append(Recommendation(
            function="Respond",
            category="RS.AN-1",
            title="Cross-reference top attacker IPs against threat intelligence feeds",
            detail=(
                "Feed the top-N source IPs into free feeds like AbuseIPDB, GreyNoise "
                "and Spamhaus. Confirmed-bad IPs go straight to the perimeter firewall "
                "block list."
            ),
            priority="Medium",
            evidence="Multiple source IPs observed",
        ))

        # -------------------- Recover --------------------
        pool.append(Recommendation(
            function="Recover",
            category="RC.RP-1",
            title="Verify off-network backups exist and can be restored",
            detail=(
                "Ransomware behaviour was observed in this dataset. The single most "
                "important recovery control is an offline, tested backup — one that can "
                "not be reached from the network being backed up. Test restore quarterly."
            ),
            priority="High",
            evidence="Impact-tactic (encryption/resource hijacking) techniques observed",
        ) if tactic_frequency.get("Impact", 0) > 0 else Recommendation(
            function="Recover",
            category="RC.RP-1",
            title="Verify off-network backups exist and can be restored",
            detail=(
                "Even without ransomware in this window, an offline, tested backup remains "
                "the highest-leverage recovery control for any SME. Test restore quarterly."
            ),
            priority="Medium",
            evidence="Baseline SME recovery control",
        ))

        pool.append(Recommendation(
            function="Recover",
            category="RC.IM-1",
            title="Feed lessons from each week's report into your patching cadence",
            detail=(
                "When this report highlights an exploit trend (e.g., a spike in a "
                "specific CVE probe), your patching priority list gains a new #1 for "
                "the following week. Close the loop between observation and action."
            ),
            priority="Medium",
            evidence="Continuous improvement recommendation",
        ))

        # ------------------------------------------------------------------
        # Apply size constraints
        # ------------------------------------------------------------------
        if per_function_min > 0:
            # Ensure at least per_function_min per CSF function (used for detailed report)
            result: List[Recommendation] = []
            for func in CSF_FUNCTIONS:
                subset = [r for r in pool if r.function == func]
                # Sort by priority so highest-priority in each function comes first
                priority_order = {"High": 0, "Medium": 1, "Low": 2}
                subset.sort(key=lambda r: priority_order.get(r.priority, 3))
                result.extend(subset[: max(per_function_min, 2)])  # up to 2 per function
            return result

        if max_recommendations:
            # Highest-priority first, truncate (used for brief report)
            priority_order = {"High": 0, "Medium": 1, "Low": 2}
            pool.sort(key=lambda r: priority_order.get(r.priority, 3))
            return pool[:max_recommendations]

        return pool