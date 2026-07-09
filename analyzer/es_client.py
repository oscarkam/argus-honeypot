"""
Elasticsearch client for T-Pot data queries.

Queries T-Pot's Elasticsearch (accessed via SSH tunnel — laptop's localhost:9200
forwards to T-Pot host's localhost:64298, where the real T-Pot ES container binds).
Returns the same dict structure as generate_stub_data() so downstream code in
analyzer.py works unchanged.

Field references follow T-Pot 24.04 HIVE schema:
    @timestamp, type, src_ip, dest_port, geoip.country_name, geoip.city_name
    Cowrie: eventid, username, password, input, session
    Dionaea: sha256hash, md5hash, filename
"""
from __future__ import annotations

from typing import Dict, Any, List
from elasticsearch import Elasticsearch


# Common port → service name mapping (T-Pot's honeypot ports)
PORT_TO_SERVICE = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-Auth", 631: "IPP", 993: "IMAPS", 995: "POP3S",
    1025: "Kamstrup", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    2575: "MedPot", 3000: "HTTP-Alt", 3306: "MySQL", 3389: "RDP",
    5000: "UPnP", 5060: "SIP", 5432: "PostgreSQL", 5555: "ADB",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9100: "Print", 9200: "Elasticsearch", 11112: "DICOM", 27017: "MongoDB",
    50100: "Meter",
}


def port_service(port: int) -> str:
    return PORT_TO_SERVICE.get(port, f"tcp/{port}")


class TpotEsClient:
    """Query wrapper around T-Pot's Elasticsearch."""

    def __init__(self, hosts: List[str], username: str = "", password: str = "",
                 verify_certs: bool = False, timeout: int = 30) -> None:
        auth = (username, password) if (username and password) else None
        self.es = Elasticsearch(
            hosts=hosts,
            basic_auth=auth,
            verify_certs=verify_certs,
            request_timeout=timeout,
        )

    def ping(self) -> bool:
        return self.es.ping()

    # =================================================================
    # Main entry — mirrors generate_stub_data() structure
    # =================================================================
    def query_window(self, hours: int = 24) -> Dict[str, Any]:
        """Execute all queries for the given time window."""
        tf = {"range": {"@timestamp": {"gte": f"now-{hours}h"}}}
        total = self._total_attacks(tf)

        return {
            "total_attacks":              total,
            "unique_source_ips":          self._unique_source_ips(tf),
            "malware_captured":           self._malware_count(tf),
            "top_source_countries":       self._top_countries(tf, total),
            "top_attacked_ports":         self._top_ports(tf, total),
            "top_credentials_attempted":  self._top_credentials(tf),
            "top_source_ips":             self._top_source_ips(tf),
            "malware_hashes":             self._malware_hashes(tf),
            "hourly_trend":               self._hourly_trend(tf, hours),
            "notable_sessions":           self._notable_sessions(tf),
            "session_details":            self._session_details(tf, total),
            "all_commands":               self._all_commands(tf),
        }

    # =================================================================
    # Individual queries
    # =================================================================
    def _total_attacks(self, tf: Dict) -> int:
        r = self.es.count(index="logstash-*", query=tf)
        return r["count"]

    def _unique_source_ips(self, tf: Dict) -> int:
        r = self.es.search(
            index="logstash-*", size=0, query=tf,
            aggs={"u": {"cardinality": {"field": "src_ip.keyword"}}},
        )
        return r["aggregations"]["u"]["value"]

    def _malware_count(self, tf: Dict) -> int:
        r = self.es.count(
            index="logstash-*",
            query={"bool": {"must": [tf, {"exists": {"field": "sha256hash.keyword"}}]}},
        )
        return r["count"]

    def _top_countries(self, tf: Dict, total: int) -> List[Dict]:
        r = self.es.search(
            index="logstash-*", size=0, query=tf,
            aggs={"c": {"terms": {"field": "geoip.country_name.keyword", "size": 10}}},
        )
        buckets = r["aggregations"]["c"]["buckets"]
        return [
            {"country": b["key"], "count": b["doc_count"],
             "percentage": round(100 * b["doc_count"] / max(total, 1), 1)}
            for b in buckets
        ]

    def _top_ports(self, tf: Dict, total: int) -> List[Dict]:
        r = self.es.search(
            index="logstash-*", size=0, query=tf,
            aggs={"p": {"terms": {"field": "dest_port", "size": 10}}},
        )
        buckets = r["aggregations"]["p"]["buckets"]
        return [
            {"port": b["key"], "service": port_service(b["key"]),
             "count": b["doc_count"],
             "percentage": round(100 * b["doc_count"] / max(total, 1), 1)}
            for b in buckets
        ]

    def _top_credentials(self, tf: Dict) -> List[Dict]:
        r = self.es.search(
            index="logstash-*", size=0,
            query={"bool": {"must": [tf, {"exists": {"field": "username.keyword"}}]}},
            aggs={
                "creds": {
                    "multi_terms": {
                        "terms": [
                            {"field": "username.keyword"},
                            {"field": "password.keyword"},
                        ],
                        "size": 10,
                    }
                }
            },
        )
        buckets = r["aggregations"]["creds"]["buckets"]
        return [
            {"username": b["key"][0], "password": b["key"][1], "count": b["doc_count"]}
            for b in buckets
        ]

    def _top_source_ips(self, tf: Dict) -> List[Dict]:
        r = self.es.search(
            index="logstash-*", size=0, query=tf,
            aggs={
                "ips": {
                    "terms": {"field": "src_ip.keyword", "size": 10},
                    "aggs": {"country": {"terms": {"field": "geoip.country_name.keyword", "size": 1}}},
                }
            },
        )
        results = []
        for b in r["aggregations"]["ips"]["buckets"]:
            country_buckets = b["country"]["buckets"]
            country = country_buckets[0]["key"] if country_buckets else "Unknown"
            results.append({"ip": b["key"], "count": b["doc_count"], "country": country})
        return results

    def _malware_hashes(self, tf: Dict) -> List[Dict]:
        r = self.es.search(
            index="logstash-*", size=20,
            query={"bool": {"must": [tf, {"exists": {"field": "sha256hash.keyword"}}]}},
            source_includes=["sha256hash", "filename", "type"],
        )
        results = []
        for h in r["hits"]["hits"]:
            s = h["_source"]
            results.append({
                "sha256":   s.get("sha256hash", ""),
                "filename": s.get("filename", "unknown"),
                "sensor":   s.get("type", "unknown").capitalize(),
            })
        # De-dupe on sha256
        seen = set()
        unique = []
        for m in results:
            if m["sha256"] and m["sha256"] not in seen:
                seen.add(m["sha256"])
                unique.append(m)
        return unique

    def _hourly_trend(self, tf: Dict, hours: int) -> List[int]:
        r = self.es.search(
            index="logstash-*", size=0, query=tf,
            aggs={"h": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h"}}},
        )
        counts = [b["doc_count"] for b in r["aggregations"]["h"]["buckets"]]
        # Pad or truncate to expected hours count
        if len(counts) < hours:
            counts = [0] * (hours - len(counts)) + counts
        return counts[-hours:]

    def _notable_sessions(self, tf: Dict) -> List[str]:
        """Return narrative strings for the 5 most active Cowrie sessions."""
        r = self.es.search(
            index="logstash-*", size=0,
            query={"bool": {"must": [tf, {"term": {"eventid.keyword": "cowrie.command.input"}}]}},
            aggs={"s": {"terms": {"field": "session.keyword", "size": 5}}},
        )
        session_ids = [b["key"] for b in r["aggregations"]["s"]["buckets"]]
        narratives = []
        for sid in session_ids:
            events = self.es.search(
                index="logstash-*", size=25,
                query={"term": {"session.keyword": sid}},
                source_includes=["input", "src_ip", "geoip.country_name", "eventid"],
                sort=[{"@timestamp": "asc"}],
            )
            docs = [h["_source"] for h in events["hits"]["hits"]]
            if not docs:
                continue
            src = docs[0].get("src_ip", "?")
            country = docs[0].get("geoip", {}).get("country_name", "Unknown")
            cmds = [d["input"] for d in docs if d.get("input")]
            cmd_summary = "; ".join(cmds[:5]) + ("..." if len(cmds) > 5 else "")
            narratives.append(
                f"Session {sid[:12]}... from {src} ({country}) executed "
                f"{len(cmds)} commands: {cmd_summary}"
            )
        return narratives

    def _session_details(self, tf: Dict, total: int) -> List[Dict]:
        """Approximate per-session activity for KillChainClassifier."""
        r = self.es.search(
            index="logstash-*", size=0,
            query={"bool": {"must": [tf, {"exists": {"field": "session.keyword"}}]}},
            aggs={
                "by_sess": {
                    "terms": {"field": "session.keyword", "size": 200},
                    "aggs": {
                        "cmd":  {"filter": {"term": {"eventid.keyword": "cowrie.command.input"}}},
                        "ok":   {"filter": {"term": {"eventid.keyword": "cowrie.login.success"}}},
                        "fail": {"filter": {"term": {"eventid.keyword": "cowrie.login.failed"}}},
                        "dl":   {"filter": {"term": {"eventid.keyword": "cowrie.session.file_download"}}},
                    },
                }
            },
        )
        sessions = []
        for b in r["aggregations"]["by_sess"]["buckets"]:
            sessions.append({
                "auth_success":         b["ok"]["doc_count"] > 0,
                "failed_auth_attempts": b["fail"]["doc_count"],
                "commands_executed":    b["cmd"]["doc_count"],
                "file_downloads":       b["dl"]["doc_count"],
                "persistence_actions":  0,
                "c2_indicators":        0,
                "encryption_actions":   0,
                "data_staging":         0,
                "lateral_movement":     0,
            })
        # Fill remaining with recon-only sessions (approximation)
        recon_needed = max(0, total - len(sessions))
        for _ in range(min(recon_needed, 2000)):
            sessions.append({
                "auth_success": False,
                "failed_auth_attempts": 1,
                "commands_executed": 0,
                "file_downloads": 0,
                "persistence_actions": 0,
                "c2_indicators": 0,
                "encryption_actions": 0,
                "data_staging": 0,
                "lateral_movement": 0,
            })
        return sessions

    def _all_commands(self, tf: Dict) -> List[str]:
        """Get all commands executed in the window (up to 500) for MITRE mapping."""
        r = self.es.search(
            index="logstash-*",
            size=500,
            query={"bool": {"must": [tf, {"term": {"eventid.keyword": "cowrie.command.input"}}]}},
        )
        hits = r["hits"]["hits"]
        commands = []
        for h in hits:
            src = h.get("_source", {})
            cmd = src.get("input")
            if cmd:
                commands.append(cmd)
        return commands