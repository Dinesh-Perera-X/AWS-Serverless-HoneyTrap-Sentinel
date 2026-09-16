from typing import Dict, Any, List

class AdversaryProfiler:
    """
    Enriches canary intrusion alerts with attacker heuristics, 
    tooling analysis (User-Agent), simulated IP/Geo context, and MITRE ATT&CK mapping.
    """

    KNOWN_TOOLING_SIGNATURES = {
        "kali": {"tool": "Kali Linux Attacker Suite", "threat_level": "CRITICAL"},
        "botocore": {"tool": "Automated Boto3 Script / Custom Scanner", "threat_level": "HIGH"},
        "aws-cli": {"tool": "Direct AWS CLI Enumeration", "threat_level": "HIGH"},
        "pacu": {"tool": "Pacu AWS Exploitation Framework", "threat_level": "CRITICAL"},
        "cloudsplaining": {"tool": "Cloud Security Assessment Scanner", "threat_level": "MEDIUM"}
    }

    @classmethod
    def _inspect_user_agent(cls, user_agent: str) -> Dict[str, str]:
        ua_lower = user_agent.lower()
        for signature, details in cls.KNOWN_TOOLING_SIGNATURES.items():
            if signature in ua_lower:
                return details
        return {"tool": "Custom HTTP Client / Unknown SDK", "threat_level": "MEDIUM"}

    @classmethod
    def _resolve_simulated_geo(cls, ip: str) -> Dict[str, str]:
        if ip.startswith("198.51.100"):
            return {"country": "Netherlands (Proxy / Tor Exit)", "asn": "AS24940 Hetzner Online", "org": "Cloud Hosting"}
        elif ip.startswith("203.0.113"):
            return {"country": "Singapore (Suspicious VPS)", "asn": "AS13335 Cloudflare", "org": "Data Center Net"}
        return {"country": "Unknown Origin", "asn": "AS-UNASSIGNED", "org": "External Network"}

    @classmethod
    def profile_incident(cls, alert: Dict[str, Any]) -> Dict[str, Any]:
        user_agent = alert.get("user_agent", "")
        source_ip = alert.get("source_ip", "")
        trigger_type = alert.get("trigger_type", "")
        action = alert.get("event_name", "")

        tooling = cls._inspect_user_agent(user_agent)
        geo = cls._resolve_simulated_geo(source_ip)

        if trigger_type == "HONEY_KEY_INVOCATION":
            if action in ("GetCallerIdentity", "ListUsers", "DescribeInstances"):
                mitre_id = "T1087.004"
                technique = "Account Discovery: Cloud Account"
                tactic = "Discovery"
            else:
                mitre_id = "T1078.004"
                technique = "Valid Accounts: Cloud Accounts"
                tactic = "Defense Evasion / Initial Access"
        else:
            mitre_id = "T1530"
            technique = "Data from Cloud Storage Object"
            tactic = "Collection / Exfiltration"

        profiled = dict(alert)
        profiled.update({
            "adversary_tooling": tooling["tool"],
            "geo_country": geo["country"],
            "geo_asn": geo["asn"],
            "mitre_id": mitre_id,
            "mitre_technique": technique,
            "mitre_tactic": tactic,
            "confidence": "HIGH (100% Canary Confidence - Zero False Positives)"
        })
        return profiled
