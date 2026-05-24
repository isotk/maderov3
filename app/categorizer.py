from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class CategoryRule:
    name: str
    keywords: List[str]


CATEGORY_RULES = [
    CategoryRule("Ransomware", ["ransomware", "extortion", "decryptor", "lockbit", "conti"]),
    CategoryRule("Vulnerabilidades", ["cve-", "vulnerability", "zero-day", "patch", "exploit"]),
    CategoryRule("Malware", ["malware", "trojan", "spyware", "worm", "botnet", "stealer"]),
    CategoryRule(
        "OSINT",
        [
            "osint",
            "open source intelligence",
            "reconnaissance",
            "recon",
            "google dork",
            "dork",
            "shodan",
            "censys",
            "whois",
            "dns",
            "subdomain",
            "passive dns",
            "geolocation",
            "metadata",
            "exif",
            "username enumeration",
            "email enumeration",
            "breach data",
            "digital footprint",
        ],
    ),
    CategoryRule("Phishing", ["phishing", "smishing", "vishing", "email scam", "credential theft"]),
    CategoryRule("Data Breach", ["data breach", "data leak", "leaked", "exposed data", "compromised"]),
    CategoryRule("Cloud Security", ["cloud", "aws", "azure", "gcp", "kubernetes", "container"]),
    CategoryRule("Threat Intelligence", ["apt", "ioc", "threat actor", "campaign", "attribution"]),
    CategoryRule("Governança e Compliance", ["compliance", "gdpr", "lgpd", "regulation", "policy"]),
]


def categorize_text(text: str) -> str:
    normalized = text.lower()
    scores: Dict[str, int] = {}

    for rule in CATEGORY_RULES:
        count = sum(1 for keyword in rule.keywords if keyword in normalized)
        if count:
            scores[rule.name] = count

    if not scores:
        return "Geral"

    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))[0][0]
