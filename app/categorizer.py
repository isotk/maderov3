from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class CategoryRule:
    name: str
    keywords: List[str]
    word_boundary: bool = False


CATEGORY_RULES = [
    CategoryRule("Ransomware", ["ransomware", "extortion", "decryptor", "lockbit", "conti"]),
    CategoryRule("Vulnerabilidades", ["cve-", "vulnerability", "zero-day", "zero day", "patch tuesday", "exploit"]),
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
            "dns enumeration",
            "subdomain enumeration",
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
    CategoryRule(
        "Dark Web",
        [
            "dark web",
            "darkweb",
            ".onion",
            "onion site",
            "tor network",
            "leak site",
            "ransomware leak",
            "initial access broker",
            "stolen credentials",
            "credential dump",
            "underground forum",
        ],
    ),
    CategoryRule("Cloud Security", ["cloud security", "aws security", "azure security", "gcp security", "kubernetes security", "container security"]),
    CategoryRule(
        "IA",
        [
            "artificial intelligence",
            "generative ai",
            "genai",
            "large language model",
            "llm",
            "machine learning",
            "deep learning",
            "prompt injection",
            "model poisoning",
            "ai security",
            "ai safety",
            "ai alignment",
            "ai governance",
            "ai regulation",
            "openai",
            "deepmind",
            "anthropic",
            "chatgpt",
            "claude",
            "gemini",
            "copilot",
            "llama",
            "mistral",
            "hugging face",
        ],
        word_boundary=True,
    ),
    CategoryRule("Threat Intelligence", ["apt", "ioc", "threat actor", "campaign", "attribution"]),
    CategoryRule(
        "Seguranca Defensiva",
        [
            "soc",
            "siem",
            "edr",
            "xdr",
            "detection engineering",
            "incident response",
            "hardening",
            "blue team",
            "threat hunting",
            "sigma rule",
            "yara",
            "mitre att&ck",
        ],
    ),
    CategoryRule("Governança e Compliance", ["compliance", "gdpr", "lgpd", "regulation", "policy"]),
]


def _word_boundary_match(keyword: str, text: str) -> bool:
    pattern = r'\b' + re.escape(keyword) + r'\b'
    return bool(re.search(pattern, text, re.IGNORECASE))


def categorize_text(text: str) -> str:
    normalized = text.lower()
    scores: Dict[str, int] = {}

    for rule in CATEGORY_RULES:
        count = 0
        for keyword in rule.keywords:
            if rule.word_boundary:
                if _word_boundary_match(keyword, normalized):
                    count += 1
            else:
                if keyword in normalized:
                    count += 1
        if count:
            scores[rule.name] = count

    if not scores:
        return "Geral"

    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))[0][0]
