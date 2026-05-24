from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class SourceConfig:
    id: str
    name: str
    site_url: str
    feed_url: Optional[str]
    feed_type: str = "rss"


SOURCE_CLASSIFICATION: Dict[str, Dict[str, object]] = {
    "cisa-advisories": {"confidence": "alta", "relevance": "alta", "profiles": ["strict", "balanced", "wide"], "tags": ["official", "advisory"]},
    "cisa-kev": {"confidence": "alta", "relevance": "alta", "profiles": ["strict", "balanced", "wide"], "tags": ["official", "vuln"]},
    "cve-org": {"confidence": "alta", "relevance": "alta", "profiles": ["strict", "balanced", "wide"], "tags": ["official", "vuln"]},
    "msrc": {"confidence": "alta", "relevance": "alta", "profiles": ["strict", "balanced", "wide"], "tags": ["vendor", "microsoft"]},
    "msrc-update-guide": {"confidence": "alta", "relevance": "alta", "profiles": ["strict", "balanced", "wide"], "tags": ["vendor", "microsoft", "vuln"]},
    "google-threat-intel": {"confidence": "alta", "relevance": "alta", "profiles": ["strict", "balanced", "wide"], "tags": ["research", "threat-intel"]},
    "unit42": {"confidence": "alta", "relevance": "alta", "profiles": ["strict", "balanced", "wide"], "tags": ["research", "threat-intel"]},
    "talos": {"confidence": "alta", "relevance": "alta", "profiles": ["strict", "balanced", "wide"], "tags": ["research", "threat-intel"]},
    "crowdstrike-blog": {"confidence": "alta", "relevance": "alta", "profiles": ["strict", "balanced", "wide"], "tags": ["research", "threat-intel"]},
    "sentinelone-labs": {"confidence": "alta", "relevance": "alta", "profiles": ["strict", "balanced", "wide"], "tags": ["research", "threat-intel"]},
    "checkpoint-research": {"confidence": "alta", "relevance": "alta", "profiles": ["strict", "balanced", "wide"], "tags": ["research", "threat-intel"]},
    "project-zero": {"confidence": "alta", "relevance": "alta", "profiles": ["strict", "balanced", "wide"], "tags": ["research", "vuln"]},
    "virustotal-blog": {"confidence": "alta", "relevance": "alta", "profiles": ["strict", "balanced", "wide"], "tags": ["research", "osint"]},
    "maltego-blog": {"confidence": "alta", "relevance": "media", "profiles": ["balanced", "wide"], "tags": ["osint", "tooling"]},
    "spiderfoot-blog": {"confidence": "alta", "relevance": "media", "profiles": ["balanced", "wide"], "tags": ["osint", "tooling"]},
    "x-msftsecresponse": {"confidence": "media", "relevance": "media", "profiles": ["wide"], "tags": ["social", "microsoft"]},
    "x-cisagov": {"confidence": "media", "relevance": "media", "profiles": ["wide"], "tags": ["social", "official"]},
    "x-thehackernews": {"confidence": "media", "relevance": "media", "profiles": ["wide"], "tags": ["social", "media"]},
    "x-crowdstrike": {"confidence": "media", "relevance": "media", "profiles": ["wide"], "tags": ["social", "threat-intel"]},
}


def source_meta(source_id: str) -> Dict[str, object]:
    base = {
        "confidence": "media",
        "relevance": "alta",
        "profiles": ["strict", "balanced", "wide"],
        "tags": [],
    }
    custom = SOURCE_CLASSIFICATION.get(source_id, {})
    return {
        "confidence": custom.get("confidence", base["confidence"]),
        "relevance": custom.get("relevance", base["relevance"]),
        "profiles": custom.get("profiles", base["profiles"]),
        "tags": custom.get("tags", base["tags"]),
    }


SOURCE_REGISTRY: List[SourceConfig] = [
    SourceConfig("bleepingcomputer", "BleepingComputer", "https://www.bleepingcomputer.com", "https://www.bleepingcomputer.com/feed/"),
    SourceConfig("thehackernews", "The Hacker News", "https://thehackernews.com", "https://feeds.feedburner.com/TheHackersNews"),
    SourceConfig("krebsonsecurity", "Krebs on Security", "https://krebsonsecurity.com", "https://krebsonsecurity.com/feed/"),
    SourceConfig("dark-reading", "Dark Reading", "https://www.darkreading.com", "https://www.darkreading.com/rss.xml"),
    SourceConfig("securityweek", "SecurityWeek", "https://www.securityweek.com", "https://www.securityweek.com/feed/"),
    SourceConfig("help-net-security", "Help Net Security", "https://www.helpnetsecurity.com", "https://www.helpnetsecurity.com/feed/"),
    SourceConfig("infosecurity-mag", "Infosecurity Magazine", "https://www.infosecurity-magazine.com", "https://www.infosecurity-magazine.com/rss/news/"),
    SourceConfig("the-record", "The Record", "https://therecord.media", "https://therecord.media/feed"),
    SourceConfig("cyberscoop", "CyberScoop", "https://cyberscoop.com", "https://www.cyberscoop.com/feed/"),
    SourceConfig("security-affairs", "Security Affairs", "https://securityaffairs.com", "https://securityaffairs.com/feed"),

    SourceConfig("cisa-advisories", "CISA Cybersecurity Advisories", "https://www.cisa.gov/news-events/cybersecurity-advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    SourceConfig("cisa-kev", "CISA KEV Catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "json_kev"),
    SourceConfig("cve-org", "CVE.org", "https://www.cve.org", "https://www.cve.org/Newsroom/News/rss"),

    SourceConfig("msrc", "Microsoft Security Response Center", "https://msrc.microsoft.com", "https://api.msrc.microsoft.com/update-guide/rss"),
    SourceConfig("msrc-update-guide", "MSRC Update Guide", "https://msrc.microsoft.com/update-guide", "https://api.msrc.microsoft.com/update-guide/rss"),
    SourceConfig("microsoft-security-blog", "Microsoft Security Blog", "https://www.microsoft.com/en-us/security/blog", "https://www.microsoft.com/en-us/security/blog/feed/"),
    SourceConfig("microsoft-threat-intel-blog", "Microsoft Threat Intelligence Blog", "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence", "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/"),
    SourceConfig("azure-security-blog", "Microsoft Azure Security Blog", "https://azure.microsoft.com/en-us/blog/topics/security", "https://azure.microsoft.com/en-us/blog/topics/security/feed/"),
    SourceConfig("google-threat-intel", "Google Threat Intelligence", "https://cloud.google.com/blog/topics/threat-intelligence", "https://cloud.google.com/blog/topics/threat-intelligence/rss/"),
    SourceConfig("aws-security-blog", "AWS Security Blog", "https://aws.amazon.com/blogs/security", "https://aws.amazon.com/blogs/security/feed/"),
    SourceConfig("gcp-security-blog", "Google Cloud Security Blog", "https://cloud.google.com/blog/products/identity-security", "https://cloud.google.com/blog/products/identity-security/rss/"),

    SourceConfig("unit42", "Unit 42", "https://unit42.paloaltonetworks.com", "https://unit42.paloaltonetworks.com/feed/"),
    SourceConfig("talos", "Cisco Talos", "https://blog.talosintelligence.com", "https://blog.talosintelligence.com/rss/"),
    SourceConfig("fortinet-threat-research", "Fortinet Threat Research", "https://www.fortinet.com/blog/threat-research", "https://www.fortinet.com/blog/threat-research?format=rss"),

    SourceConfig("sans-isc", "SANS ISC", "https://isc.sans.edu", "https://isc.sans.edu/rssfeed_full.xml"),
    SourceConfig("dfir-report", "The DFIR Report", "https://thedfirreport.com", "https://thedfirreport.com/feed/"),
    SourceConfig("portswigger", "PortSwigger", "https://portswigger.net/blog", "https://portswigger.net/blog/rss"),
    SourceConfig("owasp", "OWASP", "https://owasp.org", "https://owasp.org/feed.xml"),
    SourceConfig("exploit-db", "Exploit-DB", "https://www.exploit-db.com", "https://www.exploit-db.com/rss.xml"),
    SourceConfig("packet-storm", "Packet Storm Security", "https://packetstormsecurity.com", "https://packetstormsecurity.com/feeds/files/"),
    SourceConfig("ransomware-live", "Ransomware.live", "https://www.ransomware.live", "https://www.ransomware.live/rss"),

    SourceConfig("sophos-news", "Sophos News", "https://news.sophos.com", "https://news.sophos.com/en-us/feed"),

    SourceConfig("crowdstrike-blog", "CrowdStrike Blog", "https://www.crowdstrike.com/blog", "https://www.crowdstrike.com/blog/feed/"),
    SourceConfig("sentinelone-labs", "SentinelOne Labs", "https://www.sentinelone.com/labs", "https://www.sentinelone.com/labs/feed/"),
    SourceConfig("checkpoint-research", "Check Point Research", "https://research.checkpoint.com", "https://research.checkpoint.com/feed/"),
    SourceConfig("welivesecurity", "ESET WeLiveSecurity", "https://www.welivesecurity.com", "https://www.welivesecurity.com/feed/"),
    SourceConfig("securelist", "Kaspersky Securelist", "https://securelist.com", "https://securelist.com/feed/"),
    SourceConfig("bitdefender-labs", "Bitdefender Labs", "https://www.bitdefender.com/blog/labs", "https://www.bitdefender.com/blog/api/rss/labs/"),
    SourceConfig("withsecure-labs", "WithSecure Labs", "https://labs.withsecure.com", "https://labs.withsecure.com/feed"),
    SourceConfig("redcanary", "Red Canary Blog", "https://redcanary.com/blog", "https://redcanary.com/blog/rss.xml"),
    SourceConfig("elastic-security-labs", "Elastic Security Labs", "https://www.elastic.co/security-labs", "https://www.elastic.co/security-labs/rss.xml"),
    SourceConfig("huntress-blog", "Huntress Blog", "https://www.huntress.com/blog", "https://www.huntress.com/blog/rss.xml"),
    SourceConfig("rapid7-blog", "Rapid7 Blog", "https://www.rapid7.com/blog", "https://www.rapid7.com/blog/rss"),
    SourceConfig("malwarebytes-labs", "Malwarebytes Labs", "https://www.malwarebytes.com/blog", "https://www.malwarebytes.com/blog/feed"),

    SourceConfig("project-zero", "Google Project Zero", "https://googleprojectzero.blogspot.com", "https://googleprojectzero.blogspot.com/feeds/posts/default"),
    SourceConfig("bugcrowd-blog", "Bugcrowd Blog", "https://www.bugcrowd.com/blog", "https://www.bugcrowd.com/blog/feed/"),
    SourceConfig("yeswehack-blog", "YesWeHack Blog", "https://blog.yeswehack.com", "https://blog.yeswehack.com/rss/"),
    SourceConfig("netspi-blog", "NetSPI Blog", "https://www.netspi.com/blog", "https://www.netspi.com/blog/feed/"),
    SourceConfig("intezer-blog", "Intezer Blog", "https://intezer.com/blog", "https://intezer.com/blog/feed/"),
    SourceConfig("virustotal-blog", "VirusTotal Blog", "https://blog.virustotal.com", "https://blog.virustotal.com/feeds/posts/default"),
    SourceConfig("maltego-blog", "Maltego Blog", "https://www.maltego.com/blog", "https://www.maltego.com/blog/feed/"),
    SourceConfig("spiderfoot-blog", "SpiderFoot Blog", "https://www.spiderfoot.net/blog", "https://www.spiderfoot.net/blog/feed/"),

    SourceConfig("x-msftsecresponse", "X - MSFT Security Response", "https://x.com/msftsecresponse", "https://nitter.net/msftsecresponse/rss"),
    SourceConfig("x-cisagov", "X - CISA", "https://x.com/CISAgov", "https://nitter.net/CISAgov/rss"),
    SourceConfig("x-thehackernews", "X - The Hacker News", "https://x.com/thehackersnews", "https://nitter.net/thehackersnews/rss"),
    SourceConfig("x-crowdstrike", "X - CrowdStrike", "https://x.com/CrowdStrike", "https://nitter.net/CrowdStrike/rss"),
]
