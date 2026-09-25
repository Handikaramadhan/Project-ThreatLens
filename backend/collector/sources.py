from dataclasses import dataclass


@dataclass(frozen=True)
class ThreatSource:
    name: str
    url: str
    kind: str


SOURCES = [
    ThreatSource("NVD CVE API", "https://services.nvd.nist.gov/rest/json/cves/2.0", "cve"),
    ThreatSource("CISA KEV Catalog", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "kev"),
    ThreatSource("MITRE ATT&CK", "https://attack.mitre.org", "mitre"),
    ThreatSource("AbuseIPDB", "https://www.abuseipdb.com", "ioc"),
    ThreatSource("AlienVault OTX", "https://otx.alienvault.com", "ioc"),
    ThreatSource("URLhaus", "https://urlhaus-api.abuse.ch/v2/files/exports", "ioc"),
    ThreatSource("PhishDestroy", "https://api.destroy.tools/v1/feed/primary_active", "ioc"),
    ThreatSource("Feodo Tracker", "https://feodotracker.abuse.ch/blocklist/", "ioc"),
    ThreatSource("OpenPhish", "https://www.openphish.com/phishing_feeds.html", "ioc"),
    ThreatSource("MalwareBazaar", "https://bazaar.abuse.ch", "malware"),
    ThreatSource("The Hacker News RSS", "https://feeds.feedburner.com/TheHackersNews", "news"),
    ThreatSource("BleepingComputer RSS", "https://www.bleepingcomputer.com/feed/", "news"),
    ThreatSource("SecurityWeek RSS", "https://www.securityweek.com/feed/", "news"),
    ThreatSource("Krebs on Security RSS", "https://krebsonsecurity.com/feed/", "news"),
    ThreatSource("SANS Internet Storm Center RSS", "https://isc.sans.edu/rssfeed_full.xml", "news"),
    ThreatSource("Google Security Blog RSS", "https://feeds.feedburner.com/GoogleOnlineSecurityBlog", "news"),
]
