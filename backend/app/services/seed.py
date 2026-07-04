from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import Asset, AssetExposure, CVE, IOC, MitreTechnique, ThreatNews


def seed_if_empty(db: Session) -> None:
    exists = db.scalar(select(CVE.id).limit(1))
    if exists:
        return

    now = datetime.utcnow()
    cves = [
        CVE(cve_id="CVE-2026-5281", title="Chrome zero-day remote code execution", severity="Critical", vendor="Google", product="Chrome", cvss_score=9.8, kev=True, published_at=now - timedelta(days=2), source="NVD/KEV"),
        CVE(cve_id="CVE-2026-42897", title="Exchange privilege escalation", severity="High", vendor="Microsoft", product="Exchange", cvss_score=8.6, kev=True, published_at=now - timedelta(days=3), source="NVD"),
        CVE(cve_id="CVE-2026-3910", title="Fortinet SSL VPN auth bypass", severity="High", vendor="Fortinet", product="FortiGate", cvss_score=8.1, kev=True, published_at=now - timedelta(days=4), source="CISA KEV"),
        CVE(cve_id="CVE-2026-1234", title="Cisco IOS command injection", severity="Medium", vendor="Cisco", product="IOS", cvss_score=6.7, kev=False, published_at=now - timedelta(days=8), source="NVD"),
        CVE(cve_id="CVE-2026-1111", title="VMware management interface exposure", severity="Medium", vendor="VMware", product="ESXi", cvss_score=6.2, kev=False, published_at=now - timedelta(days=9), source="NVD"),
    ]
    db.add_all(cves)

    db.add_all(
        [
            IOC(indicator="185.197.xx.23", type="ip", threat="Ransomware", severity="High", source="AbuseIPDB"),
            IOC(indicator="176.65.xx.11", type="ip", threat="C2", severity="High", source="OTX"),
            IOC(indicator="45.77.xx.54", type="ip", threat="Phishing", severity="Medium", source="AbuseIPDB"),
            IOC(indicator="103.224.xx.10", type="domain", threat="Malware", severity="Medium", source="OTX"),
            IOC(indicator="192.99.xx.12", type="hash", threat="Loader", severity="Low", source="MalwareBazaar"),
        ]
    )
    db.add_all(
        [
            ThreatNews(title="New Chrome zero-day CVE-2026-5281 exploited in the wild", url="https://example.local/news/chrome-zero-day", source="The Hacker News", published_at=now - timedelta(hours=5), summary="Emergency patch recommended."),
            ThreatNews(title="LockBit 3.0 targeting ESXi hosts", url="https://example.local/news/lockbit-esxi", source="BleepingComputer", published_at=now - timedelta(hours=18), summary="Ransomware operators expanding virtualization targeting."),
            ThreatNews(title="Microsoft Patch Tuesday - May 2026", url="https://example.local/news/patch-tuesday", source="Microsoft", published_at=now - timedelta(days=1), summary="High priority fixes released."),
            ThreatNews(title="Phishing campaign using QR code lures", url="https://example.local/news/qr-phishing", source="THN", published_at=now - timedelta(days=2), summary="Credential harvesting observed."),
        ]
    )
    db.add_all(
        [
            MitreTechnique(technique_id="T1059", name="Command and Scripting Interpreter", tactic="Execution", count=45),
            MitreTechnique(technique_id="T1566", name="Phishing", tactic="Initial Access", count=32),
            MitreTechnique(technique_id="T1078", name="Valid Accounts", tactic="Defense Evasion", count=28),
            MitreTechnique(technique_id="T1105", name="Ingress Tool Transfer", tactic="Command and Control", count=18),
            MitreTechnique(technique_id="T1047", name="Windows Management Instrumentation", tactic="Execution", count=12),
        ]
    )

    assets = [
        Asset(name="FortiGate-01", asset_type="Firewall", os_version="7.2.5", owner="Network", risk="High"),
        Asset(name="Win-Server-01", asset_type="Server", os_version="2022", owner="Infra", risk="High"),
        Asset(name="ESXi-Host-01", asset_type="Hypervisor", os_version="7.0U3", owner="Infra", risk="Medium"),
        Asset(name="Exchange-01", asset_type="Mail Server", os_version="2019", owner="Messaging", risk="High"),
        Asset(name="DC-01", asset_type="Domain Controller", os_version="2022", owner="Identity", risk="Medium"),
    ]
    db.add_all(assets)
    db.flush()

    db.add_all(
        [
            AssetExposure(asset_id=assets[0].id, cve_id="CVE-2026-3910", matching_score=3, risk="High"),
            AssetExposure(asset_id=assets[1].id, cve_id="CVE-2026-5281", matching_score=5, risk="High"),
            AssetExposure(asset_id=assets[2].id, cve_id="CVE-2026-1111", matching_score=2, risk="Medium"),
            AssetExposure(asset_id=assets[3].id, cve_id="CVE-2026-42897", matching_score=4, risk="High"),
            AssetExposure(asset_id=assets[4].id, cve_id="CVE-2026-1234", matching_score=2, risk="Medium"),
        ]
    )

    db.commit()
