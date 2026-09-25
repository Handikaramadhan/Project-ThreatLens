from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.models.entities import Asset, AssetExposure, CVE, IOC, MitreTechnique, ThreatNews

LEGACY_DEMO_CVES = {
    "CVE-2026-5281": "Chrome zero-day remote code execution",
    "CVE-2026-42897": "Exchange privilege escalation",
    "CVE-2026-3910": "Fortinet SSL VPN auth bypass",
    "CVE-2026-1234": "Cisco IOS command injection",
    "CVE-2026-1111": "VMware management interface exposure",
}
LEGACY_DEMO_IOCS = {
    "185.197.xx.23",
    "176.65.xx.11",
    "45.77.xx.54",
    "103.224.xx.10",
    "192.99.xx.12",
}
LEGACY_DEMO_TECHNIQUES = {
    "T1059": ("Command and Scripting Interpreter", "Execution", 45),
    "T1566": ("Phishing", "Initial Access", 32),
    "T1078": ("Valid Accounts", "Defense Evasion", 28),
    "T1105": ("Ingress Tool Transfer", "Command and Control", 18),
    "T1047": ("Windows Management Instrumentation", "Execution", 12),
}
LEGACY_DEMO_ASSETS = {
    "FortiGate-01": ("Firewall", "7.2.5", "Network", "High"),
    "Win-Server-01": ("Server", "2022", "Infra", "High"),
    "ESXi-Host-01": ("Hypervisor", "7.0U3", "Infra", "Medium"),
    "Exchange-01": ("Mail Server", "2019", "Messaging", "High"),
    "DC-01": ("Domain Controller", "2022", "Identity", "Medium"),
}


def cleanup_demo_records(db: Session) -> None:
    """Remove only records that can be identified as bundled demo data."""
    demo_cve_ids: list[str] = []
    candidates = db.scalars(
        select(CVE).where(CVE.cve_id.in_(LEGACY_DEMO_CVES))
    ).all()
    for item in candidates:
        if (
            item.title == LEGACY_DEMO_CVES[item.cve_id]
            and not item.description.strip()
        ):
            demo_cve_ids.append(item.cve_id)
            db.delete(item)

    if demo_cve_ids:
        db.execute(delete(AssetExposure).where(AssetExposure.cve_id.in_(demo_cve_ids)))
    db.execute(delete(CVE).where(CVE.source == "demo"))
    db.execute(delete(IOC).where(IOC.source == "demo"))
    db.execute(delete(IOC).where(IOC.indicator.in_(LEGACY_DEMO_IOCS)))
    db.execute(delete(ThreatNews).where(ThreatNews.source == "demo"))
    db.execute(delete(ThreatNews).where(ThreatNews.url.like("https://example.local/%")))

    technique_candidates = db.scalars(
        select(MitreTechnique).where(
            MitreTechnique.technique_id.in_(LEGACY_DEMO_TECHNIQUES)
        )
    ).all()
    for item in technique_candidates:
        if (
            item.name,
            item.tactic,
            item.count,
        ) == LEGACY_DEMO_TECHNIQUES[item.technique_id]:
            db.delete(item)

    asset_candidates = db.scalars(
        select(Asset).where(Asset.name.in_(LEGACY_DEMO_ASSETS))
    ).all()
    for item in asset_candidates:
        if (
            item.asset_type,
            item.os_version,
            item.owner,
            item.risk,
        ) != LEGACY_DEMO_ASSETS[item.name]:
            continue
        db.execute(delete(AssetExposure).where(AssetExposure.asset_id == item.id))
        db.delete(item)
    db.commit()


def seed_if_empty(db: Session) -> None:
    populated = any(
        db.scalar(statement) is not None
        for statement in (
            select(CVE.id).limit(1),
            select(IOC.id).limit(1),
            select(ThreatNews.id).limit(1),
            select(MitreTechnique.id).limit(1),
            select(Asset.id).limit(1),
        )
    )
    if populated:
        return

    now = utc_now()
    cves = [
        CVE(cve_id="CVE-2026-5281", title="Chrome zero-day remote code execution", severity="Critical", vendor="Google", product="Chrome", cvss_score=9.8, kev=True, published_at=now - timedelta(days=2), source="demo"),
        CVE(cve_id="CVE-2026-42897", title="Exchange privilege escalation", severity="High", vendor="Microsoft", product="Exchange", cvss_score=8.6, kev=True, published_at=now - timedelta(days=3), source="demo"),
        CVE(cve_id="CVE-2026-3910", title="Fortinet SSL VPN auth bypass", severity="High", vendor="Fortinet", product="FortiGate", cvss_score=8.1, kev=True, published_at=now - timedelta(days=4), source="demo"),
        CVE(cve_id="CVE-2026-1234", title="Cisco IOS command injection", severity="Medium", vendor="Cisco", product="IOS", cvss_score=6.7, kev=False, published_at=now - timedelta(days=8), source="demo"),
        CVE(cve_id="CVE-2026-1111", title="VMware management interface exposure", severity="Medium", vendor="VMware", product="ESXi", cvss_score=6.2, kev=False, published_at=now - timedelta(days=9), source="demo"),
    ]
    db.add_all(cves)

    db.add_all(
        [
            IOC(indicator="185.197.xx.23", type="ip", threat="Ransomware", severity="High", source="demo"),
            IOC(indicator="176.65.xx.11", type="ip", threat="C2", severity="High", source="demo"),
            IOC(indicator="45.77.xx.54", type="ip", threat="Phishing", severity="Medium", source="demo"),
            IOC(indicator="103.224.xx.10", type="domain", threat="Malware", severity="Medium", source="demo"),
            IOC(indicator="192.99.xx.12", type="hash", threat="Loader", severity="Low", source="demo"),
        ]
    )
    db.add_all(
        [
            ThreatNews(title="New Chrome zero-day CVE-2026-5281 exploited in the wild", url="https://example.local/news/chrome-zero-day", source="demo", published_at=now - timedelta(hours=5), summary="Emergency patch recommended."),
            ThreatNews(title="LockBit 3.0 targeting ESXi hosts", url="https://example.local/news/lockbit-esxi", source="demo", published_at=now - timedelta(hours=18), summary="Ransomware operators expanding virtualization targeting."),
            ThreatNews(title="Microsoft Patch Tuesday - May 2026", url="https://example.local/news/patch-tuesday", source="demo", published_at=now - timedelta(days=1), summary="High priority fixes released."),
            ThreatNews(title="Phishing campaign using QR code lures", url="https://example.local/news/qr-phishing", source="demo", published_at=now - timedelta(days=2), summary="Credential harvesting observed."),
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
        Asset(name="FortiGate-01", asset_type="Firewall", os_version="FortiOS 7.2.5", vendor="Fortinet", product="FortiOS", version="7.2.5", environment="Production", criticality="High", internet_exposed=True, owner="Network", risk="High"),
        Asset(name="Win-Server-01", asset_type="Server", os_version="Windows Server 2022", vendor="Microsoft", product="Windows Server", version="2022", environment="Production", criticality="High", owner="Infra", risk="High"),
        Asset(name="ESXi-Host-01", asset_type="Hypervisor", os_version="ESXi 7.0U3", vendor="VMware", product="ESXi", version="7.0U3", environment="Production", criticality="High", owner="Infra", risk="Medium"),
        Asset(name="Exchange-01", asset_type="Mail Server", os_version="Exchange Server 2019", vendor="Microsoft", product="Exchange Server", version="2019", environment="Production", criticality="Critical", internet_exposed=True, owner="Messaging", risk="High"),
        Asset(name="DC-01", asset_type="Domain Controller", os_version="Windows Server 2022", vendor="Microsoft", product="Windows Server", version="2022", environment="Production", criticality="Critical", owner="Identity", risk="Medium"),
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
