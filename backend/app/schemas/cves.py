from datetime import datetime

from pydantic import BaseModel, Field


class CVSSMetrics(BaseModel):
    version: str = ""
    vector: str = ""
    base_score: float = 0
    base_severity: str = "Unknown"
    exploitability_score: float | None = None
    impact_score: float | None = None
    attack_vector: str = "Unknown"
    attack_complexity: str = "Unknown"
    privileges_required: str = "Unknown"
    user_interaction: str = "Unknown"
    scope: str = "Unknown"
    confidentiality_impact: str = "Unknown"
    integrity_impact: str = "Unknown"
    availability_impact: str = "Unknown"


class AffectedProduct(BaseModel):
    vendor: str
    product: str
    version: str
    vulnerable: bool = True
    version_range: str = ""


class CVEReference(BaseModel):
    url: str
    source: str = ""
    tags: list[str] = Field(default_factory=list)


class RemediationItem(BaseModel):
    text: str
    source: str
    url: str = ""


class ExploitStatus(BaseModel):
    known_exploited: bool
    date_added: str = ""
    action_due: str = ""
    required_action: str = ""
    ransomware_use: str = "Unknown"
    notes: str = ""


class RelatedIOC(BaseModel):
    indicator: str
    type: str
    threat: str
    severity: str
    source: str


class RelatedAsset(BaseModel):
    id: int
    name: str
    asset_type: str
    os_version: str
    owner: str
    risk: str


class RelatedNews(BaseModel):
    title: str
    source: str
    url: str
    published_at: datetime


class RootCauseAnalysis(BaseModel):
    category: str = "Undisclosed"
    summary: str = ""
    weaknesses: list[str] = Field(default_factory=list)
    basis: str = ""
    confidence: str = "Low"


class MitreTechniqueMapping(BaseModel):
    technique_id: str
    name: str
    tactic: str
    rationale: str
    confidence: str
    url: str


class ExploitabilityAnalysis(BaseModel):
    likelihood: str = "Unknown"
    confidence: str = "Low"
    prerequisites: list[str] = Field(default_factory=list)
    likely_attack_path: list[str] = Field(default_factory=list)
    exploitation_signals: list[str] = Field(default_factory=list)
    defensive_notes: list[str] = Field(default_factory=list)
    basis: list[str] = Field(default_factory=list)


class CVEListItem(BaseModel):
    cve_id: str
    severity: str
    vendor: str
    product: str = ""
    published_at: datetime
    kev: bool


class CVEPage(BaseModel):
    items: list[CVEListItem]
    total: int
    page: int
    limit: int
    pages: int


class CVEDetailOut(BaseModel):
    cve_id: str
    title: str
    description: str
    severity: str
    vendor: str
    product: str
    cvss_score: float
    cvss: CVSSMetrics | None
    kev: bool
    exploit_status: ExploitStatus
    weaknesses: list[str]
    affected_products: list[AffectedProduct]
    mitigation: list[RemediationItem]
    workarounds: list[RemediationItem]
    remediation_sources: list[CVEReference]
    references: list[CVEReference]
    related_iocs: list[RelatedIOC]
    related_assets: list[RelatedAsset]
    related_news: list[RelatedNews]
    published_at: datetime
    source: str
    detail_source: str
    fetched_at: datetime | None
    root_cause: RootCauseAnalysis = Field(default_factory=RootCauseAnalysis)
    mitre_techniques: list[MitreTechniqueMapping] = Field(default_factory=list)
    exploitability_analysis: ExploitabilityAnalysis = Field(default_factory=ExploitabilityAnalysis)
