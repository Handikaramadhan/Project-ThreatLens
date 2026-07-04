from datetime import datetime

from pydantic import BaseModel


class Metric(BaseModel):
    label: str
    value: int
    delta: str
    tone: str


class CVEItem(BaseModel):
    cve_id: str
    severity: str
    vendor: str
    product: str = ""
    published_at: datetime
    kev: bool


class IOCItem(BaseModel):
    indicator: str
    type: str
    severity: str
    source: str


class NewsItem(BaseModel):
    title: str
    source: str
    published_at: datetime
    url: str
    summary: str


class TechniqueItem(BaseModel):
    technique_id: str
    name: str
    tactic: str
    count: int


class AssetExposureItem(BaseModel):
    asset: str
    asset_type: str
    os_version: str
    matching_cve: int
    risk: str


class DistributionPoint(BaseModel):
    label: str
    value: int


class CVETrendPoint(BaseModel):
    date: str
    critical: int
    high: int
    medium: int
    low: int
    unknown: int


class DashboardPayload(BaseModel):
    metrics: list[Metric]
    cves: list[CVEItem]
    iocs: list[IOCItem]
    news: list[NewsItem]
    techniques: list[TechniqueItem]
    exposures: list[AssetExposureItem]
    cve_trend: list[CVETrendPoint]
    severity_distribution: list[DistributionPoint]
    ioc_distribution: list[DistributionPoint]
    asset_risk_distribution: list[DistributionPoint]
