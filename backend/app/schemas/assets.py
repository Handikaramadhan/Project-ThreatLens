from typing import Literal
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

AssetRisk = Literal["Low", "Medium", "High", "Critical"]
AssetCriticality = Literal["Low", "Medium", "High", "Critical"]
AssetExposureStatus = Literal["open", "validated", "false_positive", "accepted_risk", "remediated"]


class AssetWrite(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    asset_type: str = Field(min_length=2, max_length=80)
    os_version: str = Field(default="", max_length=120)
    vendor: str = Field(default="", max_length=120)
    product: str = Field(default="", max_length=120)
    version: str = Field(default="", max_length=80)
    environment: str = Field(default="", max_length=40)
    criticality: AssetCriticality = "Medium"
    internet_exposed: bool = False
    owner: str = Field(default="", max_length=120)
    risk: AssetRisk = "Low"

    @field_validator("name", "asset_type", "os_version", "vendor", "product", "version", "environment", "owner")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return value.strip()


class AssetOut(AssetWrite):
    id: int
    matching_cve: int = 0


class AssetExposureOut(BaseModel):
    cve_id: str
    title: str
    severity: str
    risk: str
    matching_score: int
    confidence: str
    match_type: str
    affected_vendor: str
    affected_product: str
    affected_version: str = ""
    affected_version_range: str = ""
    status: AssetExposureStatus = "open"
    review_note: str = ""
    reviewed_at: datetime | None = None
    reviewed_by: str = ""
    reason: str
    evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    published_at: datetime
    kev: bool


class AssetExposureUpdate(BaseModel):
    status: AssetExposureStatus
    review_note: str = Field(default="", max_length=500)

    @field_validator("review_note")
    @classmethod
    def strip_review_note(cls, value: str) -> str:
        return value.strip()
