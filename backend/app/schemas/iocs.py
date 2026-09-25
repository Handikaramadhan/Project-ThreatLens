from datetime import datetime

from pydantic import BaseModel, Field


class RelatedAssetRef(BaseModel):
    id: int
    name: str
    risk: str
    reason: str


class IOCOut(BaseModel):
    indicator: str
    type: str
    threat: str
    severity: str
    source: str
    first_seen: datetime
    last_seen: datetime
    related_assets: list[RelatedAssetRef] = Field(default_factory=list)
