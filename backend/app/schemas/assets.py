from typing import Literal

from pydantic import BaseModel, Field, field_validator

AssetRisk = Literal["Low", "Medium", "High", "Critical"]


class AssetWrite(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    asset_type: str = Field(min_length=2, max_length=80)
    os_version: str = Field(default="", max_length=120)
    owner: str = Field(default="", max_length=120)
    risk: AssetRisk = "Low"

    @field_validator("name", "asset_type", "os_version", "owner")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return value.strip()


class AssetOut(AssetWrite):
    id: int
    matching_cve: int = 0
