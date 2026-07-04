from datetime import datetime

from pydantic import BaseModel, Field


class AIStatusOut(BaseModel):
    enabled: bool
    reachable: bool
    provider: str
    model: str
    message: str


class AIConversationCreate(BaseModel):
    title: str = Field(default="New investigation", min_length=1, max_length=160)


class AIConversationOut(BaseModel):
    id: int
    title: str
    created_at: datetime
    updated_at: datetime


class AIMessageCreate(BaseModel):
    content: str = Field(min_length=2, max_length=8000)


class AIMessageOut(BaseModel):
    id: int
    role: str
    content: str
    citations: list[str]
    created_at: datetime


class AIChatResponse(BaseModel):
    user_message: AIMessageOut
    assistant_message: AIMessageOut


class AIProductInference(BaseModel):
    vendor: str = "Unknown"
    product: str = "Unknown"
    versions: list[str] = Field(default_factory=list)
    confidence: float = 0
    evidence: list[str] = Field(default_factory=list)


class CVEAIEnrichmentOut(BaseModel):
    cve_id: str
    executive_summary: str = ""
    product_inference: AIProductInference
    attack_path: list[str] = Field(default_factory=list)
    business_impact: list[str] = Field(default_factory=list)
    detection_guidance: list[str] = Field(default_factory=list)
    mitigation: list[str] = Field(default_factory=list)
    workarounds: list[str] = Field(default_factory=list)
    analyst_notes: list[str] = Field(default_factory=list)
    citations: list[str] = Field(default_factory=list)
    provider: str
    model: str
    generated_at: datetime
