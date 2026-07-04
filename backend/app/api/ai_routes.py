import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import delete, desc, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.entities import (
    AIConversation,
    AIMessage,
    CVE,
    CVEAIEnrichment,
    CVEDetail,
    CVEWebEnrichment,
)
from app.schemas.ai import (
    AIChatResponse,
    AIConversationCreate,
    AIConversationOut,
    AIMessageCreate,
    AIMessageOut,
    AIStatusOut,
    CVEAIEnrichmentOut,
)
from app.services.ai import AIUnavailable, answer_threat_intel, investigate_cve, runner_status
from app.services.auth import AuthContext, get_auth_context, require_csrf

router = APIRouter()


def _json_dict(value: str) -> dict:
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}


def _message_out(message: AIMessage) -> AIMessageOut:
    try:
        citations = json.loads(message.citations)
    except json.JSONDecodeError:
        citations = []
    return AIMessageOut(
        id=message.id,
        role=message.role,
        content=message.content,
        citations=citations if isinstance(citations, list) else [],
        created_at=message.created_at,
    )


def _conversation_for_user(db: Session, conversation_id: int, user_id: int) -> AIConversation:
    conversation = db.scalar(
        select(AIConversation).where(
            AIConversation.id == conversation_id,
            AIConversation.user_id == user_id,
        )
    )
    if conversation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
    return conversation


def _enrichment_out(row: CVEAIEnrichment) -> CVEAIEnrichmentOut:
    payload = _json_dict(row.payload)
    return CVEAIEnrichmentOut(
        cve_id=row.cve_id,
        executive_summary=str(payload.get("executive_summary") or ""),
        product_inference=payload.get("product_inference") or {},
        attack_path=payload.get("attack_path") or [],
        business_impact=payload.get("business_impact") or [],
        detection_guidance=payload.get("detection_guidance") or [],
        mitigation=payload.get("mitigation") or [],
        workarounds=payload.get("workarounds") or [],
        analyst_notes=payload.get("analyst_notes") or [],
        citations=payload.get("citations") or [],
        provider=row.provider,
        model=row.model,
        generated_at=row.generated_at,
    )


@router.get("/ai/status", response_model=AIStatusOut)
def ai_status(_: AuthContext = Depends(get_auth_context)) -> AIStatusOut:
    reachable, message = runner_status()
    return AIStatusOut(
        enabled=settings.ai_enabled,
        reachable=reachable,
        provider=settings.ai_provider,
        model=settings.ai_model,
        message=message,
    )


@router.get("/ai/conversations", response_model=list[AIConversationOut])
def list_conversations(
    db: Session = Depends(get_db),
    context: AuthContext = Depends(get_auth_context),
) -> list[AIConversationOut]:
    rows = db.scalars(
        select(AIConversation)
        .where(AIConversation.user_id == context.user.id)
        .order_by(desc(AIConversation.updated_at))
        .limit(100)
    ).all()
    return [
        AIConversationOut(
            id=row.id,
            title=row.title,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )
        for row in rows
    ]


@router.post("/ai/conversations", response_model=AIConversationOut, status_code=201)
def create_conversation(
    payload: AIConversationCreate,
    db: Session = Depends(get_db),
    context: AuthContext = Depends(require_csrf),
) -> AIConversationOut:
    row = AIConversation(user_id=context.user.id, title=payload.title.strip())
    db.add(row)
    db.commit()
    db.refresh(row)
    return AIConversationOut(
        id=row.id,
        title=row.title,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.get("/ai/conversations/{conversation_id}/messages", response_model=list[AIMessageOut])
def list_messages(
    conversation_id: int,
    db: Session = Depends(get_db),
    context: AuthContext = Depends(get_auth_context),
) -> list[AIMessageOut]:
    _conversation_for_user(db, conversation_id, context.user.id)
    rows = db.scalars(
        select(AIMessage)
        .where(AIMessage.conversation_id == conversation_id)
        .order_by(AIMessage.created_at, AIMessage.id)
        .limit(200)
    ).all()
    return [_message_out(row) for row in rows]


@router.post("/ai/conversations/{conversation_id}/messages", response_model=AIChatResponse)
def send_message(
    conversation_id: int,
    payload: AIMessageCreate,
    db: Session = Depends(get_db),
    context: AuthContext = Depends(require_csrf),
) -> AIChatResponse:
    conversation = _conversation_for_user(db, conversation_id, context.user.id)
    content = payload.content.strip()
    user_message = AIMessage(conversation_id=conversation.id, role="user", content=content)
    db.add(user_message)
    if conversation.title == "New investigation":
        conversation.title = content[:80]
    conversation.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(user_message)
    try:
        answer = answer_threat_intel(
            db,
            content,
            f"threatlens-user-{context.user.id}-conversation-{conversation.id}",
        )
    except AIUnavailable as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    assistant_message = AIMessage(
        conversation_id=conversation.id,
        role="assistant",
        content=answer,
    )
    db.add(assistant_message)
    conversation.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(assistant_message)
    return AIChatResponse(
        user_message=_message_out(user_message),
        assistant_message=_message_out(assistant_message),
    )


@router.delete("/ai/conversations/{conversation_id}", status_code=204)
def delete_conversation(
    conversation_id: int,
    db: Session = Depends(get_db),
    context: AuthContext = Depends(require_csrf),
) -> Response:
    conversation = _conversation_for_user(db, conversation_id, context.user.id)
    db.execute(delete(AIConversation).where(AIConversation.id == conversation.id))
    db.commit()
    return Response(status_code=204)


@router.get("/cves/{cve_id}/ai-enrichment", response_model=CVEAIEnrichmentOut)
def get_cve_ai_enrichment(
    cve_id: str,
    db: Session = Depends(get_db),
    _: AuthContext = Depends(get_auth_context),
) -> CVEAIEnrichmentOut:
    row = db.get(CVEAIEnrichment, cve_id.strip().upper())
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI enrichment not found")
    return _enrichment_out(row)


@router.post("/cves/{cve_id}/ai-enrichment", response_model=CVEAIEnrichmentOut)
def generate_cve_ai_enrichment(
    cve_id: str,
    db: Session = Depends(get_db),
    context: AuthContext = Depends(require_csrf),
) -> CVEAIEnrichmentOut:
    normalized_id = cve_id.strip().upper()
    cve = db.scalar(select(CVE).where(CVE.cve_id == normalized_id))
    if cve is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CVE not found")
    detail = db.get(CVEDetail, normalized_id)
    web = db.get(CVEWebEnrichment, normalized_id)
    try:
        payload = investigate_cve(
            cve,
            _json_dict(detail.nvd_payload) if detail else {},
            _json_dict(web.payload) if web else {},
            f"threatlens-cve-{normalized_id}",
        )
    except AIUnavailable as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    row = db.get(CVEAIEnrichment, normalized_id)
    if row is None:
        row = CVEAIEnrichment(cve_id=normalized_id)
        db.add(row)
    row.payload = json.dumps(payload)
    row.provider = settings.ai_provider
    row.model = settings.ai_model
    row.confidence = float(payload["product_inference"]["confidence"])
    row.generated_by = context.user.id
    row.generated_at = datetime.utcnow()
    db.commit()
    db.refresh(row)
    return _enrichment_out(row)
