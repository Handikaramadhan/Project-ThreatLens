import json
import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models.entities import Asset, AssetExposure, CVE, CVEDetail
from app.services.alerts import alert_event_key, queue_alert_event
from app.services.product_resolution import is_unknown_product

GENERIC_TERMS = {
    "server",
    "service",
    "application",
    "app",
    "prod",
    "production",
    "dev",
    "test",
    "web",
    "api",
    "db",
    "database",
    "linux",
    "windows",
    "enterprise",
    "community",
    "edition",
    "platform",
}

RISK_BY_SEVERITY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}

OS_ALIASES = (
    (
        ("rocky linux", "almalinux", "alma linux", "centos"),
        ("red hat enterprise linux", "redhat enterprise linux", "enterprise linux", "rhel"),
    ),
)


@dataclass(frozen=True)
class ProductCandidate:
    vendor: str
    product: str
    version: str = ""
    version_range: str = ""


@dataclass(frozen=True)
class ExposureExplanation:
    confidence: str
    match_type: str
    affected_vendor: str
    affected_product: str
    affected_version: str
    affected_version_range: str
    reason: str
    evidence: list[str]
    limitations: list[str]


def _norm(value: object) -> str:
    return re.sub(r"[^a-z0-9.]+", " ", str(value or "").lower()).strip()


def _tokens(value: object) -> set[str]:
    return {
        token
        for token in _norm(value).split()
        if len(token) >= 3 and token not in GENERIC_TERMS and not token.isdigit()
    }


def _versions(value: object) -> list[tuple[int, ...]]:
    versions = []
    for match in re.finditer(r"\b\d+(?:\.\d+){0,3}\b", str(value or "")):
        versions.append(tuple(int(part) for part in match.group(0).split(".")))
    return versions


def _cmp_version(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    return (padded_left > padded_right) - (padded_left < padded_right)


def _range_satisfied(asset_version: tuple[int, ...], version_range: str) -> bool:
    constraints = re.findall(r"(>=|>|<=|<)\s*(\d+(?:\.\d+){0,3})", version_range)
    if not constraints:
        return True
    for operator, version in constraints:
        target = tuple(int(part) for part in version.split("."))
        comparison = _cmp_version(asset_version, target)
        if operator == ">=" and comparison < 0:
            return False
        if operator == ">" and comparison <= 0:
            return False
        if operator == "<=" and comparison > 0:
            return False
        if operator == "<" and comparison >= 0:
            return False
    return True


def _load_nvd_payload(detail: CVEDetail | None) -> dict[str, Any]:
    if detail is None:
        return {}
    try:
        payload = json.loads(detail.nvd_payload or "{}")
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _candidates_for_cve(cve: CVE, detail: CVEDetail | None) -> list[ProductCandidate]:
    payload = _load_nvd_payload(detail)
    candidates: list[ProductCandidate] = []
    seen: set[tuple[str, str, str, str]] = set()

    for item in payload.get("affected_products") or []:
        if not isinstance(item, dict) or item.get("vulnerable") is False:
            continue
        product = str(item.get("product") or "")
        if is_unknown_product(product):
            continue
        vendor = str(item.get("vendor") or "")
        version = str(item.get("version") or "")
        version_range = str(item.get("version_range") or "")
        identity = (_norm(vendor), _norm(product), _norm(version), _norm(version_range))
        if identity in seen:
            continue
        seen.add(identity)
        candidates.append(ProductCandidate(vendor=vendor, product=product, version=version, version_range=version_range))

    if not candidates and not is_unknown_product(cve.product):
        candidates.append(ProductCandidate(vendor=cve.vendor, product=cve.product))

    return candidates[:50]


def _version_score(asset_versions: list[tuple[int, ...]], candidate: ProductCandidate) -> int | None:
    affected_version = _versions(candidate.version)
    affected_range = candidate.version_range
    if affected_range:
        if not asset_versions:
            return 5
        return 15 if any(_range_satisfied(version, affected_range) for version in asset_versions) else None
    if affected_version:
        if not asset_versions:
            return 5
        target = affected_version[0]
        if any(version == target for version in asset_versions):
            return 15
        if len(target) == 1 and any(version and version[0] == target[0] for version in asset_versions):
            return 12
        return None
    return 0


def _alias_product_matched(asset_norm: str, candidate: ProductCandidate) -> bool:
    candidate_norm = _norm(f"{candidate.vendor} {candidate.product}")
    for asset_aliases, product_aliases in OS_ALIASES:
        if any(alias in asset_norm for alias in asset_aliases) and any(
            alias in candidate_norm for alias in product_aliases
        ):
            return True
    return False


def _confidence_for_score(score: int) -> str:
    if score >= 85:
        return "High"
    if score >= 70:
        return "Medium"
    return "Low"


def _matched_candidate(asset: Asset, cve: CVE, detail: CVEDetail | None, score: int) -> tuple[ProductCandidate, int] | None:
    best: tuple[ProductCandidate, int] | None = None
    for candidate in _candidates_for_cve(cve, detail):
        candidate_score = _match_score(asset, cve, candidate)
        if candidate_score is None:
            continue
        if best is None or candidate_score > best[1]:
            best = (candidate, candidate_score)
    if best is not None:
        return best
    candidates = _candidates_for_cve(cve, detail)
    if candidates:
        return candidates[0], score
    return ProductCandidate(vendor=cve.vendor, product=cve.product), score


def _match_score(asset: Asset, cve: CVE, candidate: ProductCandidate) -> int | None:
    asset_text = " ".join(
        [
            asset.name,
            asset.asset_type,
            asset.os_version,
            asset.vendor,
            asset.product,
            asset.version,
        ]
    )
    asset_norm = _norm(asset_text)
    product_norm = _norm(candidate.product)
    product_tokens = _tokens(candidate.product)
    alias_matched = _alias_product_matched(asset_norm, candidate)
    if not product_tokens and not alias_matched:
        return None

    product_matched = alias_matched or product_norm in asset_norm or bool(product_tokens.intersection(_tokens(asset_text)))
    if not product_matched:
        return None

    score = 65
    asset_versions = _versions(asset_text)
    if alias_matched:
        candidate_name_versions = _versions(f"{candidate.vendor} {candidate.product}")
        if candidate_name_versions and asset_versions and not any(
            asset_version[0] == candidate_version[0]
            for asset_version in asset_versions
            for candidate_version in candidate_name_versions
            if asset_version and candidate_version
        ):
            return None

    vendor_tokens = _tokens(candidate.vendor)
    if vendor_tokens and vendor_tokens.intersection(_tokens(asset_text)):
        score += 10

    version_score = _version_score(asset_versions, candidate)
    if version_score is None:
        return None
    score += version_score

    if cve.kev:
        score += 5
    if str(cve.severity).lower() in {"critical", "high"}:
        score += 5
    return min(score, 100)


def explain_exposure(asset: Asset, cve: CVE, detail: CVEDetail | None, score: int) -> ExposureExplanation:
    asset_text = " ".join(
        [
            asset.name,
            asset.asset_type,
            asset.os_version,
            asset.vendor,
            asset.product,
            asset.version,
        ]
    )
    asset_norm = _norm(asset_text)
    asset_versions = _versions(asset_text)
    match = _matched_candidate(asset, cve, detail, score)
    candidate = match[0] if match else ProductCandidate(vendor=cve.vendor, product=cve.product)
    evidence: list[str] = []
    limitations: list[str] = []

    alias_matched = _alias_product_matched(asset_norm, candidate)
    exact_product_matched = bool(_norm(candidate.product) and _norm(candidate.product) in asset_norm)
    token_overlap = sorted(_tokens(candidate.product).intersection(_tokens(asset_text)))
    vendor_overlap = sorted(_tokens(candidate.vendor).intersection(_tokens(asset_text)))
    version_score = _version_score(asset_versions, candidate)

    if alias_matched:
        match_type = "OS family alias"
        reason = (
            f"{asset.name} matched {candidate.vendor} {candidate.product} via OS-family alias; "
            f"score {score}. Validate installed packages before remediation."
        )
        evidence.append("Asset OS family is known to be downstream-compatible with the affected product family.")
        limitations.append("Alias matches are conservative leads, not proof that the vulnerable package is installed.")
    elif exact_product_matched:
        match_type = "Product metadata"
        reason = (
            f"{asset.name} metadata contains affected product {candidate.product}; "
            f"score {score}. Validate installed version before remediation."
        )
        evidence.append(f"Asset metadata contains affected product name: {candidate.product}.")
    else:
        match_type = "Token overlap"
        reason = (
            f"{asset.name} metadata overlaps affected product {candidate.product}; "
            f"score {score}. Treat as inferred until verified."
        )
        if token_overlap:
            evidence.append(f"Shared product terms: {', '.join(token_overlap)}.")
        limitations.append("Token-overlap matches can be noisy when asset metadata is sparse.")

    if vendor_overlap:
        evidence.append(f"Vendor term also appears in asset metadata: {', '.join(vendor_overlap)}.")
    if candidate.version_range:
        if version_score == 15:
            evidence.append(f"Asset version satisfies affected range: {candidate.version_range}.")
        else:
            evidence.append(f"CVE has affected version range metadata: {candidate.version_range}.")
    elif candidate.version:
        if version_score in {12, 15}:
            evidence.append(f"Asset version aligns with affected version: {candidate.version}.")
        else:
            evidence.append(f"CVE has affected version metadata: {candidate.version}.")
    elif asset_versions:
        limitations.append("CVE source does not include precise affected-version metadata for this product.")
    else:
        limitations.append("Asset has no parsed version, so version-level validation is limited.")

    if cve.kev:
        evidence.append("CVE is listed as KEV, increasing triage priority.")
    if str(cve.severity).lower() in {"critical", "high"}:
        evidence.append(f"CVE severity is {cve.severity}.")
    if not evidence:
        evidence.append("Exposure was retained because asset metadata matched affected product metadata.")

    return ExposureExplanation(
        confidence=_confidence_for_score(score),
        match_type=match_type,
        affected_vendor=candidate.vendor,
        affected_product=candidate.product,
        affected_version=candidate.version,
        affected_version_range=candidate.version_range,
        reason=reason,
        evidence=evidence,
        limitations=limitations,
    )


def exposure_reason(asset: Asset, cve: CVE, detail: CVEDetail | None, score: int) -> str:
    return explain_exposure(asset, cve, detail, score).reason


def _risk_for_cve(cve: CVE) -> str:
    return RISK_BY_SEVERITY.get(str(cve.severity or "").lower(), "Medium")


def refresh_asset_exposures(db: Session, asset_id: int | None = None) -> int:
    asset_query = select(Asset)
    if asset_id is not None:
        asset_query = asset_query.where(Asset.id == asset_id)
    assets = list(db.scalars(asset_query).all())

    existing_exposures = list(
        db.scalars(
            select(AssetExposure)
            if asset_id is None
            else select(AssetExposure).where(AssetExposure.asset_id == asset_id)
        ).all()
    )
    existing_reviews = {
        (exposure.asset_id, exposure.cve_id): {
            "status": exposure.status,
            "review_note": exposure.review_note,
            "reviewed_at": exposure.reviewed_at,
            "reviewed_by": exposure.reviewed_by,
        }
        for exposure in existing_exposures
    }

    delete_query = delete(AssetExposure)
    if asset_id is not None:
        delete_query = delete_query.where(AssetExposure.asset_id == asset_id)
    db.execute(delete_query)

    if not assets:
        return 0

    cves = list(db.scalars(select(CVE)).all())
    details_by_id = {
        detail.cve_id: detail
        for detail in db.scalars(select(CVEDetail)).all()
    }
    created = 0
    for asset in assets:
        for cve in cves:
            best_score = None
            for candidate in _candidates_for_cve(cve, details_by_id.get(cve.cve_id)):
                score = _match_score(asset, cve, candidate)
                if score is not None and (best_score is None or score > best_score):
                    best_score = score
            if best_score is None:
                continue
            existing_review = existing_reviews.get((asset.id, cve.cve_id), {})
            if existing_review.get("status") == "false_positive":
                continue
            is_new_exposure = (asset.id, cve.cve_id) not in existing_reviews
            db.add(
                AssetExposure(
                    asset_id=asset.id,
                    cve_id=cve.cve_id,
                    matching_score=best_score,
                    risk=_risk_for_cve(cve),
                    **existing_review,
                )
            )
            if is_new_exposure and best_score >= 70:
                queue_alert_event(
                    db,
                    event_type="asset_exposure",
                    event_key=alert_event_key("asset", f"{asset.id}:{cve.cve_id}"),
                    title=f"{asset.name} terdampak {cve.cve_id}",
                    body=(
                        f"{asset.name} cocok dengan {cve.cve_id} ({cve.severity}). "
                        f"Produk: {asset.vendor} {asset.product} {asset.version or asset.os_version}."
                    ),
                    severity=_risk_for_cve(cve),
                    link="/#/assets",
                )
            created += 1
    return created
