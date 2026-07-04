import re
from typing import Any

UNKNOWN_VALUES = {"", "unknown", "n/a", "na", "not available", "unspecified", "*", "-"}


def is_unknown_product(value: object) -> bool:
    return str(value or "").strip().lower() in UNKNOWN_VALUES


def _clean(value: object, limit: int = 160) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def extract_cve_org_products(cve_record: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not cve_record:
        return []
    containers = cve_record.get("containers") or {}
    all_containers = [containers.get("cna") or {}, *(containers.get("adp") or [])]
    products: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    for container in all_containers:
        for affected in container.get("affected") or []:
            if not isinstance(affected, dict):
                continue
            vendor = _clean(affected.get("vendor"), 120)
            product = _clean(affected.get("product"), 160)
            if is_unknown_product(product):
                continue
            if is_unknown_product(vendor):
                vendor = "Unknown"
            versions = affected.get("versions") or []
            if not versions:
                versions = [{"version": "Not specified", "status": affected.get("defaultStatus", "affected")}]
            for version_item in versions:
                if not isinstance(version_item, dict):
                    continue
                status = str(version_item.get("status") or "affected").lower()
                if status not in {"affected", "vulnerable", "unknown"}:
                    continue
                version = _clean(version_item.get("version") or "Not specified", 120)
                ranges = []
                if version_item.get("lessThan"):
                    ranges.append(f"< {version_item['lessThan']}")
                if version_item.get("lessThanOrEqual"):
                    ranges.append(f"<= {version_item['lessThanOrEqual']}")
                if version_item.get("versionType"):
                    ranges.append(str(version_item["versionType"]))
                version_range = ", ".join(ranges)
                identity = (vendor.lower(), product.lower(), version.lower(), version_range.lower())
                if identity in seen:
                    continue
                seen.add(identity)
                products.append(
                    {
                        "vendor": vendor,
                        "product": product,
                        "version": version,
                        "vulnerable": True,
                        "version_range": version_range,
                    }
                )
    return products[:100]


def infer_product_from_description(description: str) -> tuple[str, str] | None:
    text = re.sub(r"\s+", " ", description or "").strip()
    oracle_match = re.search(
        r"Vulnerability in the (?P<product>.+?) product of (?P<suite>.+?)(?:\s*\(|\.)",
        text,
        re.IGNORECASE,
    )
    if oracle_match:
        product = _clean(oracle_match.group("product"), 120)
        suite = _clean(oracle_match.group("suite"), 120)
        first_product_word = product.split(" ", 1)[0]
        vendor = first_product_word if first_product_word.lower() in suite.lower() else suite.split(" ", 1)[0]
        if not is_unknown_product(product):
            return vendor.title(), product

    product_match = re.search(
        r"(?:vulnerability|flaw|issue) (?:exists |was found )?in "
        r"(?:the )?(?P<product>[A-Z][A-Za-z0-9_.+ -]{2,80}?) "
        r"(?:before|prior to|versions?|through|allows|could allow|which)",
        text,
    )
    if product_match:
        product = _clean(product_match.group("product"), 120)
        if len(product.split()) <= 8 and not is_unknown_product(product):
            return "Unknown", product
    return None
