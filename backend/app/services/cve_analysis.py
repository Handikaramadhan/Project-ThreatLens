import re
from dataclasses import dataclass

from app.schemas.cves import CVSSMetrics, ExploitabilityAnalysis, MitreTechniqueMapping, RootCauseAnalysis


@dataclass(frozen=True)
class WeaknessDefinition:
    name: str
    summary: str
    category: str


WEAKNESSES = {
    "CWE-20": WeaknessDefinition(
        "Improper Input Validation",
        "The product does not correctly validate attacker-controlled input before processing it.",
        "Input validation",
    ),
    "CWE-22": WeaknessDefinition(
        "Path Traversal",
        "Path input is not constrained to an intended directory, allowing access outside the permitted path.",
        "File access control",
    ),
    "CWE-78": WeaknessDefinition(
        "OS Command Injection",
        "Attacker-controlled input can reach an operating-system command without sufficient neutralization.",
        "Command injection",
    ),
    "CWE-79": WeaknessDefinition(
        "Cross-site Scripting",
        "Untrusted input is included in web output without context-appropriate encoding or sanitization.",
        "Output encoding",
    ),
    "CWE-89": WeaknessDefinition(
        "SQL Injection",
        "Attacker-controlled input can alter the structure of a database query.",
        "Injection",
    ),
    "CWE-120": WeaknessDefinition(
        "Classic Buffer Overflow",
        "Data is copied into a fixed-size buffer without adequately checking its bounds.",
        "Memory safety",
    ),
    "CWE-200": WeaknessDefinition(
        "Exposure of Sensitive Information",
        "The product exposes information to an actor who is not explicitly authorized to receive it.",
        "Information disclosure",
    ),
    "CWE-287": WeaknessDefinition(
        "Improper Authentication",
        "The product does not correctly verify the identity claimed by a user or remote component.",
        "Authentication",
    ),
    "CWE-306": WeaknessDefinition(
        "Missing Authentication for Critical Function",
        "A security-sensitive function can be reached without authentication.",
        "Authentication",
    ),
    "CWE-362": WeaknessDefinition(
        "Race Condition",
        "Concurrent operations can reach an unsafe state because shared resources are not synchronized correctly.",
        "Concurrency",
    ),
    "CWE-416": WeaknessDefinition(
        "Use After Free",
        "The product continues using memory after it has been released.",
        "Memory safety",
    ),
    "CWE-434": WeaknessDefinition(
        "Unrestricted Upload of Dangerous File",
        "Uploaded file type or destination is not sufficiently restricted before the file is stored or executed.",
        "File upload",
    ),
    "CWE-502": WeaknessDefinition(
        "Deserialization of Untrusted Data",
        "Untrusted serialized data is reconstructed without sufficient validation or type restrictions.",
        "Unsafe deserialization",
    ),
    "CWE-787": WeaknessDefinition(
        "Out-of-bounds Write",
        "The product writes data beyond the intended memory buffer boundary.",
        "Memory safety",
    ),
    "CWE-798": WeaknessDefinition(
        "Use of Hard-coded Credentials",
        "A credential embedded in the product can be recovered or reused by an attacker.",
        "Credential management",
    ),
    "CWE-862": WeaknessDefinition(
        "Missing Authorization",
        "The product does not perform an authorization check before a protected action.",
        "Authorization",
    ),
    "CWE-918": WeaknessDefinition(
        "Server-Side Request Forgery",
        "Attacker-controlled input can make the server send requests to unintended destinations.",
        "Request routing",
    ),
}

DESCRIPTION_PATTERNS = (
    (r"\bsql injection\b", "CWE-89"),
    (r"\b(command|os command) injection\b", "CWE-78"),
    (r"\bcross[- ]site scripting\b|\bxss\b", "CWE-79"),
    (r"\bpath traversal\b|\bdirectory traversal\b", "CWE-22"),
    (r"\bserver[- ]side request forgery\b|\bssrf\b", "CWE-918"),
    (r"\bdeseriali[sz]ation\b", "CWE-502"),
    (r"\buse[- ]after[- ]free\b", "CWE-416"),
    (r"\bout[- ]of[- ]bounds write\b", "CWE-787"),
    (r"\bbuffer overflow\b", "CWE-120"),
    (r"\bauthentication bypass\b|\bimproper authentication\b", "CWE-287"),
    (r"\bmissing authentication\b|\bunauthenticated attacker\b", "CWE-306"),
    (r"\bunrestricted file upload\b", "CWE-434"),
    (r"\brace condition\b", "CWE-362"),
    (r"\binformation disclosure\b|\bsensitive information\b", "CWE-200"),
)


def _weakness_ids(weaknesses: list[str], description: str) -> tuple[list[str], str]:
    ids = []
    for item in weaknesses:
        match = re.search(r"CWE-\d+", str(item), re.IGNORECASE)
        if match:
            identifier = match.group(0).upper()
            if identifier not in ids:
                ids.append(identifier)
    if ids:
        return ids, "NVD/CNA weakness classification"
    lowered = description.lower()
    for pattern, identifier in DESCRIPTION_PATTERNS:
        if re.search(pattern, lowered, re.IGNORECASE):
            return [identifier], "Description keyword heuristic"
    return [], "Insufficient public root-cause evidence"


def build_root_cause(description: str, weaknesses: list[str]) -> RootCauseAnalysis:
    ids, basis = _weakness_ids(weaknesses, description)
    definition = next((WEAKNESSES[item] for item in ids if item in WEAKNESSES), None)
    if definition:
        return RootCauseAnalysis(
            category=definition.category,
            summary=definition.summary,
            weaknesses=ids,
            basis=basis,
            confidence="High" if basis.startswith("NVD") else "Medium",
        )
    if ids:
        return RootCauseAnalysis(
            category="Software weakness",
            summary=(
                f"The source classifies this vulnerability as {', '.join(ids)}, "
                "but does not disclose enough implementation detail for a more specific root-cause statement."
            ),
            weaknesses=ids,
            basis=basis,
            confidence="Medium",
        )
    return RootCauseAnalysis(
        category="Undisclosed",
        summary=(
            "NVD/CNA describes the impact and exploit conditions but does not provide "
            "enough evidence to determine the implementation-level root cause."
        ),
        weaknesses=[],
        basis=basis,
        confidence="Low",
    )


def build_mitre_mapping(
    description: str,
    weaknesses: list[str],
    cvss: CVSSMetrics | None,
) -> list[MitreTechniqueMapping]:
    ids, _ = _weakness_ids(weaknesses, description)
    lowered = description.lower()
    mappings: list[MitreTechniqueMapping] = []

    def add(technique_id: str, name: str, tactic: str, rationale: str, confidence: str) -> None:
        if any(item.technique_id == technique_id for item in mappings):
            return
        mappings.append(
            MitreTechniqueMapping(
                technique_id=technique_id,
                name=name,
                tactic=tactic,
                rationale=rationale,
                confidence=confidence,
                url=f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
            )
        )

    attack_vector = cvss.attack_vector.lower() if cvss else ""
    user_interaction = cvss.user_interaction.lower() if cvss else ""
    client_terms = ("browser", "office", "document", "pdf", "client application")
    if user_interaction not in {"", "none", "unknown"} or any(term in lowered for term in client_terms):
        add(
            "T1203",
            "Exploitation for Client Execution",
            "Execution",
            "The exploit path involves a user-facing client application or user interaction.",
            "Medium",
        )
    elif attack_vector == "network" or any(term in lowered for term in ("remote attacker", "network access", "http")):
        add(
            "T1190",
            "Exploit Public-Facing Application",
            "Initial Access",
            "A network-reachable vulnerable service could be targeted for initial access.",
            "Medium",
        )

    if any(item in ids for item in ("CWE-78", "CWE-77", "CWE-94")) or "command execution" in lowered:
        add(
            "T1059",
            "Command and Scripting Interpreter",
            "Execution",
            "Successful exploitation may enable attacker-controlled commands or scripts.",
            "Medium",
        )
    if "CWE-798" in ids or "default credential" in lowered or "hard-coded credential" in lowered:
        add(
            "T1078",
            "Valid Accounts",
            "Initial Access / Persistence",
            "Recovered or default credentials may be used to access the affected system.",
            "Medium",
        )
    if any(item in ids for item in ("CWE-22", "CWE-200")) and any(
        term in lowered for term in ("read", "disclosure", "expose", "file")
    ):
        add(
            "T1005",
            "Data from Local System",
            "Collection",
            "The vulnerability may permit collection of local files or exposed system data.",
            "Low",
        )
    return mappings[:4]


def build_exploitability_analysis(
    *,
    description: str,
    weaknesses: list[str],
    cvss: CVSSMetrics | None,
    known_exploited: bool,
    has_public_references: bool,
    related_news_count: int,
) -> ExploitabilityAnalysis:
    ids, weakness_basis = _weakness_ids(weaknesses, description)
    lowered = description.lower()
    prerequisites: list[str] = []
    path: list[str] = []
    signals: list[str] = []
    notes: list[str] = []
    basis: list[str] = []
    score = 0

    if known_exploited:
        score += 4
        signals.append("CISA KEV atau NVD menandai eksploitasi aktif.")
        basis.append("Known exploited flag")
    if cvss:
        if cvss.attack_vector.lower() == "network":
            score += 2
            prerequisites.append("Target service reachable over network.")
            path.append("Attacker reaches the vulnerable network-exposed component.")
        if cvss.attack_complexity.lower() == "low":
            score += 1
            prerequisites.append("No unusual race/timing/environment condition required.")
        if cvss.privileges_required.lower() in {"none", "no privileges required"}:
            score += 1
            prerequisites.append("Authentication may not be required.")
        if cvss.user_interaction.lower() not in {"none", "", "unknown"}:
            prerequisites.append("A user interaction step may be required.")
            path.append("Attacker delivers malicious content or link to a user.")
        if cvss.exploitability_score is not None and cvss.exploitability_score >= 3:
            score += 1
            signals.append(f"CVSS exploitability score is {cvss.exploitability_score}.")
        basis.append("CVSS vector")

    if any(item in ids for item in ("CWE-78", "CWE-89", "CWE-502", "CWE-787", "CWE-416", "CWE-434", "CWE-918")):
        score += 1
        signals.append(f"High-abuse weakness class: {', '.join(ids)}.")
        basis.append(weakness_basis)
    if has_public_references:
        score += 1
        signals.append("Public advisory/reference material is available.")
        basis.append("Reference tags")
    if related_news_count:
        score += 1
        signals.append(f"{related_news_count} related intelligence item(s) mention this CVE.")
        basis.append("Threat news correlation")
    if any(term in lowered for term in ("remote code execution", "rce", "command execution", "authentication bypass")):
        score += 1
        path.append("Exploit impact may directly reach code execution or protected-function bypass.")

    if not path:
        path.append("Exploit path is not public enough to describe beyond the CVSS conditions.")
    if any(item in ids for item in ("CWE-78", "CWE-89", "CWE-502")):
        notes.append("Prioritize logs around input-bearing endpoints and abnormal process/database activity.")
    if cvss and cvss.attack_vector.lower() == "network":
        notes.append("Check internet-exposed assets and edge controls before internal-only systems.")
    if known_exploited:
        notes.append("Treat matching assets as urgent until patched, isolated, or explicitly accepted.")
    if not notes:
        notes.append("Use vendor advisory and CVSS conditions to define detection scope.")

    if score >= 7:
        likelihood, confidence = "Very high", "High"
    elif score >= 5:
        likelihood, confidence = "High", "Medium"
    elif score >= 3:
        likelihood, confidence = "Medium", "Medium"
    elif score >= 1:
        likelihood, confidence = "Low", "Low"
    else:
        likelihood, confidence = "Unknown", "Low"

    return ExploitabilityAnalysis(
        likelihood=likelihood,
        confidence=confidence,
        prerequisites=prerequisites or ["Prerequisites are not disclosed by public sources."],
        likely_attack_path=path,
        exploitation_signals=signals or ["No public exploitation signal is cached yet."],
        defensive_notes=notes,
        basis=sorted(set(basis)) or ["Local cache"],
    )
