"""Deterministic impact-quality checks for vulnerability reports."""

from __future__ import annotations

import re
from typing import Any


_BROAD_CWES = frozenset({"CWE-20", "CWE-74", "CWE-77", "CWE-200", "CWE-284", "CWE-693"})

_STRONG_IMPACT_PATTERNS = (
    r"\bunauthori[sz]ed\b",
    r"\baccess control\b",
    r"\bauth(?:entication|orization)?\s+bypass\b",
    r"\bprivilege\b",
    r"\badmin\b",
    r"\bcross[- ]tenant\b",
    r"\bdata (?:access|disclosure|exposure|leak|exfiltration)\b",
    r"\bsecret\b",
    r"\bcredential\b",
    r"\baccount takeover\b",
    r"\bstate change\b",
    r"\bmodify\b",
    r"\bdelete\b",
    r"\bwrite\b",
    r"\bssrf\b",
    r"\bfile (?:read|write|disclosure)\b",
    r"\bpath traversal\b",
    r"\bcommand execution\b",
    r"\bcode execution\b",
    r"\brce\b",
    r"\bsql injection\b",
    r"\bxss\b",
    r"\bcross-site scripting\b",
    r"\bdenial of service\b",
    r"\bdos\b",
    r"\bavailability (?:impact|degradation|loss)\b",
    r"\bservice interruption\b",
    r"\bunresponsive",
    r"\bstops? responding\b",
    r"\bsustained\b",
    r"\bworker\b",
    r"\bmemory\b",
    r"\bcpu\b",
    r"\blatency\b",
    r"\bcrash\b",
)

_WEAK_BEHAVIOR_PATTERNS = (
    r"\bnormal validation\b",
    r"\bordinary validation\b",
    r"\bvalidation error\b",
    r"\bframework validation\b",
    r"\b422\b",
    r"\b400\b",
    r"\bbad request\b",
    r"\bunprocessable entity\b",
    r"\bgeneric error\b",
    r"\berror shape\b",
    r"\bempty string\b",
    r"\bmissing field\b",
    r"\bignored field\b",
    r"\bextra field\b",
    r"\bcontent[- ]type\b",
    r"\bparser (?:behavior|default|difference|inconsistency)\b",
)

_AVAILABILITY_PROOF_PATTERNS = (
    r"\bsustained\b",
    r"\brepeated\b",
    r"\bdegradation\b",
    r"\bdowntime\b",
    r"\bworker\b",
    r"\bqueue\b",
    r"\bthread\b",
    r"\bprocess\b",
    r"\bmemory\b",
    r"\bcpu\b",
    r"\blatency\b",
    r"\btimeout\b",
    r"\bcrash\b",
    r"\bhealth[- ]?check\b",
)

_MEASURED_AVAILABILITY_PATTERNS = (
    r"\b\d+(?:\.\d+)?\s*(?:ms|s|sec|secs|seconds|m|minutes)\b",
    r"\b\d+(?:\.\d+)?\s*%\b",
    r"\bcpu\b",
    r"\bmemory\b",
    r"\brss\b",
    r"\blatency\b",
    r"\btimeout\b",
    r"\bhealth[- ]?check\b",
    r"\bstatus\s*(?:code)?\b",
)

# Signals that a PoC script measures impact externally while the attack is active,
# rather than timing the attack request itself.
_AVAILABILITY_SCRIPT_EXTERNAL = (
    r"\bthreading\b",
    r"\bThread\b",
    r"\bconcurrent\b",
    r"\bmultiprocessing\b",
    r"\bdocker\s+stats\b",
    r"\bsubprocess\b",
    r"(?<![&])&(?![&])",  # single & background execution (not &&)
    r"\bcrash(?:es|ed)?\b",
    r"\boom\b",
    r"\bout[- ]of[- ]memory\b",
)


def validate_vulnerability_impact_gate(
    *,
    impact: str,
    evidence: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    assumptions: str,
    counterevidence: str,
    attacker_capability: str | None,
    security_boundary: str | None,
    demonstrated_impact: str | None,
    negative_controls: str | None,
    cvss_breakdown: dict[str, str],
    cwe: str | None,
) -> tuple[list[str], dict[str, Any]]:
    """Validate that a dynamic finding carries bug-bounty-grade impact evidence."""

    fields = {
        "attacker_capability": attacker_capability,
        "security_boundary": security_boundary,
        "demonstrated_impact": demonstrated_impact,
        "negative_controls": negative_controls,
    }
    errors = [
        f"{name} is required for the impact gate - state the concrete fact, not a label"
        for name, value in fields.items()
        if not str(value or "").strip()
    ]

    if cwe and cwe.upper() in _BROAD_CWES:
        errors.append(
            f"{cwe.upper()} is too broad for a confirmed report. Use a specific child CWE "
            "or omit the CWE until the root cause is precise."
        )

    joined = _join(
        impact,
        evidence,
        technical_analysis,
        poc_description,
        poc_script_code,
        assumptions,
        counterevidence,
        *(str(value or "") for value in fields.values()),
    )
    strong_signal = _matches_any(joined, _STRONG_IMPACT_PATTERNS)
    weak_signal = _matches_any(joined, _WEAK_BEHAVIOR_PATTERNS)

    if weak_signal and not strong_signal:
        errors.append(
            "Impact gate failed: the proof appears to show only validation, parser, "
            "content-type, generic error, ignored-field, or formatting behavior. Record "
            "coverage instead unless the same proof crosses a security boundary."
        )

    demonstrated = str(demonstrated_impact or "")
    if not _matches_any(demonstrated, _STRONG_IMPACT_PATTERNS):
        errors.append(
            "demonstrated_impact must name the unauthorized security consequence, such "
            "as data access, unauthorized state change, code/file/network execution, "
            "or sustained availability degradation."
        )

    boundary = str(security_boundary or "")
    if not re.search(r"\b(?:auth|authorization|authentication|tenant|user|role|privilege|"
                     r"trust|server|filesystem|network|database|process|resource|"
                     r"availability|boundary)\b", boundary, re.IGNORECASE):
        errors.append(
            "security_boundary must identify the boundary crossed or exhausted "
            "(auth, tenant/user/role, server-side resource, filesystem, network, "
            "database, process, or equivalent)."
        )

    negative = str(negative_controls or "")
    if not re.search(r"\b(?:baseline|control|benign|negative|compared|ruled out|checked|"
                     r"normal|without|non[- ]?exploit|confirm(?:s|ed|ing)?|"
                     r"isolat(?:es?|ed|ing)|demonstrat(?:es?|ed|ing)|"
                     r"verif(?:ied|ies|y|ying)|rules?\s+out|differential|versus|absent)\b",
                     negative, re.IGNORECASE):
        errors.append(
            "negative_controls must describe the baseline or counter-test that ruled "
            "out normal behavior."
        )

    if cvss_breakdown.get("availability") in {"L", "H"} and not _matches_any(
        joined, _AVAILABILITY_PROOF_PATTERNS
    ):
        errors.append(
            "Availability impact requires measured sustained degradation, resource "
            "exhaustion, crash, timeout, worker/process impact, or health-check failure."
        )
    if cvss_breakdown.get("availability") in {"L", "H"} and not _matches_any(
        joined, _MEASURED_AVAILABILITY_PATTERNS
    ):
        errors.append(
            "Availability impact requires concrete observed measurements such as timing, "
            "CPU, memory, health-check, status-code, timeout, or worker/process evidence."
        )

    if cvss_breakdown.get("availability") in {"L", "H"} and poc_script_code.strip() and not _matches_any(
        poc_script_code, _AVAILABILITY_SCRIPT_EXTERNAL
    ):
        errors.append(
            "Availability proof scripts must demonstrate external impact measurement "
            "while the attack is active: fire the attack in the background ('&'), use "
            "concurrent or parallel requests (threading, multiprocessing), measure "
            "server-side metrics (docker stats, CPU sampling), or trigger a crash/OOM. "
            "Timing the attack request's own response time is not sufficient "
            "availability evidence."
        )

    if not any(cvss_breakdown.get(metric) in {"L", "H"} for metric in (
        "confidentiality",
        "integrity",
        "availability",
    )):
        errors.append(
            "CVSS has no confidentiality, integrity, or availability impact. Record "
            "coverage instead of a vulnerability report."
        )

    decision = {
        "accepted": not errors,
        "attacker_capability": str(attacker_capability or "").strip(),
        "security_boundary": str(security_boundary or "").strip(),
        "demonstrated_impact": str(demonstrated_impact or "").strip(),
        "negative_controls": str(negative_controls or "").strip(),
        "strong_signal": strong_signal,
        "weak_signal": weak_signal,
        "availability_evidence_signal": _matches_any(joined, _AVAILABILITY_PROOF_PATTERNS),
        "availability_measurement_signal": _matches_any(
            joined, _MEASURED_AVAILABILITY_PATTERNS
        ),
        "errors": errors,
    }
    return errors, decision


def _join(*parts: str) -> str:
    return "\n".join(str(part or "") for part in parts)


def _matches_any(text: str, patterns: tuple[str, ...]) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)
