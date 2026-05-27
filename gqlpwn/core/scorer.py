"""Lightweight CVSS-inspired severity scoring for findings."""

from __future__ import annotations

from gqlpwn.utils.models import Finding, SeverityLevel

# Base scores per severity band
_SEVERITY_BASE: dict[str, float] = {
    "critical": 9.5,
    "high":     7.5,
    "medium":   5.0,
    "low":      2.5,
    "info":     0.0,
}

# Modifiers that raise or lower the base score
_MODIFIER_AUTH_REQUIRED = -1.0      # harder to exploit if auth needed
_MODIFIER_NETWORK_ACCESSIBLE = +0.5  # worse if no auth at all
_MODIFIER_DATA_EXPOSURE = +0.5       # findings that expose data are worse
_MODIFIER_AGGRESSIVE_MODULE = -0.5   # dos-style — impact is real but exploitability limited

# Modules where data exposure is the primary impact
_DATA_EXPOSURE_MODULES = {"info_disclosure", "bola", "injection"}
_AGGRESSIVE_MODULES = {"dos"}


def score(finding: Finding) -> float:
    """Return a 0.0–10.0 CVSS-lite score for a finding."""
    base = _SEVERITY_BASE.get(finding.severity, 0.0)
    if base == 0.0:
        return 0.0  # Informational — modifiers don't change risk category
    modifier = 0.0

    if finding.module in _DATA_EXPOSURE_MODULES:
        modifier += _MODIFIER_DATA_EXPOSURE

    if finding.module in _AGGRESSIVE_MODULES:
        modifier += _MODIFIER_AGGRESSIVE_MODULE

    # Evidence of no-auth access bumps the score
    evidence_lower = finding.evidence.lower()
    if any(kw in evidence_lower for kw in ("unauthenticated", "no auth", "without authentication")):
        modifier += _MODIFIER_NETWORK_ACCESSIBLE

    return max(0.0, min(10.0, round(base + modifier, 1)))


def assign_scores(findings: list[Finding]) -> list[Finding]:
    """Mutate findings in place with computed CVSS scores, return them."""
    for f in findings:
        f.cvss_score = score(f)
    return findings


def severity_from_score(cvss: float) -> SeverityLevel:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0.0:
        return "low"
    return "info"
