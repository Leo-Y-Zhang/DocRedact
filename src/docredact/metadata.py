"""Curated per-detector severity and reference metadata.

One reviewed place mapping every built-in detector type to how bad a leak of that kind
usually is, plus the closest CWE reference. Severity is about the *category* (an exposed
private key outranks an exposed IP address); per-finding trustworthiness is the separate
``confidence`` field. Custom policy detectors default to medium / "custom rule".
"""

from __future__ import annotations

import enum


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANKS[self]


_SEVERITY_RANKS = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}

SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)

# type -> (severity, reference). References are the closest-fit CWE for the leak class.
DETECTOR_METADATA: dict[str, tuple[Severity, str]] = {
    "pem_key": (Severity.CRITICAL, "CWE-798 hardcoded credentials"),
    "api_key": (Severity.CRITICAL, "CWE-798 hardcoded credentials"),
    "jwt": (Severity.HIGH, "CWE-522 insufficiently protected credentials"),
    "high_entropy": (Severity.MEDIUM, "CWE-312 cleartext storage (suspected secret)"),
    "credit_card": (Severity.HIGH, "CWE-312 cleartext storage of card data (PCI)"),
    "iban": (Severity.MEDIUM, "CWE-359 privacy violation (financial identifier)"),
    "email": (Severity.LOW, "CWE-359 privacy violation (contact PII)"),
    "phone": (Severity.LOW, "CWE-359 privacy violation (contact PII)"),
    "person_name": (Severity.LOW, "CWE-359 privacy violation (personal name)"),
    "ipv4": (Severity.LOW, "CWE-200 information exposure (network layout)"),
}

CUSTOM_DETECTOR_METADATA: tuple[Severity, str] = (Severity.MEDIUM, "custom rule")


def metadata_for(type_: str) -> tuple[Severity, str]:
    """Severity + reference for a detector type (custom rules get the default)."""
    return DETECTOR_METADATA.get(type_, CUSTOM_DETECTOR_METADATA)
