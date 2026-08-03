"""Sensitive-data detectors over extracted text.

Each detector is a small pure function returning ``Entity`` spans. All
matching is heuristic, regex-based, and fully offline; see the README
for per-detector accuracy caveats (the person-name and high-entropy
detectors in particular are intentionally simple and weak).
"""

from __future__ import annotations

import enum
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .policy import Policy

ENTROPY_MIN_LENGTH = 24
ENTROPY_THRESHOLD = 4.0
ENTROPY_STRONG_THRESHOLD = 4.5


class Confidence(str, enum.Enum):
    """How likely a finding is to be a true positive, driven by validators.

    A checksum-validated hit (Luhn card, mod-97 IBAN) or a precise shape
    (email, AKIA key, JWT, PEM header) is high; a plausible-but-loose shape
    (dotted quad that could be a version string) is medium; a deliberately
    weak heuristic (person-name, checksum-failing IBAN) is low.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANKS[self]


_CONFIDENCE_RANKS = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


@dataclass(frozen=True)
class Entity:
    """A detected sensitive-looking span inside one block of text."""

    type: str
    value: str
    start: int
    end: int
    confidence: Confidence = Confidence.HIGH


def _entities(
    pattern: re.Pattern[str], text: str, type_: str, confidence: Confidence = Confidence.HIGH
) -> list[Entity]:
    return [
        Entity(type_, m.group(), m.start(), m.end(), confidence) for m in pattern.finditer(text)
    ]


def luhn_valid(number: str) -> bool:
    """Return True if ``number`` (digits only, length >= 2) passes Luhn."""
    if len(number) < 2 or not number.isascii() or not number.isdigit():
        return False
    total = 0
    for i, char in enumerate(reversed(number)):
        digit = ord(char) - 48
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def shannon_entropy(text: str) -> float:
    """Shannon entropy of ``text`` in bits per character (0.0 if len < 2)."""
    if len(text) < 2:
        return 0.0
    size = len(text)
    return -sum(
        (count / size) * math.log2(count / size) for count in Counter(text).values()
    )


_IBAN_MAX_LENGTH = 34  # ISO 13616: no real IBAN is longer than 34 characters


def iban_mod97_valid(iban: str) -> bool:
    """Return True if ``iban`` (no separators) passes the ISO 7064 mod-97 check.

    Each character of the rearranged string (body + first four chars) is mapped
    A=10..Z=35 and the running value must be 1 mod 97. The remainder is folded
    incrementally rather than built into one giant ``int`` -- a user detector
    with this validator can match an arbitrarily long run, and CPython raises on
    int() conversions past 4300 digits, so the naive form was a crash/DoS vector.
    Anything longer than a real IBAN cannot be one, so it fails fast.
    """
    if len(iban) < 5 or len(iban) > _IBAN_MAX_LENGTH or not iban.isascii() or not iban.isalnum():
        return False
    rearranged = (iban[4:] + iban[:4]).upper()
    remainder = 0
    for char in rearranged:
        chunk = str(ord(char) - 55) if char.isalpha() else char
        for digit in chunk:
            remainder = (remainder * 10 + (ord(digit) - 48)) % 97
    return remainder == 1


# Segment lengths are bounded (RFC 5321: local <= 64, labels <= 63, and a
# capped label count) so matching stays linear. The unbounded original
# (``[A-Za-z0-9.-]+\.[A-Za-z]{2,}``) backtracked quadratically on adversarial
# input like ``x@a.a.a...`` with no valid TLD, letting a ~200 KB block of
# document text burn seconds of CPU (ReDoS / denial of service).
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,10}"
    r"\.[A-Za-z]{2,24}\b"
)

_PHONE_PATTERNS = (
    re.compile(r"\+\d{1,3}(?:[-. ]\d{2,4}){2,4}(?!\d)"),
    re.compile(r"(?:\(\d{3}\) ?|(?<![\d.(-])\d{3}[-. ])\d{3}[-. ]\d{4}(?![\d-])"),
    re.compile(r"(?<![\d.(-])\d{3}[-.]\d{4}(?![\d.-])"),
)

# No leading \b: a word-boundary assertion only fires at a transition
# between a word char and a non-word char, so a real secret glued directly
# onto the end of another word with NO separator at all (e.g.
# "jane@example.comAKIAIOSFODNN7EXAMPLE" -- both "m" and "A" are word chars,
# so there is no transition there) silently failed to match. AKIA and
# gh[po]_ are distinctive, fixed-case literal prefixes, so dropping the
# leading \b and matching them anywhere in the text does not create
# meaningful false positives; the trailing boundary is kept so a match still
# cannot swallow extra trailing characters from a longer run.
#
# "sk-" is NOT changed the same way: it is only two letters and a hyphen, so
# it turns up as an accidental tail of ordinary words (e.g. "task-..." ends
# in "sk-..."). It keeps its negative lookbehind, which still has the same
# theoretical glued-token gap as \b, but loosening it creates real false
# positives (verified: it started matching inside "task-abcdefghijklmnopqrstuvwx",
# the project's own negative-test fixture, which exists specifically to catch
# a change like this).
_API_KEY_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}(?![A-Za-z0-9])"),
    re.compile(r"gh[po]_[A-Za-z0-9]{36}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}"),
)

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{3,}\b")

_PEM_RE = re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----")

_TOKEN_RE = re.compile(rf"[A-Za-z0-9+/=_-]{{{ENTROPY_MIN_LENGTH},}}")

_CARD_RE = re.compile(r"(?<![\w-])\d(?:[ -]?\d){12,18}(?![\w-])")

_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")

# ISO 13616 says an IBAN is PRINTED in groups of four, and that is the form it
# arrives in on an invoice or a bank letter. Requiring an unbroken run therefore
# missed the common case entirely: "GB82 WEST 1234 5698 7654 32" produced zero
# findings, so --write-redacted copied it out verbatim and --redact strict exited
# 0 on a document the user had been told was safe to share. Separators are now
# allowed between characters, exactly as _CARD_RE already allows them.
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]){11,30}\b")

_IBAN_SEPARATORS = re.compile(r"[ -]")

_NAME_RE = re.compile(r"\b(?:Mrs|Mr|Ms|Mx|Dr|Prof)\.?\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b")


def detect_emails(text: str) -> list[Entity]:
    """Detect email addresses (requires a dotted TLD, so user@localhost is skipped)."""
    return _entities(_EMAIL_RE, text, "email")


def detect_phones(text: str) -> list[Entity]:
    """Detect phone numbers: +intl with separators, US (xxx) xxx-xxxx, and xxx-xxxx.

    Requires separators, which keeps dates, versions, and card numbers out;
    unformatted digit runs like +15550142 are missed by design.
    """
    spans: list[tuple[int, int, str]] = []
    for pattern in _PHONE_PATTERNS:
        for m in pattern.finditer(text):
            if 7 <= sum(char.isdigit() for char in m.group()) <= 15:
                spans.append((m.start(), -m.end(), m.group()))
    out: list[Entity] = []
    last_end = -1
    for start, _neg_end, value in sorted(spans):
        if start >= last_end:
            out.append(Entity("phone", value, start, start + len(value)))
            last_end = start + len(value)
    return out


def detect_api_keys(text: str) -> list[Entity]:
    """Detect API-key-shaped strings: AWS AKIA..., GitHub ghp_/gho_..., generic sk-..."""
    out: list[Entity] = []
    for pattern in _API_KEY_PATTERNS:
        out.extend(_entities(pattern, text, "api_key"))
    return sorted(out, key=lambda e: e.start)


def detect_jwts(text: str) -> list[Entity]:
    """Detect JWT-shaped tokens: three base64url segments, header starting with eyJ."""
    return _entities(_JWT_RE, text, "jwt")


def detect_pem_keys(text: str) -> list[Entity]:
    """Detect PEM private-key BEGIN headers (RSA/EC/OPENSSH/unlabelled)."""
    return _entities(_PEM_RE, text, "pem_key")


def detect_high_entropy(text: str) -> list[Entity]:
    """Detect tokens of >= 24 chars with Shannon entropy >= 4.0 bits/char.

    Deliberately blunt: random-looking identifiers and long mixed-case
    names can false-positive, and hex-only secrets (max 4 bits/char) can
    slip under the threshold. Documented in the README. Confidence scales
    with entropy: >= 4.5 bits/char is medium, the 4.0-4.5 band is low.
    """
    out: list[Entity] = []
    for m in _TOKEN_RE.finditer(text):
        entropy = shannon_entropy(m.group())
        if entropy >= ENTROPY_THRESHOLD:
            confidence = (
                Confidence.MEDIUM if entropy >= ENTROPY_STRONG_THRESHOLD else Confidence.LOW
            )
            out.append(Entity("high_entropy", m.group(), m.start(), m.end(), confidence))
    return out


def detect_credit_cards(text: str) -> list[Entity]:
    """Detect 13-19 digit card-shaped numbers (space/dash separators) passing Luhn.

    Detection is already gated on the Luhn checksum, so every hit is high
    confidence by construction.
    """
    out: list[Entity] = []
    for m in _CARD_RE.finditer(text):
        span = _first_luhn_span(m.group())
        if span is None:
            continue
        a, b = span
        out.append(
            Entity("credit_card", m.group()[a:b], m.start() + a, m.start() + b, Confidence.HIGH)
        )
    return out


def _first_luhn_span(chunk: str) -> tuple[int, int] | None:
    """Offsets of the longest Luhn-valid 13-19 digit card inside ``chunk``.

    The pattern is greedy across separators and a card has no prefix anchor, so a
    match routinely carries more than the card: an expiry or a CVV printed after
    it, or a reference number printed before. Requiring the WHOLE match to pass
    Luhn therefore returned nothing at all for the commonest real layouts -
    ``4111 1111 1111 1111 05/28`` yielded zero findings and the full PAN went
    straight into the "safe, shareable" artifact with ``--redact strict`` exiting
    0. Failing to find is the one direction this tool must never fail in.

    detect_ibans has trimmed back like this since the spaced-IBAN fix; the card
    detector was left as the odd one out.

    Returns the UNION of every valid window rather than picking one. Luhn passes
    by chance about one time in ten, so a run like "Ref 12 4111 1111 1111 1111"
    contains a coincidentally-valid 19-digit window starting one group early as
    well as the real 16-digit card. Choosing between them misaligns the span and
    leaves a digit of the real PAN outside the redaction - the first draft of
    this function did exactly that, redacting "12 4111 1111 1111 111" and
    printing the final "1". Over-redacting a neighbouring reference number is a
    cosmetic loss; leaking one digit of a card is not.

    Candidate spans are taken at PRINTED GROUP boundaries only, never at
    arbitrary digit offsets. Luhn passes by chance about one time in ten, and a
    16-digit run contains roughly ten sub-windows, so scanning every offset makes
    a majority of ordinary long numbers - order numbers, references - look like
    cards. Requiring a candidate to start and end on the separators the document
    actually prints removes that: a coincidental hit must also align with the
    grouping. A compact run has one group, so only the whole run is considered,
    and a Luhn-invalid 16-digit number is still rejected outright.
    """
    groups = list(re.finditer(r"\d+", chunk))
    if not groups:
        return None
    lo: int | None = None
    hi: int | None = None
    for a in range(len(groups)):
        for b in range(a + 1, len(groups) + 1):
            run = "".join(g.group() for g in groups[a:b])
            if not 13 <= len(run) <= 19:
                continue
            if luhn_valid(run):
                start, end = groups[a].start(), groups[b - 1].end()
                lo = start if lo is None else min(lo, start)
                hi = end if hi is None else max(hi, end)
    return None if lo is None or hi is None else (lo, hi)


def detect_ipv4(text: str) -> list[Entity]:
    """Detect dotted-quad IPv4 addresses with all octets in 0-255.

    Medium confidence: version-like dotted quads (e.g. 10.2.3.4 in a version
    string) satisfy the same shape.
    """
    return [
        Entity("ipv4", m.group(), m.start(), m.end(), Confidence.MEDIUM)
        for m in _IPV4_RE.finditer(text)
        if all(int(octet) <= 255 for octet in m.group().split("."))
    ]


def iban_compact(value: str) -> str:
    """An IBAN with its printing separators removed, ready for the checksum."""
    return _IBAN_SEPARATORS.sub("", value)


def detect_ibans(text: str) -> list[Entity]:
    """Detect IBAN-shaped strings, printed in groups or as one run.

    Every shape hit is still reported (honest heuristic), but the ISO 7064
    mod-97 checksum drives confidence: passing = high, failing = low. The
    checksum can only RAISE confidence, never hide a finding.

    Because separators are permitted, the pattern is greedy enough to run past
    the end of an IBAN and into an adjacent capitalised word, which would both
    break the checksum and over-redact the following text. So each match is
    trimmed from the right until the checksum validates; if none does, the whole
    span is still reported, at low confidence, since suppressing a possible
    account number is the one thing this must never do.
    """
    out: list[Entity] = []
    for m in _IBAN_RE.finditer(text):
        value = m.group()
        candidate = value
        while len(iban_compact(candidate)) >= 5:
            if iban_mod97_valid(iban_compact(candidate)):
                value = candidate.rstrip(" -")
                break
            candidate = candidate[:-1]
        out.append(
            Entity(
                "iban",
                value,
                m.start(),
                m.start() + len(value),
                Confidence.HIGH if iban_mod97_valid(iban_compact(value)) else Confidence.LOW,
            )
        )
    return out


def detect_person_names(text: str) -> list[Entity]:
    """Detect Honorific + two capitalized words, e.g. "Mr. John Smith".

    A deliberately weak heuristic: it misses bare names entirely and can
    match non-names ("Dr Pepper Cola"). Treat as a hint, not a guarantee --
    hence low confidence.
    """
    return _entities(_NAME_RE, text, "person_name", Confidence.LOW)


DETECTORS = (
    detect_emails,
    detect_phones,
    detect_api_keys,
    detect_jwts,
    detect_pem_keys,
    detect_credit_cards,
    detect_ipv4,
    detect_ibans,
    detect_person_names,
    detect_high_entropy,
)

# Type name -> detector, so a policy can disable built-ins by name.
DETECTORS_BY_NAME = {
    "email": detect_emails,
    "phone": detect_phones,
    "api_key": detect_api_keys,
    "jwt": detect_jwts,
    "pem_key": detect_pem_keys,
    "credit_card": detect_credit_cards,
    "ipv4": detect_ipv4,
    "iban": detect_ibans,
    "person_name": detect_person_names,
    "high_entropy": detect_high_entropy,
}


def _merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge half-open [start, end) intervals into a sorted, disjoint list."""
    if not spans:
        return []
    ordered = sorted(spans)
    merged: list[tuple[int, int]] = [ordered[0]]
    for start, end in ordered[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:  # overlapping or touching -> extend
            if end > last_end:
                merged[-1] = (last_start, end)
        else:
            merged.append((start, end))
    return merged


def _contained(merged: list[tuple[int, int]], start: int, end: int) -> bool:
    """True if [start, end) is FULLY inside one interval of the disjoint sorted list.

    Binary-search for the first interval that could contain it, making the whole
    filter O((H + S) log S) instead of an O(H * S) nested scan. Containment (not
    mere overlap) is deliberate: a high-entropy token that merely brushes a
    specific hit but extends beyond it is NOT the same finding -- dropping it
    would silently un-report a suspected secret whose tail no other entity
    covers.
    """
    lo, hi = 0, len(merged)
    while lo < hi:  # first interval whose end > start
        mid = (lo + hi) // 2
        if merged[mid][1] <= start:
            lo = mid + 1
        else:
            hi = mid
    return lo < len(merged) and merged[lo][0] <= start and end <= merged[lo][1]


def _run_user_detectors(text: str, policy: Policy) -> list[Entity]:
    """Run the policy's custom detectors; a validator drives confidence, never hides."""
    out: list[Entity] = []
    for detector in policy.detectors:
        for m in detector.pattern.finditer(text):
            confidence = detector.confidence
            if detector.validator == "luhn":
                # Validate the digit sequence inside the match, so a user pattern
                # may include a label prefix without breaking the checksum.
                digits = re.sub(r"\D", "", m.group())
                confidence = Confidence.HIGH if luhn_valid(digits) else Confidence.LOW
            elif detector.validator == "iban_mod97":
                confidence = (
                    Confidence.HIGH if iban_mod97_valid(m.group()) else Confidence.LOW
                )
            out.append(Entity(detector.name, m.group(), m.start(), m.end(), confidence))
    return out


def _allowed(entity: Entity, policy: Policy) -> bool:
    """True if the policy allowlists this value (exact or full-value pattern match)."""
    if entity.value in policy.allow_values:
        return True
    return any(pattern.fullmatch(entity.value) for pattern in policy.allow_patterns)


def scan_text(text: str, policy: Policy | None = None) -> list[Entity]:
    """Run every detector; drop high-entropy hits that overlap a specific hit.

    An optional policy disables built-ins by name, adds user detectors, and
    allowlists values (allowlisting only ever REMOVES findings). Result is
    sorted by (start, end, type) for deterministic output.
    """
    found: list[Entity] = []
    for name, detector in DETECTORS_BY_NAME.items():
        if policy is not None and name in policy.disabled:
            continue
        found.extend(detector(text))
    if policy is not None:
        found.extend(_run_user_detectors(text, policy))
    # Merge the specific (non-high-entropy) spans once, then binary-search each
    # high-entropy candidate against them: a candidate FULLY CONTAINED in a
    # specific hit is that hit (e.g. a JWT segment matching the token regex)
    # and is dropped; one extending beyond stays reported. Near-linear, so a
    # ~0.5 MB block of high-entropy-heavy text no longer costs tens of seconds.
    specific = _merge_spans(
        [(e.start, e.end) for e in found if e.type != "high_entropy"]
    )
    kept = [
        e
        for e in found
        if e.type != "high_entropy" or not _contained(specific, e.start, e.end)
    ]
    if policy is not None and (policy.allow_values or policy.allow_patterns):
        kept = [e for e in kept if not _allowed(e, policy)]
    return sorted(kept, key=lambda e: (e.start, e.end, e.type))
