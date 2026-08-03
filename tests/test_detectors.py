"""Unit tests for docredact.detectors: positive and negative cases per detector."""

from __future__ import annotations

import random
import time

import pytest

from docredact.detectors import (
    DETECTORS,
    detect_api_keys,
    detect_credit_cards,
    detect_emails,
    detect_high_entropy,
    detect_ibans,
    detect_ipv4,
    detect_jwts,
    detect_pem_keys,
    detect_person_names,
    detect_phones,
    luhn_valid,
    scan_text,
    shannon_entropy,
)

RANDOMISH_32 = "tZ8q3vXw1LpB7yNcKfRd9GhJ2sQmEuA5"
GHP_TOKEN = "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz"
FAKE_JWT = "eyJhbGciOiJub25lIn0.eyJkZW1vIjoidHJ1ZSJ9.c2lnbmF0dXJl"


# --- Luhn ---------------------------------------------------------------

@pytest.mark.parametrize(
    "number", ["4111111111111111", "5555555555554444", "371449635398431"]
)
def test_luhn_accepts_known_test_numbers(number: str) -> None:
    assert luhn_valid(number)


def test_luhn_rejects_wrong_check_digit() -> None:
    assert not luhn_valid("4111111111111112")


@pytest.mark.parametrize("number", ["", "1", "4111a11111111111"])
def test_luhn_rejects_short_or_non_digit(number: str) -> None:
    assert not luhn_valid(number)


# --- Shannon entropy ----------------------------------------------------

def test_entropy_empty_and_single_char_are_zero() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("a") == 0.0


def test_entropy_repeated_char_is_zero() -> None:
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_two_symbol_alternation_is_one_bit() -> None:
    assert shannon_entropy("abab") == pytest.approx(1.0)


def test_entropy_four_uniform_symbols_is_two_bits() -> None:
    assert shannon_entropy("abcd") == pytest.approx(2.0)


# --- Emails -------------------------------------------------------------

def test_detect_emails_positive() -> None:
    text = "write to jane.doe@example.com today"
    ents = detect_emails(text)
    assert [e.value for e in ents] == ["jane.doe@example.com"]
    ent = ents[0]
    assert ent.type == "email"
    assert text[ent.start : ent.end] == ent.value


@pytest.mark.parametrize(
    "text", ["plain text", "user at example dot com", "user@localhost"]
)
def test_detect_emails_negative(text: str) -> None:
    assert detect_emails(text) == []


def test_detect_emails_no_redos_on_adversarial_domain() -> None:
    # Regression: the email regex backtracked quadratically on a long run of
    # "a." labels with no valid TLD, so a ~200 KB block of document text could
    # burn tens of seconds of CPU (denial of service on untrusted input). The
    # bounded pattern must dispatch this in well under a second.
    text = "x@" + "a." * 200_000 + "!"
    start = time.perf_counter()
    result = detect_emails(text)
    elapsed = time.perf_counter() - start
    assert result == []
    assert elapsed < 1.0, f"email detector took {elapsed:.2f}s (possible ReDoS)"


# --- Phones -------------------------------------------------------------

@pytest.mark.parametrize(
    "value", ["+1-555-0142", "(555) 555-0142", "555-0142", "+44 20 5550 0142"]
)
def test_detect_phones_positive(value: str) -> None:
    ents = detect_phones(f"call {value} now")
    assert [e.value for e in ents] == [value]
    assert all(e.type == "phone" for e in ents)


@pytest.mark.parametrize(
    "text", ["2026-07-06", "4111111111111111", "version 1.2.3", "pi is 3.14159"]
)
def test_detect_phones_negative(text: str) -> None:
    assert detect_phones(text) == []


# --- API keys -----------------------------------------------------------

def test_detect_api_keys_aws() -> None:
    ents = detect_api_keys("key AKIAIOSFODNN7EXAMPLE listed")
    assert [(e.type, e.value) for e in ents] == [("api_key", "AKIAIOSFODNN7EXAMPLE")]


def test_detect_api_keys_github_prefixes() -> None:
    gho = "gho_" + "abcdefghijklmnopqrstuvwxyz0123456789"
    ents = detect_api_keys(f"a {GHP_TOKEN} b {gho} c")
    assert [e.value for e in ents] == [GHP_TOKEN, gho]


def test_detect_api_keys_generic_sk_prefix() -> None:
    token = "sk-abcdefghijklmnopqrstuvwx"
    ents = detect_api_keys(f"use {token} here")
    assert [e.value for e in ents] == [token]


def test_detect_api_keys_negative() -> None:
    text = "AKIA123 ghp_tooshort task-abcdefghijklmnopqrstuvwx sk-short"
    assert detect_api_keys(text) == []


def test_detect_api_keys_glued_onto_email_with_no_separator() -> None:
    # Regression: the AKIA pattern was anchored with a leading \b, which only
    # matches at a transition between a word char and a non-word char. When
    # the key is glued directly onto the end of an email address with NO
    # separating whitespace/punctuation at all, the character before "A"
    # ("m" from ".com") is itself a word char, so there is no boundary there
    # and the match silently failed -- a real secret went undetected.
    glued = "jane@example.comAKIAIOSFODNN7EXAMPLE"
    ents = detect_api_keys(glued)
    assert [(e.type, e.value) for e in ents] == [("api_key", "AKIAIOSFODNN7EXAMPLE")]
    ent = ents[0]
    assert glued[ent.start : ent.end] == "AKIAIOSFODNN7EXAMPLE"


def test_scan_text_finds_glued_api_key_through_full_pipeline() -> None:
    # Same glued-token scenario, but through the full scan_text pipeline (the
    # code path a real document goes through, running every built-in
    # detector together): the glued AWS key must still be reported.
    text = "Contact jane@example.comAKIAIOSFODNN7EXAMPLE for access."
    ents = scan_text(text)
    types_and_values = {(e.type, e.value) for e in ents}
    assert ("api_key", "AKIAIOSFODNN7EXAMPLE") in types_and_values


# --- JWTs ---------------------------------------------------------------

def test_detect_jwts_positive() -> None:
    ents = detect_jwts(f"bearer {FAKE_JWT} sent")
    assert [(e.type, e.value) for e in ents] == [("jwt", FAKE_JWT)]


@pytest.mark.parametrize("text", ["file.tar.gz", "a.b.c", "eyJ.x.y"])
def test_detect_jwts_negative(text: str) -> None:
    assert detect_jwts(text) == []


# --- PEM private key headers ---------------------------------------------

@pytest.mark.parametrize(
    "header",
    [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ],
)
def test_detect_pem_keys_positive(header: str) -> None:
    ents = detect_pem_keys(f"{header}\nabc\n")
    assert [(e.type, e.value) for e in ents] == [("pem_key", header)]


@pytest.mark.parametrize(
    "text", ["-----BEGIN PUBLIC KEY-----", "BEGIN PRIVATE KEY"]
)
def test_detect_pem_keys_negative(text: str) -> None:
    assert detect_pem_keys(text) == []


# --- High entropy ---------------------------------------------------------

def test_detect_high_entropy_positive() -> None:
    ents = detect_high_entropy(f"secret {RANDOMISH_32} end")
    assert [e.value for e in ents] == [RANDOMISH_32]
    assert ents[0].type == "high_entropy"


def test_detect_high_entropy_rejects_low_entropy_token() -> None:
    assert detect_high_entropy("a" * 32) == []


def test_detect_high_entropy_rejects_short_token() -> None:
    # High per-char entropy but below the minimum length gate.
    assert detect_high_entropy(RANDOMISH_32[:12]) == []


def test_detect_high_entropy_ignores_plain_prose() -> None:
    assert detect_high_entropy("the quick brown fox jumps over the lazy dog") == []


# --- Credit cards ---------------------------------------------------------

@pytest.mark.parametrize("value", ["4111111111111111", "4111 1111 1111 1111"])
def test_detect_credit_cards_positive(value: str) -> None:
    ents = detect_credit_cards(f"card {value} on file")
    assert [(e.type, e.value) for e in ents] == [("credit_card", value)]


def test_detect_credit_cards_rejects_luhn_invalid() -> None:
    assert detect_credit_cards("card 4111111111111112 on file") == []


@pytest.mark.parametrize("text", ["12345678901234567890", "order 123456789012 done"])
def test_detect_credit_cards_rejects_wrong_lengths(text: str) -> None:
    assert detect_credit_cards(text) == []


# --- IPv4 -----------------------------------------------------------------

@pytest.mark.parametrize("value", ["192.0.2.10", "10.0.0.1", "255.255.255.255"])
def test_detect_ipv4_positive(value: str) -> None:
    ents = detect_ipv4(f"host {value} up")
    assert [(e.type, e.value) for e in ents] == [("ipv4", value)]


def test_detect_ipv4_at_end_of_sentence() -> None:
    ents = detect_ipv4("reply came from 198.51.100.7.")
    assert [e.value for e in ents] == ["198.51.100.7"]


@pytest.mark.parametrize("text", ["999.1.1.1", "1.2.3", "1.2.3.4.5", "1..2.3.4"])
def test_detect_ipv4_negative(text: str) -> None:
    assert detect_ipv4(text) == []


# --- IBAN-shaped ----------------------------------------------------------

def test_detect_ibans_positive() -> None:
    ents = detect_ibans("IBAN GB82WEST12345698765432 listed")
    assert [(e.type, e.value) for e in ents] == [("iban", "GB82WEST12345698765432")]


@pytest.mark.parametrize(
    "text", ["GB82", "gb82west12345698765432", "DEUTSCHE BANK"]
)
def test_detect_ibans_negative(text: str) -> None:
    assert detect_ibans(text) == []


# ISO 13616 says an IBAN is PRINTED in groups of four, so the spaced form is the
# one that turns up on an invoice or a bank letter. Requiring an unbroken run
# found zero of them, and a document the user had been told was safe to share
# went out with the account number verbatim.

@pytest.mark.parametrize(
    "text,expected",
    [
        ("Pay GB82 WEST 1234 5698 7654 32 today", "GB82 WEST 1234 5698 7654 32"),
        ("Pay GB82WEST12345698765432 today", "GB82WEST12345698765432"),
        ("IBAN: DE89 3704 0044 0532 0130 00", "DE89 3704 0044 0532 0130 00"),
        ("IBAN DE89-3704-0044-0532-0130-00 end", "DE89-3704-0044-0532-0130-00"),
    ],
)
def test_detect_ibans_in_printed_groups(text: str, expected: str) -> None:
    from docredact.detectors import Confidence

    ents = detect_ibans(text)
    assert [(e.type, e.value) for e in ents] == [("iban", expected)]
    assert ents[0].confidence is Confidence.HIGH


def test_spaced_iban_does_not_swallow_the_following_words() -> None:
    """Allowing separators makes the pattern greedy; it must trim back."""
    text = "Pay DE89 3704 0044 0532 0130 00 NOW PLEASE THANKS"
    ents = detect_ibans(text)
    assert [e.value for e in ents] == ["DE89 3704 0044 0532 0130 00"]
    assert text[ents[0].start:ents[0].end] == "DE89 3704 0044 0532 0130 00"


def test_spaced_iban_is_absent_from_the_redacted_artifact() -> None:
    """The guarantee the tool actually sells, not merely that it was detected."""
    from docredact.redact import mask_text

    text = "Invoice 42. Pay to GB82 WEST 1234 5698 7654 32 by Friday."
    masked = mask_text(text, detect_ibans(text))

    assert "GB82 WEST 1234 5698 7654 32" not in masked
    assert "7654" not in masked  # no fragment of the account survives
    assert "WEST" not in masked
    assert masked.startswith("Invoice 42. Pay to")
    assert masked.endswith("by Friday.")


# --- Person names (weak heuristic) -----------------------------------------

@pytest.mark.parametrize(
    "value", ["Mr. John Smith", "Dr Jane Roe", "Prof. Ada Example"]
)
def test_detect_person_names_positive(value: str) -> None:
    ents = detect_person_names(f"met {value} today")
    assert [(e.type, e.value) for e in ents] == [("person_name", value)]


@pytest.mark.parametrize(
    "text", ["Mr. john smith", "mr. John Smith", "met Dr. Smith today", "John Smith"]
)
def test_detect_person_names_negative(text: str) -> None:
    assert detect_person_names(text) == []


# --- scan_text ordering and suppression -------------------------------------

def test_scan_text_orders_by_position() -> None:
    ents = scan_text("email jane.doe@example.com phone 555-0142")
    assert [e.type for e in ents] == ["email", "phone"]


def test_scan_text_suppresses_high_entropy_overlapping_api_key() -> None:
    token = "ghp_NotReal9zQ2vXm7Lp4sTk1bNw8rYc3dJh6uZ"
    ents = scan_text(f"token {token} end")
    assert [e.type for e in ents] == ["api_key"]
    # Sanity: on its own the token IS high-entropy, so suppression did the work.
    assert detect_high_entropy(token) != []


def test_scan_text_iban_not_double_counted_as_card() -> None:
    ents = scan_text("IBAN GB82WEST12345698765432")
    assert [e.type for e in ents] == ["iban"]


def test_scan_text_empty() -> None:
    assert scan_text("") == []


def test_scan_text_high_entropy_filter_is_near_linear() -> None:
    # DoS regression: the old filter did any(_overlaps(e, s) for s in specific)
    # inside a loop over every found entity -> O(H * S). On high-entropy-heavy
    # text this scaled quadratically (~0.25 MB/1.3s, ~0.5 MB/5.2s). The merged
    # interval sweep is near-linear, so this ~0.5 MB input must finish well
    # under a second. The bound is generous to stay stable on slow CI, yet far
    # below what the old quadratic path needed.
    random.seed(0)
    alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    parts: list[str] = []
    for i in range(10_000):
        parts.append("".join(random.choice(alnum) for _ in range(28)))  # entropy
        parts.append(f"user{i}@example.com")  # a specific (email) hit
    text = " ".join(parts)
    assert len(text) > 450_000  # the input that previously scaled quadratically
    start = time.perf_counter()
    result = scan_text(text)
    elapsed = time.perf_counter() - start
    assert result  # sanity: it actually found and sorted entities
    assert elapsed < 1.0, f"scan_text took {elapsed:.2f}s (possible quadratic blowup)"


def test_scan_text_high_entropy_suppression_matches_naive() -> None:
    # The near-linear merged-interval filter must be byte-identical to the old
    # nested-loop semantics: a high-entropy hit is dropped iff it overlaps ANY
    # specific hit. Verify against a direct O(H*S) reference on a mixed input.
    text = (
        "token ghp_NotReal9zQ2vXm7Lp4sTk1bNw8rYc3dJh6uZ end "
        "mail jane.doe@example.com IBAN GB82WEST12345698765432 "
        "card 4111111111111111 key AKIAIOSFODNN7EXAMPLE "
        "loose tZ8q3vXw1LpB7yNcKfRd9GhJ2sQmEuA5 tail"
    )
    result = scan_text(text)

    found: list = []
    for detector in DETECTORS:
        found.extend(detector(text))
    specific = [e for e in found if e.type != "high_entropy"]

    def _ov(a, b):  # type: ignore[no-untyped-def]
        return a.start < b.end and b.start < a.end

    reference = sorted(
        (
            e
            for e in found
            if e.type != "high_entropy" or not any(_ov(e, s) for s in specific)
        ),
        key=lambda e: (e.start, e.end, e.type),
    )
    assert result == reference


# A card on a real document is rarely alone: an expiry or CVV follows it, or a
# reference number precedes it. The pattern is greedy across separators, so the
# whole match then failed Luhn and produced ZERO findings - the full PAN went
# into the "safe, shareable" artifact with --redact strict exiting 0.
# detect_ibans had trimmed back since the spaced-IBAN fix; cards had not.

@pytest.mark.parametrize(
    "text,pan",
    [
        ("Card 4111 1111 1111 1111 05/28", "4111111111111111"),
        ("Card 4111 1111 1111 1111 123", "4111111111111111"),
        ("Ref 12 4111 1111 1111 1111", "4111111111111111"),
        ("Card 4111111111111111 alone", "4111111111111111"),
        ("Amex 3782 822463 10005 exp 09/27", "378282246310005"),
    ],
)
def test_no_fragment_of_a_card_survives_redaction(text: str, pan: str) -> None:
    """The guarantee the tool sells, not merely that the detector fired.

    Asserted as "no run of six PAN digits survives" rather than by comparing the
    span, because the correct span is the UNION of every Luhn-valid window: Luhn
    passes by chance about one time in ten, so a neighbouring reference number
    can form a second valid window. Picking between them misaligns the redaction
    and leaves a digit of the real card in the output - the first draft of this
    fix did exactly that.
    """
    import re

    from docredact.redact import mask_text

    ents = detect_credit_cards(text)
    assert ents, f"no card found in {text!r}"
    survived = re.sub(r"\D", "", mask_text(text, ents))
    for i in range(len(pan) - 5):
        assert pan[i : i + 6] not in survived, f"{pan[i:i + 6]} survived redaction"


def test_a_document_with_no_card_is_left_alone() -> None:
    assert detect_credit_cards("Invoice 12345 dated 2026-08-01") == []
