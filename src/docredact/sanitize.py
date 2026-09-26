"""Sanitized-artifact generation: a safe, shareable copy of the document.

Where ``--redact mask`` rewrites the JSON report, ``--write-redacted PATH`` produces the
artifact people actually want to share: the document's text with every finding replaced by
a **consistent token**. The same value always becomes the same token across the whole
document (every occurrence of one email is ``[EMAIL_1]``, a second distinct email is
``[EMAIL_2]``), so cross-references survive sanitization -- a reader can still tell that two
paragraphs mention the same account without learning what it is.

Alongside the text, a redaction manifest lists every token with its type and occurrence
count. The manifest never contains a raw value; it is safe to share with the artifact.

The artifact is a deterministic plain-text rendering built from the extracted blocks
(paragraphs / sections / rows / elements / pages), not a binary round-trip: extraction
already normalizes whitespace, CSV quoting, and HTML markup, and PDF/DOCX cannot be
rebuilt from text. This is documented behaviour, not a limitation smuggled in silently.
"""

from __future__ import annotations

from .detectors import Entity
from .extractors import Block
from .redact import select_replacements

# Block kinds that are scanned and reported but never rendered into the artifact.
# They hold text a reader of the document does not see as its content - what the
# author deleted with Track Changes, review comments and notes - and the artifact is
# the copy that gets shared. Rendering them would hand the recipient exactly what
# the detectors cannot recognise (names, salaries, free text) from the part of the
# file the author meant to remove.
HIDDEN_KINDS = frozenset({"deletion", "comment", "annotation", "metadata", "link", "alt_text"})


def rendered_blocks(blocks: list[Block]) -> list[Block]:
    """The blocks the artifact is built from: every block except the hidden kinds."""
    return [b for b in blocks if b.kind not in HIDDEN_KINDS]


def _token_prefix(type_: str) -> str:
    return type_.upper()


def assign_tokens(
    blocks: list[Block], entities_by_block: dict[int, list[Entity]]
) -> tuple[dict[tuple[str, str], str], list[dict[str, object]]]:
    """Assign ``[TYPE_N]`` tokens to unique (type, value) pairs in first-appearance order.

    Returns (token_map, manifest). The manifest lists {token, type, occurrences} in
    assignment order and carries NO raw values.
    """
    token_map: dict[tuple[str, str], str] = {}
    counters: dict[str, int] = {}
    occurrences: dict[str, int] = {}
    order: list[tuple[str, str]] = []  # (token, type) in assignment order
    for block in blocks:
        for winner, _, _ in select_replacements(entities_by_block.get(block.index, [])):
            key = (winner.type, winner.value)
            token = token_map.get(key)
            if token is None:
                counters[winner.type] = counters.get(winner.type, 0) + 1
                token = f"[{_token_prefix(winner.type)}_{counters[winner.type]}]"
                token_map[key] = token
                order.append((token, winner.type))
            occurrences[token] = occurrences.get(token, 0) + 1
    manifest: list[dict[str, object]] = [
        {"token": token, "type": type_, "occurrences": occurrences[token]}
        for token, type_ in order
    ]
    return token_map, manifest


def _replace_spans(text: str, entities: list[Entity], token_map: dict[tuple[str, str], str]) -> str:
    pieces: list[str] = []
    position = 0
    for winner, start, end in select_replacements(entities):
        pieces.append(text[position:start])
        pieces.append(token_map[(winner.type, winner.value)])
        position = end
    pieces.append(text[position:])
    return "".join(pieces)


def sanitize_blocks(
    blocks: list[Block], entities_by_block: dict[int, list[Entity]]
) -> tuple[list[str], list[dict[str, object]]]:
    """Replace every finding in every block with its consistent token.

    Returns (sanitized_texts, manifest); texts keep block order.
    """
    token_map, manifest = assign_tokens(blocks, entities_by_block)
    texts = [
        _replace_spans(b.text, entities_by_block.get(b.index, []), token_map) for b in blocks
    ]
    return texts, manifest


def render_artifact(fmt: str, sanitized_texts: list[str]) -> str:
    """Join sanitized block texts into the artifact's plain-text rendering.

    Line-oriented formats (csv rows, json fields) stay one block per line; every
    other format separates blocks with a blank line (mirroring how txt/md blocks
    were split). Empty blocks (e.g. image-only PDF pages) are dropped. UTF-8, LF,
    trailing newline, deterministic.
    """
    kept = [t for t in sanitized_texts if t]
    separator = "\n" if fmt in ("csv", "json") else "\n\n"
    return separator.join(kept) + "\n" if kept else ""
