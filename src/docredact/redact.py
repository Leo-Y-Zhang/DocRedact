"""Masking of detected entity spans."""

from __future__ import annotations

from collections.abc import Sequence

from .detectors import Entity

MASK_TEMPLATE = "[REDACTED:{}]"


def select_replacements(entities: Sequence[Entity]) -> list[tuple[Entity, int, int]]:
    """Resolve overlaps into one replacement per cluster, covering the UNION of spans.

    Overlapping entities are clustered; each cluster is replaced as a whole
    (start of the first span to end of the furthest span), labeled by its
    leftmost-longest entity. Consuming the union - not just the winner's span -
    guarantees that no byte of any detected value survives replacement, even
    when spans only partially overlap. Shared by masking and sanitized-artifact
    generation so both replace exactly the same ranges.

    Returns (winner, cluster_start, cluster_end) triples in document order.
    """
    ordered = sorted(entities, key=lambda e: (e.start, -e.end, e.type))
    clusters: list[tuple[Entity, int, int]] = []
    for entity in ordered:
        if clusters and entity.start < clusters[-1][2]:
            winner, start, end = clusters[-1]
            clusters[-1] = (winner, start, max(end, entity.end))
        else:
            clusters.append((entity, entity.start, entity.end))
    return clusters


def mask_text(text: str, entities: Sequence[Entity]) -> str:
    """Replace entity spans in ``text`` with ``[REDACTED:<type>]`` tokens.

    Overlapping spans collapse into one mask covering their union, labeled by
    the leftmost-longest entity. Masking is idempotent because mask tokens
    contain nothing any detector matches.
    """
    pieces: list[str] = []
    position = 0
    for winner, start, end in select_replacements(entities):
        pieces.append(text[position:start])
        pieces.append(MASK_TEMPLATE.format(winner.type))
        position = end
    pieces.append(text[position:])
    return "".join(pieces)
