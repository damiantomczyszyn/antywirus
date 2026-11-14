"""Hybrid score fusion - the heart of "more than just hashes".

A single analysis layer is either blind or noisy:

* **signature** layer is certain but only knows what it has already seen;
* **heuristic** layer generalises but produces false positives;
* **intel** layer knows bad infrastructure but not bad code;
* **behavior** layer catches brand-new malware but only once it acts.

:func:`fuse` combines them.  Two properties matter:

1. *Within* a layer, extra findings add less and less (they are usually
   correlated - a packed binary also has high entropy), and each layer has a
   cap.  Heuristics alone therefore top out at MEDIUM and can never quarantine
   a file on their own.
2. *Across* layers, agreement is strong evidence, so a corroboration bonus is
   applied when two or more independent layers fire.  Static heuristics plus a
   behavioural rule will reach HIGH even though neither would alone.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from ..models import (
    Detection,
    DetectionLayer,
    FileVerdict,
    ProcessVerdict,
    Severity,
    severity_for_score,
)

__all__ = [
    "LAYER_CAPS",
    "CORROBORATION_BONUS",
    "SECONDARY_WEIGHT",
    "fuse",
    "apply_to_file_verdict",
    "apply_to_process_verdict",
    "explain",
]

#: Highest score a single layer may contribute on its own.
LAYER_CAPS: dict[DetectionLayer, float] = {
    DetectionLayer.SIGNATURE: 100.0,
    DetectionLayer.INTEL: 80.0,
    DetectionLayer.BEHAVIOR: 85.0,
    DetectionLayer.HEURISTIC: 55.0,
}

#: Weight applied to every finding in a layer except the strongest one.
SECONDARY_WEIGHT = 0.4

#: Multiplier per extra corroborating layer (2 layers -> 1.15, 3 -> 1.30).
CORROBORATION_BONUS = 0.15


def _layer_score(detections: Sequence[Detection], layer: DetectionLayer) -> float:
    """Diminishing-returns sum of one layer's findings, capped."""
    if not detections:
        return 0.0
    weights = sorted((d.weighted for d in detections), reverse=True)
    total = weights[0] + SECONDARY_WEIGHT * sum(weights[1:])
    return min(total, LAYER_CAPS.get(layer, 100.0))


def fuse(detections: Iterable[Detection]) -> tuple[float, Severity]:
    """Combine findings into ``(score, severity)``.

    ``score`` is clamped to 0..100.  An exact-hash signature match always
    yields 100/CRITICAL because it is a certainty, not an estimate.
    """
    items = [d for d in detections if d.weighted > 0]
    if not items:
        return 0.0, Severity.CLEAN

    by_layer: dict[DetectionLayer, list[Detection]] = {}
    for det in items:
        by_layer.setdefault(det.layer, []).append(det)

    # A certainty short-circuits the whole model.
    if any(d.weighted >= 100.0 for d in by_layer.get(DetectionLayer.SIGNATURE, ())):
        return 100.0, Severity.CRITICAL

    subtotal = sum(_layer_score(dets, layer) for layer, dets in by_layer.items())

    active_layers = len(by_layer)
    if active_layers > 1:
        subtotal *= 1.0 + CORROBORATION_BONUS * (active_layers - 1)

    score = round(min(100.0, subtotal), 2)
    return score, severity_for_score(score)


def apply_to_file_verdict(verdict: FileVerdict) -> FileVerdict:
    """Recompute ``score`` and ``severity`` in place from ``verdict.detections``."""
    verdict.score, verdict.severity = fuse(verdict.detections)
    return verdict


def apply_to_process_verdict(verdict: ProcessVerdict) -> ProcessVerdict:
    """Recompute ``score`` and ``severity`` in place from ``verdict.detections``."""
    verdict.score, verdict.severity = fuse(verdict.detections)
    return verdict


def explain(detections: Iterable[Detection]) -> str:
    """Human-readable breakdown, used by the GUI details pane and the CLI."""
    items = [d for d in detections if d.weighted > 0]
    if not items:
        return "Brak przesłanek — obiekt czysty."

    by_layer: dict[DetectionLayer, list[Detection]] = {}
    for det in items:
        by_layer.setdefault(det.layer, []).append(det)

    lines: list[str] = []
    for layer in (
        DetectionLayer.SIGNATURE,
        DetectionLayer.INTEL,
        DetectionLayer.BEHAVIOR,
        DetectionLayer.HEURISTIC,
    ):
        dets = by_layer.get(layer)
        if not dets:
            continue
        lines.append(f"[{layer.value}] wkład warstwy: {_layer_score(dets, layer):.1f} pkt")
        for det in sorted(dets, key=lambda d: d.weighted, reverse=True):
            detail = f" - {det.detail}" if det.detail else ""
            lines.append(
                f"    * {det.rule}: {det.threat_name} "
                f"({det.score:.0f} x {det.confidence:.2f} = {det.weighted:.1f}){detail}"
            )

    score, severity = fuse(items)
    if len(by_layer) > 1:
        lines.append(
            f"Premia za zgodność {len(by_layer)} warstw: "
            f"x{1.0 + CORROBORATION_BONUS * (len(by_layer) - 1):.2f}"
        )
    lines.append(f"WYNIK: {score:.1f}/100 -> {severity.value.upper()}")
    return "\n".join(lines)
