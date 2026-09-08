"""Computes snapshot completeness/upload decision.
Schema and payload-size failures short-circuit to "failed" before evidence completeness is checked."""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True)
class CompletenessDecision:
    snapshot_status: str  # "complete" | "incomplete" | "failed"
    should_upload: bool
    reasons: tuple[str, ...]


def decide_completeness(
    *,
    discovery_complete: bool,
    unready_regions: tuple[str, ...],
    domain_complete: dict[str, bool],
    exadata_detected: bool,
    unresolved_relationship_count: int,
    schema_valid: bool,
    within_payload_budget: bool,
) -> CompletenessDecision:
    if not schema_valid:
        return CompletenessDecision("failed", False, ("schema validation failed",))
    if not within_payload_budget:
        return CompletenessDecision(
            "failed", False, ("serialized payload exceeds the configured size budget",)
        )

    reasons: list[str] = []
    if not discovery_complete:
        reasons.append("discovery incomplete (tenancy/region/compartment enumeration failed)")
    if unready_regions:
        reasons.append(f"configured region(s) not subscribed/READY: {list(unready_regions)}")
    for domain, complete in sorted(domain_complete.items()):
        if not complete:
            reasons.append(f"{domain} collection incomplete")
    if exadata_detected:
        reasons.append(
            "Exadata detected; database domain coverage cannot be claimed complete "
            "(spec 5.7/10: no partial database evidence)"
        )
    if unresolved_relationship_count > 0:
        # no relationship classification exists; any unresolved relationship blocks upload
        reasons.append(f"{unresolved_relationship_count} unresolved relationship(s)")

    if reasons:
        return CompletenessDecision("incomplete", False, tuple(reasons))
    return CompletenessDecision("complete", True, ("all required operations succeeded",))
