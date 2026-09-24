"""Evidence-chain detector.

FROZEN DETECTOR DEFINITIONS — do not modify thresholds after freeze.

Detector reads only SessionSummary.evidence, never labels.
"""

from .schema import Evidence, Verdict, SessionSummary


# ── Frozen Detector Definitions ───────────────────────────────────────────────

def detect_cpu_only(evidence: Evidence) -> bool:
    """CPU-only: sustained high CPU."""
    return evidence.compute_evidence_present


def detect_network_only(evidence: Evidence) -> bool:
    """Network-only: bidirectional network activity."""
    # Note: requires rx/tx counts from network observer, not in Evidence directly
    # This detector is a placeholder — actual implementation needs network stats
    return evidence.compute_evidence_present  # conservative fallback


def detect_protocol_only(evidence: Evidence) -> bool:
    """Protocol-only: job and submit markers present."""
    return evidence.has_protocol_markers


def detect_closure_only(evidence: Evidence) -> bool:
    """Closure-only: behavioral closure observed."""
    return evidence.behavioral_closure


def detect_evidence_chain(evidence: Evidence) -> bool:
    """Evidence chain: protocol markers + association + session closed."""
    return (
        evidence.has_protocol_markers
        and evidence.has_association
        and evidence.session_closed
    )


def detect_full(evidence: Evidence) -> Verdict:
    """Full detector: evidence chain + compute evidence.

    FROZEN DEFINITION:
        confirmed_mining = evidence_chain AND compute_evidence_present
    """
    chain = detect_evidence_chain(evidence)
    confirmed = chain and evidence.compute_evidence_present

    if confirmed:
        return Verdict(confirmed_mining=True, reason="evidence_chain_complete")
    else:
        reasons = []
        if not evidence.has_protocol_markers:
            reasons.append("no_protocol_markers")
        if not evidence.has_association:
            reasons.append("no_association")
        if not evidence.compute_evidence_present:
            reasons.append("no_compute")
        if not evidence.session_closed:
            reasons.append("session_not_closed")
        return Verdict(confirmed_mining=False, reason=",".join(reasons) if reasons else "unknown")


# ── Convenience ──────────────────────────────────────────────────────────────

def detect(summary: SessionSummary) -> Verdict:
    """Run full detector on a session summary.

    Args:
        summary: session summary (reads only .evidence, never .label)

    Returns:
        Verdict with confirmed_mining and reason
    """
    return detect_full(summary.evidence)


def detect_all(summaries: list[SessionSummary]) -> list[Verdict]:
    """Run detector on multiple session summaries."""
    return [detect(s) for s in summaries]
