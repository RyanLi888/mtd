"""Evidence-chain reconstruction.

Reconstructs the mining evidence chain:
  job → compute → submit → association → closure

Never reads labels. Never reads raw payloads.
"""

from .schema import MarkerSummary, Evidence, SessionSummary, VISIBILITY_UNAVAILABLE


def reconstruct_evidence(
    marker: MarkerSummary,
    compute_present: bool,
    behavioral_closure: bool,
    session_closed: bool,
) -> Evidence:
    """Reconstruct evidence from probe outputs.

    Args:
        marker: unified marker summary from plaintext or TLS probe
        compute_present: whether sustained CPU compute was observed
        behavioral_closure: whether rx→compute→tx temporal pattern matched
        session_closed: whether process exited and connection closed

    Returns:
        Evidence with all fields populated
    """
    return Evidence(
        job_marker_count=marker.job_marker_count,
        submit_marker_count=marker.submit_marker_count,
        associated_submit_count=marker.associated_submit_count,
        compute_evidence_present=compute_present,
        behavioral_closure=behavioral_closure,
        session_closed=session_closed,
    )


def classify_visibility_mode(probe_type: str) -> str:
    """Map probe type to visibility mode.

    Args:
        probe_type: 'plaintext', 'tls', or 'unavailable'

    Returns:
        visibility mode string
    """
    mapping = {
        'plaintext': 'plaintext_stratum',
        'tls': 'openssl_visible_tls',
        'unavailable': 'protocol_unavailable',
    }
    return mapping.get(probe_type, 'protocol_unavailable')


def compute_session_closed(
    process_exit_observed: bool,
    connection_closed_count: int,
    tcp_close_count: int,
) -> bool:
    """FROZEN: session_closed = process_exit AND (conn_closed OR tcp_close)."""
    net_closed = connection_closed_count > 0 or tcp_close_count > 0
    return process_exit_observed and net_closed
