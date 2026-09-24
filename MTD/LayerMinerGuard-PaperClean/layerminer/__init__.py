"""LayerMinerGuard: Visibility-Aware Host-Side Mining Evidence-Chain Reconstruction."""

from .schema import (
    MarkerSummary, Evidence, PrivacyRecord, Verdict, SessionSummary, Label,
    VISIBILITY_PLAINTEXT, VISIBILITY_TLS, VISIBILITY_UNAVAILABLE,
)
from .evidence_chain import reconstruct_evidence, classify_visibility_mode, compute_session_closed
from .detector import detect, detect_full, detect_all
