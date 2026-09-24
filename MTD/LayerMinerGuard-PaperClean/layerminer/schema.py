"""Unified evidence schema for LayerMinerGuard.

All probes output MarkerSummary. All sessions output SessionSummary.
Detector reads only SessionSummary, never labels.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional
import json
import hashlib
import time


# ── Visibility Modes ──────────────────────────────────────────────────────────

VISIBILITY_PLAINTEXT = "plaintext_stratum"
VISIBILITY_TLS = "openssl_visible_tls"
VISIBILITY_UNAVAILABLE = "protocol_unavailable"

VALID_VISIBILITIES = {VISIBILITY_PLAINTEXT, VISIBILITY_TLS, VISIBILITY_UNAVAILABLE}


# ── Marker Summary (probe output) ────────────────────────────────────────────

@dataclass
class MarkerSummary:
    """Unified output from plaintext or TLS probe."""
    visibility_mode: str                          # plaintext_stratum / openssl_visible_tls / protocol_unavailable
    job_marker_count: int = 0                     # read-side job markers
    submit_marker_count: int = 0                  # write-side submit markers
    associated_submit_count: int = 0              # token-matched submits
    association_mismatch_count: int = 0           # submits without matching job
    raw_payload_saved: bool = False               # always False

    def validate(self):
        assert self.visibility_mode in VALID_VISIBILITIES, f"Invalid visibility: {self.visibility_mode}"
        assert not self.raw_payload_saved, "raw_payload_saved must be False"
        assert self.job_marker_count >= 0
        assert self.submit_marker_count >= 0
        assert self.associated_submit_count >= 0


# ── Evidence (session-level) ─────────────────────────────────────────────────

@dataclass
class Evidence:
    """Aggregated evidence from all probes for one session."""
    job_marker_count: int = 0
    submit_marker_count: int = 0
    associated_submit_count: int = 0
    compute_evidence_present: bool = False
    behavioral_closure: bool = False
    session_closed: bool = False

    @property
    def has_protocol_markers(self) -> bool:
        return self.job_marker_count > 0 and self.submit_marker_count > 0

    @property
    def has_association(self) -> bool:
        return self.associated_submit_count > 0

    @property
    def evidence_chain_complete(self) -> bool:
        return (
            self.has_protocol_markers
            and self.has_association
            and self.compute_evidence_present
            and self.session_closed
        )


# ── Privacy Record ───────────────────────────────────────────────────────────

@dataclass
class PrivacyRecord:
    """Confirms no raw sensitive data was saved."""
    raw_payload_saved: bool = False
    wallet_saved: bool = False
    job_id_saved: bool = False
    nonce_saved: bool = False
    result_saved: bool = False
    blob_saved: bool = False

    def validate(self):
        for field_name in ['raw_payload_saved', 'wallet_saved', 'job_id_saved',
                           'nonce_saved', 'result_saved', 'blob_saved']:
            assert not getattr(self, field_name), f"{field_name} must be False"


# ── Verdict ──────────────────────────────────────────────────────────────────

@dataclass
class Verdict:
    """Detector output for one session."""
    confirmed_mining: bool = False
    reason: str = ""

    def __str__(self):
        return "POSITIVE" if self.confirmed_mining else f"NEGATIVE ({self.reason})"


# ── Session Summary (full output) ────────────────────────────────────────────

@dataclass
class SessionSummary:
    """Complete sanitized summary for one experiment session."""
    session_id: str
    experiment: str = ""
    scenario: str = ""
    duration_sec: int = 0

    # Target info
    target_program: str = ""
    target_version: str = ""
    target_linkage: str = ""                      # dynamic / static

    # Visibility
    visibility_mode: str = VISIBILITY_UNAVAILABLE
    probe_backend: str = ""

    # Evidence
    evidence: Evidence = field(default_factory=Evidence)

    # Privacy
    privacy: PrivacyRecord = field(default_factory=PrivacyRecord)

    # Verdict
    verdict: Verdict = field(default_factory=Verdict)

    # Runner
    runner_exit_code: int = 0
    runner_residual_pids: list = field(default_factory=list)

    # Provenance
    producer_commit: str = ""
    timestamp: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, path: str):
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def from_dict(cls, d: dict) -> 'SessionSummary':
        evidence = Evidence(**d.get('evidence', {}))
        privacy = PrivacyRecord(**d.get('privacy', {}))
        verdict = Verdict(**d.get('verdict', {}))
        return cls(
            session_id=d['session_id'],
            experiment=d.get('experiment', ''),
            scenario=d.get('scenario', ''),
            duration_sec=d.get('duration_sec', 0),
            target_program=d.get('target', {}).get('program', ''),
            target_version=d.get('target', {}).get('version', ''),
            target_linkage=d.get('target', {}).get('linkage', ''),
            visibility_mode=d.get('visibility', {}).get('mode', VISIBILITY_UNAVAILABLE),
            probe_backend=d.get('visibility', {}).get('probe_backend', ''),
            evidence=evidence,
            privacy=privacy,
            verdict=verdict,
            runner_exit_code=d.get('runner', {}).get('exit_code', 0),
            runner_residual_pids=d.get('runner', {}).get('residual_processes', []),
            producer_commit=d.get('producer_commit', ''),
            timestamp=d.get('timestamp', 0.0),
        )

    @classmethod
    def from_json(cls, path: str) -> 'SessionSummary':
        with open(path) as f:
            return cls.from_dict(json.load(f))


# ── Label (separate from features, never read by detector) ───────────────────

@dataclass
class Label:
    """Ground truth label — stored separately from features."""
    session_id: str
    label: str                                  # positive / negative
    scenario_group: str = ""
    split: str = "heldout"                      # heldout / development

    def validate(self):
        assert self.label in ('positive', 'negative'), f"Invalid label: {self.label}"
