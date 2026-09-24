"""Tests for layerminer.schema."""

import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from layerminer.schema import (
    MarkerSummary, Evidence, PrivacyRecord, Verdict, SessionSummary, Label,
    VISIBILITY_PLAINTEXT, VISIBILITY_TLS, VISIBILITY_UNAVAILABLE,
)


class TestMarkerSummary:
    def test_valid_creation(self):
        ms = MarkerSummary(visibility_mode=VISIBILITY_TLS, job_marker_count=5)
        assert ms.visibility_mode == VISIBILITY_TLS
        assert ms.job_marker_count == 5
        assert ms.raw_payload_saved is False

    def test_validate_rejects_invalid_visibility(self):
        ms = MarkerSummary(visibility_mode="invalid")
        with pytest.raises(AssertionError):
            ms.validate()

    def test_validate_rejects_raw_payload(self):
        ms = MarkerSummary(visibility_mode=VISIBILITY_TLS, raw_payload_saved=True)
        with pytest.raises(AssertionError):
            ms.validate()

    def test_validate_accepts_valid(self):
        ms = MarkerSummary(visibility_mode=VISIBILITY_TLS)
        ms.validate()  # Should not raise


class TestEvidence:
    def test_has_protocol_markers(self):
        e = Evidence(job_marker_count=1, submit_marker_count=1)
        assert e.has_protocol_markers is True

    def test_no_protocol_markers(self):
        e = Evidence(job_marker_count=0, submit_marker_count=1)
        assert e.has_protocol_markers is False

    def test_evidence_chain_complete(self):
        e = Evidence(
            job_marker_count=1,
            submit_marker_count=1,
            associated_submit_count=1,
            compute_evidence_present=True,
            session_closed=True,
        )
        assert e.evidence_chain_complete is True

    def test_evidence_chain_incomplete(self):
        e = Evidence(
            job_marker_count=1,
            submit_marker_count=1,
            associated_submit_count=0,
            compute_evidence_present=True,
            session_closed=True,
        )
        assert e.evidence_chain_complete is False


class TestPrivacyRecord:
    def test_valid_privacy(self):
        pr = PrivacyRecord()
        pr.validate()  # Should not raise

    def test_rejects_raw_payload(self):
        pr = PrivacyRecord(raw_payload_saved=True)
        with pytest.raises(AssertionError):
            pr.validate()

    def test_rejects_wallet(self):
        pr = PrivacyRecord(wallet_saved=True)
        with pytest.raises(AssertionError):
            pr.validate()


class TestVerdict:
    def test_positive(self):
        v = Verdict(confirmed_mining=True, reason="evidence_chain_complete")
        assert "POSITIVE" in str(v)

    def test_negative(self):
        v = Verdict(confirmed_mining=False, reason="no_protocol_markers")
        assert "NEGATIVE" in str(v)


class TestSessionSummary:
    def test_to_dict_roundtrip(self):
        s = SessionSummary(session_id="test_001", duration_sec=300)
        d = s.to_dict()
        s2 = SessionSummary.from_dict(d)
        assert s2.session_id == "test_001"
        assert s2.duration_sec == 300

    def test_privacy_fields(self):
        s = SessionSummary(session_id="test_002")
        assert s.privacy.raw_payload_saved is False
        assert s.privacy.wallet_saved is False


class TestLabel:
    def test_valid_label(self):
        l = Label(session_id="test", label="positive")
        l.validate()

    def test_invalid_label(self):
        l = Label(session_id="test", label="unknown")
        with pytest.raises(AssertionError):
            l.validate()
