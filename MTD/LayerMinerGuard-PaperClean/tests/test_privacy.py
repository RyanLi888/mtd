"""Privacy audit tests.

Ensures no raw sensitive data leaks into any output files.
"""

import pytest
import sys
import os
import json
import glob

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from layerminer.schema import PrivacyRecord, SessionSummary

# Fields that must NEVER appear in any output
FORBIDDEN_FIELDS = {
    'wallet', 'wallet_address', 'payment_address',
    'job_id_raw', 'nonce_raw', 'result_raw', 'blob_raw',
    'raw_payload', 'payload_raw', 'payload_hex',
}

# Fields that are allowed (counts, not raw values)
ALLOWED_FIELDS = {
    'job_marker_count', 'submit_marker_count', 'associated_submit_count',
    'raw_payload_saved', 'wallet_saved', 'job_id_saved',
    'nonce_saved', 'result_saved', 'blob_saved',
}


class TestPrivacyRecord:
    def test_all_flags_false_by_default(self):
        pr = PrivacyRecord()
        assert pr.raw_payload_saved is False
        assert pr.wallet_saved is False
        assert pr.job_id_saved is False
        assert pr.nonce_saved is False
        assert pr.result_saved is False
        assert pr.blob_saved is False

    def test_validate_passes_when_all_false(self):
        pr = PrivacyRecord()
        pr.validate()  # Should not raise

    def test_validate_fails_when_any_true(self):
        for field in ['raw_payload_saved', 'wallet_saved', 'job_id_saved',
                       'nonce_saved', 'result_saved', 'blob_saved']:
            pr = PrivacyRecord(**{field: True})
            with pytest.raises(AssertionError, match=field):
                pr.validate()


class TestSessionSummaryPrivacy:
    def test_session_summary_has_privacy_record(self):
        s = SessionSummary(session_id="test")
        assert isinstance(s.privacy, PrivacyRecord)
        s.privacy.validate()  # Should pass

    def test_session_summary_to_dict_has_privacy(self):
        s = SessionSummary(session_id="test")
        d = s.to_dict()
        assert 'privacy' in d
        assert d['privacy']['raw_payload_saved'] is False


class TestNoForbiddenFieldsInOutput:
    """Scan output files for forbidden fields."""

    def test_no_forbidden_fields_in_layerminer_source(self):
        """Scan layerminer/ source for forbidden field references."""
        source_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'layerminer')
        if not os.path.exists(source_dir):
            pytest.skip("layerminer/ not found")

        violations = []
        for py_file in glob.glob(os.path.join(source_dir, '**', '*.py'), recursive=True):
            with open(py_file) as f:
                content = f.read()
            for field in FORBIDDEN_FIELDS:
                # Check for assignment or dict key with forbidden field
                if f"'{field}'" in content or f'"{field}"' in content:
                    # Allow in comments or string literals that are checking for absence
                    violations.append(f"{py_file}: contains '{field}'")

        if violations:
            pytest.fail("Forbidden fields found:\n" + "\n".join(violations))

    def test_no_real_wallet_in_source(self):
        """Ensure no real wallet addresses in source."""
        source_dir = os.path.dirname(os.path.dirname(__file__))
        wallet_patterns = [
            '4',  # Monero addresses start with 4
            '8',  # Monero addresses start with 8
        ]

        # This is a basic check - real wallet addresses are 95 chars
        # We just ensure no obvious wallet strings exist
        for root, dirs, files in os.walk(source_dir):
            if '.git' in root:
                continue
            for fname in files:
                if not fname.endswith('.py'):
                    continue
                fpath = os.path.join(root, fname)
                with open(fpath) as f:
                    content = f.read()
                # Check for 95-char base58 strings (Monero address format)
                import re
                wallet_pattern = r'\b[48][1-9A-HJ-NP-Za-km-z]{94}\b'
                matches = re.findall(wallet_pattern, content)
                if matches:
                    pytest.fail(f"Possible wallet address in {fpath}: {matches[0][:20]}...")
