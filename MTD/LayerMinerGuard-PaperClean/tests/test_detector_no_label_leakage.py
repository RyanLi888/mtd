"""Detector no-label-leakage tests.

Ensures the detector never reads labels, only reads evidence.
"""

import pytest
import sys
import os
import ast

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from layerminer.detector import detect, detect_full, detect_all
from layerminer.schema import SessionSummary, Evidence, Verdict


FORBIDDEN_FIELDS = {
    'label', 'expected_protocol_chain', 'expected_compute_evidence',
    'expected_host_mining_chain', 'scenario_type', 'include_in_main_table',
    'include_in_ablation', 'supports_claim', 'pool_alias', 'miner_type',
}


class TestDetectorNoLabelLeakage:
    """Verify detector code does not reference forbidden fields."""

    def _scan_for_forbidden(self, filepath: str, name: str):
        """Scan a Python file for forbidden field references in actual code."""
        import ast
        with open(filepath) as f:
            source = f.read()

        try:
            tree = ast.parse(source)
        except SyntaxError:
            pytest.skip(f"Cannot parse {filepath}")

        violations = []
        for node in ast.walk(tree):
            # Only check string constants that are NOT docstrings
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                # Skip docstrings (they are the first expr in a module/class/function)
                continue
            # Check attribute names and variable names
            if isinstance(node, ast.Attribute):
                if node.attr in FORBIDDEN_FIELDS:
                    violations.append(f"{name}:{node.lineno}: attribute '{node.attr}'")
            if isinstance(node, ast.Name):
                if node.id in FORBIDDEN_FIELDS:
                    violations.append(f"{name}:{node.lineno}: name '{node.id}'")
            # Check dict keys
            if isinstance(node, ast.Dict):
                for key in node.keys:
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        if key.value in FORBIDDEN_FIELDS:
                            violations.append(f"{name}:{key.lineno}: dict key '{key.value}'")

        if violations:
            pytest.fail(f"Forbidden fields in {name}:\n" + "\n".join(violations))

    def test_detector_source_no_forbidden_fields(self):
        """Scan detector.py for forbidden field references in actual code."""
        detector_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'layerminer', 'detector.py'
        )
        if not os.path.exists(detector_path):
            pytest.skip("detector.py not found")
        self._scan_for_forbidden(detector_path, "detector.py")

    def test_evidence_chain_source_no_forbidden_fields(self):
        """Scan evidence_chain.py for forbidden field references in actual code."""
        ec_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'layerminer', 'evidence_chain.py'
        )
        if not os.path.exists(ec_path):
            pytest.skip("evidence_chain.py not found")
        self._scan_for_forbidden(ec_path, "evidence_chain.py")


class TestDetectorBehavior:
    """Test detector produces correct verdicts."""

    def test_positive_when_chain_complete(self):
        evidence = Evidence(
            job_marker_count=10,
            submit_marker_count=5,
            associated_submit_count=5,
            compute_evidence_present=True,
            session_closed=True,
        )
        verdict = detect_full(evidence)
        assert verdict.confirmed_mining is True
        assert "evidence_chain_complete" in verdict.reason

    def test_negative_when_no_markers(self):
        evidence = Evidence(
            job_marker_count=0,
            submit_marker_count=0,
            compute_evidence_present=True,
            session_closed=True,
        )
        verdict = detect_full(evidence)
        assert verdict.confirmed_mining is False
        assert "no_protocol_markers" in verdict.reason

    def test_negative_when_no_association(self):
        evidence = Evidence(
            job_marker_count=10,
            submit_marker_count=5,
            associated_submit_count=0,
            compute_evidence_present=True,
            session_closed=True,
        )
        verdict = detect_full(evidence)
        assert verdict.confirmed_mining is False
        assert "no_association" in verdict.reason

    def test_negative_when_no_compute(self):
        evidence = Evidence(
            job_marker_count=10,
            submit_marker_count=5,
            associated_submit_count=5,
            compute_evidence_present=False,
            session_closed=True,
        )
        verdict = detect_full(evidence)
        assert verdict.confirmed_mining is False
        assert "no_compute" in verdict.reason

    def test_detect_on_session_summary(self):
        summary = SessionSummary(
            session_id="test",
            evidence=Evidence(
                job_marker_count=10,
                submit_marker_count=5,
                associated_submit_count=5,
                compute_evidence_present=True,
                session_closed=True,
            ),
        )
        verdict = detect(summary)
        assert verdict.confirmed_mining is True

    def test_detect_all(self):
        summaries = [
            SessionSummary(
                session_id="pos",
                evidence=Evidence(
                    job_marker_count=10, submit_marker_count=5,
                    associated_submit_count=5, compute_evidence_present=True,
                    session_closed=True,
                ),
            ),
            SessionSummary(
                session_id="neg",
                evidence=Evidence(compute_evidence_present=True),
            ),
        ]
        verdicts = detect_all(summaries)
        assert len(verdicts) == 2
        assert verdicts[0].confirmed_mining is True
        assert verdicts[1].confirmed_mining is False
