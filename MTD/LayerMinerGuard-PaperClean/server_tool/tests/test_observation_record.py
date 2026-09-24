"""Tests for observation record writing."""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from server_tool.layerminer_server.alert_store import write_observation_record, read_recent_observations


def _test_config():
    tmpdir = tempfile.mkdtemp()
    obs_dir = os.path.join(tmpdir, "observations")
    return {
        "output": {
            "observation_dir": obs_dir,
            "alerts_jsonl": os.path.join(tmpdir, "alerts.jsonl"),
        }
    }


def _record():
    return {
        "record_type": "observation",
        "timestamp": "2026-06-25T12:00:00Z",
        "run_id": "abc123",
        "pid": 1234,
        "process_name": "test",
        "verdict": "protocol_suspicious",
        "confidence": "medium",
        "reasons": ["compute_evidence_present", "job_marker_seen"],
        "evidence": {
            "job_marker_count": 5,
            "submit_marker_count": 0,
        },
        "privacy": {
            "raw_payload_saved": False,
            "wallet_saved": False,
        },
    }


class TestWriteObservationRecord:
    def test_writes_file(self):
        config = _test_config()
        path = write_observation_record(_record(), config)
        assert os.path.exists(path)
        assert path.endswith(".json")

    def test_file_contains_valid_json(self):
        config = _test_config()
        path = write_observation_record(_record(), config)
        with open(path) as f:
            data = json.load(f)
        assert data["record_type"] == "observation"
        assert data["pid"] == 1234

    def test_filename_has_pid_and_verdict(self):
        config = _test_config()
        path = write_observation_record(_record(), config)
        fname = os.path.basename(path)
        assert "1234" in fname
        assert "protocol-suspicious" in fname

    def test_sanitized_no_raw_payload(self):
        config = _test_config()
        rec = _record()
        rec["raw_payload"] = "should be removed"
        path = write_observation_record(rec, config)
        with open(path) as f:
            data = json.load(f)
        assert "raw_payload" not in data

    def test_read_recent_observations(self):
        config = _test_config()
        write_observation_record(_record(), config)
        records = read_recent_observations(config, limit=10)
        assert len(records) >= 1
        assert records[0]["record_type"] == "observation"
