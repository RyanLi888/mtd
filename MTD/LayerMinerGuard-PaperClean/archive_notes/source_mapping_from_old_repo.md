# Source Mapping from Old Repository

## Old Repository

`~/Desktop/z/LayerMiner`

## Core Detection Framework

| Old Path | New Path | Status |
|---|---|---|
| `core/l1_scorer.py` | `layerminer/detector.py` | Refactored |
| `core/l2_analyzer.py` | `layerminer/evidence_chain.py` | Refactored |
| `core/l3_confirmer.py` | `layerminer/detector.py` | Merged |
| `core/detector.py` | `layerminer/detector.py` | Refactored |
| `core/event_schema.py` | `layerminer/schema.py` | Refactored |

## Probes

| Old Path | New Path | Status |
|---|---|---|
| `prototypes/bcc_tls_uprobe_probe.py` | `probes/tls_openssl_probe.py` | Adapted |
| `prototypes/bcc_stratum_semantic_probe.py` | `probes/plaintext_stratum_probe.py` | Adapted |
| `scripts/p21_target_network_observer.py` | `probes/net_observer.py` | Pending |

## Scripts

| Old Path | New Path | Status |
|---|---|---|
| `scripts/run_p21_canonical_session.sh` | `scripts/run_single_session.py` | Rewritten in Python |
| `scripts/p21_finalize_session.py` | `scripts/run_single_session.py` | Merged |
| `scripts/p21_predict_detectors.py` | `layerminer/detector.py` | Merged |
| `scripts/p21_score_predictions.py` | `experiments/exp6_final_eval/` | Pending |
| `scripts/p21_launch_suspended.py` | `scripts/run_single_session.py` | Merged |

## Workloads

| Old Path | New Path | Status |
|---|---|---|
| `scripts/p21_deterministic_fake_pool.py` | `workloads/fake_plaintext_pool.py` | Pending |
| `scripts/fake_stratum_pool_tls_p31e.py` | `workloads/fake_tls_pool.py` | Pending |
| `workloads/p21_cpu_heavy_benign.py` | `workloads/benign_cpu.py` | Pending |

## Tests

| Old Path | New Path | Status |
|---|---|---|
| `tests/test_p21_no_label_leakage.py` | `tests/test_detector_no_label_leakage.py` | Adapted |
| `tests/test_p21_prediction_scoring_split.py` | `tests/test_schema.py` | Partial |
| `tests/test_paper_detector_decoupling.py` | `tests/test_detector_no_label_leakage.py` | Merged |

## Not Migrated (Historical)

- All P15-P22 phase result files in `reports/`
- All session data in `data/sessions/`
- All trace data in `traces/`
- All old experiment scripts (P15-P22 runners)
- All old workloads (P15-P22 specific)
- All old configs (P15-P22 specific)

## Why Not Migrated

1. **P-phase results**: Historical development data, not needed for paper
2. **Session data**: Contains raw events, privacy risk
3. **Traces**: Contains raw JSONL, privacy risk
4. **Old scripts**: Superseded by unified runners
5. **Old configs**: Superseded by new YAML configs
