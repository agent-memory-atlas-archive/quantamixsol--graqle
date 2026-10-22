# DAG control typology

Every control in the decision path carries exactly one type. Arbitration is the
total order **HARD > CAP > THRESHOLD > COMPENSATORY > DESCRIPTIVE**.

| type | meaning |
|---|---|
| `descriptive` | reported, never changes the outcome |
| `compensatory` | enters a weighted sum |
| `threshold` | a scalar compared to a symbol; can be offset upstream |
| `hard` | boolean, non-compensatory, evaluated before any aggregate |
| `cap` | bounds an aggregate after a hard failure |

The registry is closed: `graqle.assurance.control_types.CONTROL_REGISTRY`. This
table is checked against it by `tests/test_assurance/hard_gates/test_control_types.py`.

| control_id | type | source |
|---|---|---|
| TS-BLOCK | hard | `graqle/core/governance.py:_check_pattern_leakage` |
| GOV.review_threshold | threshold | `graqle/core/governance.py:GovernanceConfig.review_threshold` |
| GOV.block_threshold | threshold | `graqle/core/governance.py:GovernanceConfig.block_threshold` |
| GOV.secret_exposure_floor | threshold | `graqle/core/governance.py:_check_secret_exposure` |
| GOV.cumulative_radius_cap | threshold | `graqle/core/governance.py:GovernanceConfig.cumulative_radius_cap` |
| ART14.human_review_required_threshold | threshold | `graqle/compliance/article_14_gate.py:DEFAULT_HUMAN_REVIEW_THRESHOLD` |
| DRACE.D | compensatory | `graqle/intelligence/governance/drace.py:evaluate_dependency` |
| DRACE.R | compensatory | `graqle/intelligence/governance/drace.py:evaluate_reasoning` |
| DRACE.A | compensatory | `graqle/intelligence/governance/drace.py:evaluate_auditability` |
| DRACE.C | compensatory | `graqle/intelligence/governance/drace.py:evaluate_constraint` |
| DRACE.E | compensatory | `graqle/intelligence/governance/drace.py:evaluate_explainability` |
| DRACE.C.blocking_cap | cap | `graqle/intelligence/governance/drace.py:evaluate_constraint` |
| DRACE.total | descriptive | `graqle/intelligence/governance/drace.py:DRACEScore.total` |
| DRACE.grade | descriptive | `graqle/intelligence/governance/drace.py:DRACEScore.grade` |
| CV.source_reliability | compensatory | `graqle/assurance/confidence_vector.py:ConfidenceVector.dims` |
| CV.extraction_reliability | compensatory | `graqle/assurance/confidence_vector.py:ConfidenceVector.dims` |
| CV.corroboration | compensatory | `graqle/assurance/confidence_vector.py:ConfidenceVector.dims` |
| CV.temporal_validity | compensatory | `graqle/assurance/confidence_vector.py:ConfidenceVector.dims` |
| CV.context_fit | compensatory | `graqle/assurance/confidence_vector.py:ConfidenceVector.dims` |
| CV.reasoning_support | compensatory | `graqle/assurance/confidence_vector.py:ConfidenceVector.dims` |
| CV.operational_reliability | compensatory | `graqle/assurance/confidence_vector.py:ConfidenceVector.dims` |
| CV.extraction_reliability.floor | threshold | `graqle/assurance/confidence_vector.py:ConfidenceVector.dims` |
| CV.operational_reliability.activation_floor | threshold | `graqle/assurance/confidence_vector.py:ConfidenceVector.dims` |
| CV.corroboration.min | threshold | `graqle/assurance/confidence_vector.py:ConfidenceVector.dims` |
| HG-01 | hard | `graqle/assurance/hard_gates.py:HG01MandatoryPolicy` |
| HG-02 | hard | `graqle/assurance/hard_gates.py:HG02InvalidatedEvidence` |
| HG-03 | hard | `graqle/assurance/hard_gates.py:HG03ProvenanceForHighImpact` |
| HG-04 | hard | `graqle/assurance/hard_gates.py:HG04ArgsBinding` |
| HG-05 | hard | `graqle/assurance/hard_gates.py:HG05Poisoning` |
| HG-06 | hard | `graqle/assurance/hard_gates.py:HG06ActorAuthorized` |
| HG-07 | hard | `graqle/assurance/hard_gates.py:HG07MaterialContradiction` |
| CAP | cap | `graqle/assurance/critical_cap.py:CriticalFailureCap` |

`CV.*` sources point at `confidence_vector.py`, which arrives with CR-014.
