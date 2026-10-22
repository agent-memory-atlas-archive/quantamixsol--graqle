"""CR-018 PR-018a: ProvenanceEvent model, committed form and canonical hash.

Covers AC-3 (determinism), AC-12 (escrow half: erasing salt and value leaves the
hash and the commitments intact), AC-14 part 1 (no forbidden key, no stray
numeric literal). Numeric values below are test-local substitutes, never
deployment values.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
import random
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from graqle.assurance import provenance_event as pe
from graqle.assurance.provenance_event import (
    FORBIDDEN_ANCHOR_KEYS,
    GENESIS_HASH,
    REDACTABLE_FIELDS,
    ProvenanceBuildError,
    ProvenanceEvent,
    canonical_hash,
    committed_form,
    event_canonical_hash,
    generate_salts,
    verify_disclosure,
)
from graqle.assurance.reason_codes import REGISTRY
from graqle.assurance.salt_escrow import FileSaltEscrow

ULID = "01J7Q0F3ZK9B4N2X8P5R6T7V9W"
HEX_A = "a" * 64
HEX_B = "b" * 64


def _event_dict(**overrides: object) -> dict:
    d: dict = {
        "event_id": f"evt_{ULID}",
        "event_type": "decision_gate_evaluated",
        "schema_version": "0.1.0",
        "occurred_at": "2026-09-12T10:00:00Z",
        "captured_at": "2026-09-12T10:00:01Z",
        "actor": {
            "agent_id": "agent-007",
            "type": "software_agent",
            "identity_assurance": "IAL2",
            "kid": "kid-test",
        },
        "activity": {
            "decision_id": f"dec_{ULID}",
            "trajectory_id": f"trj_{ULID}",
            "checkpoint": 2,
            "attempt": 0,
            "parent_trajectory_ref": None,
            "model_version": "model-x",
            "rule_set_version": "rs-1",
            "policy_bundle_version": "pb-1",
            "config_version": "cfg-1",
        },
        "inputs": {
            "evidence_refs": ["ev-1", "ev-2"],
            "claim_refs": ["cl-1"],
            "instruction_refs": ["in-1"],
            "policy_refs": ["pol-1"],
            "candidate_action_hash": HEX_A,
            "candidate_action_hash_algo": "sha256-jcs-v1",
        },
        "assessment": {
            "confidence_vector_ref": HEX_B,
            "confidence_vector_schema_version": "1",
            "projection_id": "proj-1",
            "trajectory_reliability_ref": None,
            "hard_gate_results": [
                {
                    "gate_id": "HG-04",
                    "passed": True,
                    "reason_code": None,
                    "rule_version": "r1",
                    "inputs_hash": HEX_A,
                    "probabilistic": False,
                }
            ],
            "unresolved_conflicts": [],
            "outcome": "HOLD",
            "reason_codes": [],
            "evaluation_errors": [],
        },
        "ordering": {"sequence_number": 3, "previous_event_hash": HEX_B},
        "integrity": {
            "canonicalization": "JCS-RFC8785",
            "hash_alg": "sha256",
            "canonical_hash": HEX_A,
            "field_commitments": {},
            "signature": {
                "alg": "ed25519",
                "kid": "kid-test",
                "key_version": 1,
                "sig": "c" * 128,
                "signed_at": "2026-09-12T10:00:01Z",
            },
            "signature_ref": "sig:" + "d" * 32,
            "anchor_ref": None,
        },
    }
    d.update(overrides)
    return d


def _shuffled(obj: object, rng: random.Random) -> object:
    if isinstance(obj, dict):
        items = list(obj.items())
        rng.shuffle(items)
        return {k: _shuffled(v, rng) for k, v in items}
    if isinstance(obj, list):
        return [_shuffled(v, rng) for v in obj]
    return obj


def _all_keys(obj: object) -> set[str]:
    if isinstance(obj, dict):
        keys = set(obj)
        for v in obj.values():
            keys |= _all_keys(v)
        return keys
    if isinstance(obj, list):
        keys = set()
        for v in obj:
            keys |= _all_keys(v)
        return keys
    return set()


class TestModel:
    def test_valid_event_round_trips(self) -> None:
        ev = ProvenanceEvent.model_validate(_event_dict())
        assert ev.model_dump(mode="json") == _event_dict()

    def test_extra_fields_forbidden_at_every_level(self) -> None:
        d = _event_dict()
        d["surprise"] = 1
        with pytest.raises(ValidationError):
            ProvenanceEvent.model_validate(d)
        d = _event_dict()
        d["assessment"]["surprise"] = 1
        with pytest.raises(ValidationError):
            ProvenanceEvent.model_validate(d)

    def test_event_is_frozen(self) -> None:
        ev = ProvenanceEvent.model_validate(_event_dict())
        with pytest.raises(ValidationError):
            ev.event_id = f"evt_{ULID}"  # type: ignore[misc]

    @pytest.mark.parametrize(
        "path,value",
        [
            (("event_id",), "evt_lowercase0000000000000000"),
            (("activity", "trajectory_id"), "trj_short"),
            (("ordering", "previous_event_hash"), "A" * 64),
            (("ordering", "sequence_number"), -1),
            (("assessment", "outcome"), "MAYBE"),
            (("integrity", "signature", "sig"), "c" * 127),
            (("integrity", "signature", "key_version"), 0),
        ],
    )
    def test_invalid_values_rejected(self, path: tuple[str, ...], value: object) -> None:
        d = _event_dict()
        node = d
        for part in path[:-1]:
            node = node[part]
        node[path[-1]] = value
        with pytest.raises(ValidationError):
            ProvenanceEvent.model_validate(d)

    def test_unknown_reason_code_rejected_and_registered_code_accepted(self) -> None:
        d = _event_dict()
        d["assessment"]["reason_codes"] = ["DAG-XX-NOT_REGISTERED"]
        with pytest.raises(ValidationError):
            ProvenanceEvent.model_validate(d)
        d["assessment"]["reason_codes"] = [sorted(REGISTRY)[0]]
        ProvenanceEvent.model_validate(d)

    def test_genesis_equals_latch_value(self) -> None:
        # Asserted by test, not imported by the module (no latch dependency).
        from graqle.compliance.eu_ai_act_latch import _GENESIS_HASH

        assert GENESIS_HASH == _GENESIS_HASH
        src = Path(pe.__file__).read_text(encoding="utf-8")
        assert "eu_ai_act_latch" not in src.replace("eu_ai_act_latch._GENESIS_HASH", "")


class TestTimestamps:
    def test_captured_before_occurred_rejected_with_no_skew_configured(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(pe.SKEW_ENV_VAR, raising=False)
        d = _event_dict(occurred_at="2026-09-12T10:00:05Z", captured_at="2026-09-12T10:00:04Z")
        with pytest.raises(ValidationError):
            ProvenanceEvent.model_validate(d)

    def test_skew_tolerance_admits_small_inversion_only(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(pe.SKEW_ENV_VAR, "3")
        ProvenanceEvent.model_validate(
            _event_dict(occurred_at="2026-09-12T10:00:05Z", captured_at="2026-09-12T10:00:03Z")
        )
        with pytest.raises(ValidationError):
            ProvenanceEvent.model_validate(
                _event_dict(occurred_at="2026-09-12T10:00:05Z", captured_at="2026-09-12T10:00:01Z")
            )

    @pytest.mark.parametrize("bad", ["abc", "0", "-4", ""])
    def test_malformed_skew_setting_fails_closed(
        self, monkeypatch: pytest.MonkeyPatch, bad: str
    ) -> None:
        monkeypatch.setenv(pe.SKEW_ENV_VAR, bad)
        with pytest.raises(ValidationError):
            ProvenanceEvent.model_validate(_event_dict())

    @pytest.mark.parametrize("bad", ["2026-09-12T10:00:00", "2026-09-12T10:00:00+00:00", "nope"])
    def test_timestamps_must_be_utc_z(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            ProvenanceEvent.model_validate(_event_dict(occurred_at=bad))
        d = _event_dict()
        d["integrity"]["signature"]["signed_at"] = bad
        with pytest.raises(ValidationError):
            ProvenanceEvent.model_validate(d)


class TestCommittedForm:
    def test_present_redactable_fields_are_replaced_by_commitments(self) -> None:
        d = _event_dict()
        salts = generate_salts(d)
        assert set(salts) == set(REDACTABLE_FIELDS)
        cf = committed_form(d, salts)
        assert "integrity" not in cf
        for path in REDACTABLE_FIELDS:
            parent = cf
            *parents, key = path.split(".")
            for part in parents:
                parent = parent[part]
            assert set(parent[key]) == {"__commit"}
        # Non-redactable fields keep their values.
        assert cf["inputs"]["policy_refs"] == ["pol-1"]
        assert "agent-007" not in json.dumps(cf)

    def test_input_is_not_mutated(self) -> None:
        d = _event_dict()
        before = copy.deepcopy(d)
        committed_form(d, generate_salts(d))
        assert d == before

    def test_missing_salt_for_present_field_fails_closed(self) -> None:
        d = _event_dict()
        salts = generate_salts(d)
        del salts["inputs.claim_refs"]
        with pytest.raises(ProvenanceBuildError, match="missing salt"):
            committed_form(d, salts)
        with pytest.raises(ProvenanceBuildError, match="missing salt"):
            canonical_hash(d, salts)

    def test_absent_optional_field_needs_no_salt(self) -> None:
        d = _event_dict()
        del d["inputs"]["instruction_refs"]
        salts = generate_salts(d)
        assert "inputs.instruction_refs" not in salts
        _, commits = canonical_hash(d, salts)
        assert "inputs.instruction_refs" not in commits

    def test_structural_error_fails_closed(self) -> None:
        d = _event_dict()
        del d["actor"]
        with pytest.raises(ProvenanceBuildError, match="structural"):
            committed_form(d, {})
        d = _event_dict()
        d["inputs"] = ["not", "an", "object"]
        with pytest.raises(ProvenanceBuildError, match="structural"):
            committed_form(d, {"actor.agent_id": b"x" * 32})

    @pytest.mark.parametrize("salt", [b"", b"x" * 31, b"x" * 33, "x" * 32, None])
    def test_salt_must_be_exactly_32_bytes(self, salt: object) -> None:
        d = _event_dict()
        salts = generate_salts(d)
        salts["actor.agent_id"] = salt  # type: ignore[assignment]
        with pytest.raises(ProvenanceBuildError):
            canonical_hash(d, salts)


class TestCanonicalHashDeterminism:
    """AC-3 (platform and interpreter coverage comes from the CI matrix)."""

    def test_invariant_under_key_order(self) -> None:
        d = _event_dict()
        salts = generate_salts(d)
        base = canonical_hash(d, salts)
        rng = random.Random(0)
        for _ in range(200):
            assert canonical_hash(_shuffled(d, rng), salts) == base  # type: ignore[arg-type]

    def test_integrity_block_is_outside_the_hash(self) -> None:
        d = _event_dict()
        salts = generate_salts(d)
        base, _ = canonical_hash(d, salts)
        d["integrity"]["canonical_hash"] = HEX_B
        d["integrity"]["anchor_ref"] = {
            "batch_id": "b-1",
            "merkle_root_hex": HEX_A,
            "leaf_hash": HEX_B,
            "rekor_log_index": None,
            "rekor_log_id": None,
            "commit_status": "pending",
        }
        assert canonical_hash(d, salts)[0] == base

    def test_hash_is_sha256_of_canon_of_committed_form(self) -> None:
        from graqle.governance.tamper_evidence.canonicalize import canon

        d = _event_dict()
        salts = generate_salts(d)
        digest, _ = canonical_hash(d, salts)
        assert digest == hashlib.sha256(canon(committed_form(d, salts))).hexdigest()
        assert len(digest) == 64 and digest == digest.lower()

    def test_model_and_dict_paths_agree(self) -> None:
        d = _event_dict()
        salts = generate_salts(d)
        ev = ProvenanceEvent.model_validate(d)
        assert event_canonical_hash(ev, salts) == canonical_hash(d, salts)

    def test_stable_across_interpreter_hash_seeds(self) -> None:
        script = (
            "import json,sys\n"
            "from graqle.assurance.provenance_event import canonical_hash\n"
            "d=json.loads(sys.argv[1])\n"
            "s={p:bytes([i])*32 for i,p in enumerate(sorted(["
            "'actor.agent_id','inputs.evidence_refs',"
            "'inputs.claim_refs','inputs.instruction_refs']))}\n"
            "print(canonical_hash(d,s)[0])\n"
        )
        outs = set()
        for seed in ("0", "1", "12345"):
            env = {**os.environ, "PYTHONHASHSEED": seed}
            res = subprocess.run(
                [sys.executable, "-c", script, json.dumps(_event_dict())],
                capture_output=True,
                text=True,
                env=env,
                check=True,
            )
            outs.add(res.stdout.strip())
        assert len(outs) == 1

    def test_single_byte_flips_change_the_hash(self) -> None:
        d = _event_dict()
        salts = generate_salts(d)
        base, _ = canonical_hash(d, salts)
        rng = random.Random(1)
        seen = {base}
        for _ in range(500):
            m = copy.deepcopy(d)
            choice = rng.randrange(5)
            if choice == 0:
                m["ordering"]["sequence_number"] += rng.randrange(1, 10**6)
            elif choice == 1:
                m["activity"]["model_version"] += rng.choice("abcdefgh")
            elif choice == 2:
                m["ordering"]["previous_event_hash"] = f"{rng.getrandbits(256):064x}"
            elif choice == 3:
                m["inputs"]["policy_refs"].append(f"p{rng.getrandbits(64)}")
            else:
                m["occurred_at"] = f"2026-09-12T10:00:00.{rng.randrange(10**6):06d}Z"
            h, _ = canonical_hash(m, salts)
            if m != d:
                assert h != base
            seen.add(h)
        assert len(seen) > 1

    def test_changing_a_redacted_value_changes_the_hash(self) -> None:
        d = _event_dict()
        salts = generate_salts(d)
        base, _ = canonical_hash(d, salts)
        d["actor"]["agent_id"] = "agent-008"
        assert canonical_hash(d, salts)[0] != base

    @pytest.mark.parametrize("bad", [float("nan"), float("inf"), -0.0])
    def test_non_canonical_numbers_raise_build_error(self, bad: float) -> None:
        d = _event_dict()
        d["activity"]["checkpoint"] = bad
        with pytest.raises(ProvenanceBuildError, match="non-canonical"):
            canonical_hash(d, generate_salts(d))

    def test_non_json_native_value_raises_build_error(self) -> None:
        d = _event_dict()
        d["occurred_at"] = {1, 2}  # a set is not JSON-native
        with pytest.raises(ProvenanceBuildError):
            canonical_hash(d, generate_salts(d))

    def test_only_tamper_evidence_errors_are_translated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from graqle.governance.tamper_evidence import canonicalize

        def boom(_obj: object) -> bytes:
            raise RuntimeError("unrelated failure")

        monkeypatch.setattr(canonicalize, "canon", boom)
        d = _event_dict()
        with pytest.raises(RuntimeError, match="unrelated failure"):
            canonical_hash(d, generate_salts(d))


class TestRedaction:
    """AC-12, escrow half. The verifier half lands in PR-018c."""

    def test_disclosure_opens_only_with_the_right_value_and_salt(self) -> None:
        d = _event_dict()
        salts = generate_salts(d)
        _, commits = canonical_hash(d, salts)
        c = commits["actor.agent_id"]
        assert verify_disclosure(c, "agent-007", salts["actor.agent_id"])
        assert not verify_disclosure(c, "agent-008", salts["actor.agent_id"])
        assert not verify_disclosure(c, "agent-007", b"\x00" * 32)
        assert not verify_disclosure(c, "agent-007", b"short")
        assert not verify_disclosure(c, float("nan"), salts["actor.agent_id"])
        assert not verify_disclosure(None, "agent-007", salts["actor.agent_id"])  # type: ignore[arg-type]
        assert not verify_disclosure(c.upper(), "agent-007", salts["actor.agent_id"])
        assert not verify_disclosure(c + "\n", "agent-007", salts["actor.agent_id"])
        assert not verify_disclosure("é" * 64, "agent-007", salts["actor.agent_id"])
        assert not verify_disclosure("", "agent-007", salts["actor.agent_id"])

    def test_hash_survives_erasure_of_every_salt_and_value(self, tmp_path: Path) -> None:
        from graqle.governance.tamper_evidence.canonicalize import canon

        escrow = FileSaltEscrow(tmp_path / "salts")
        rng = random.Random(2)
        for i in range(1000):
            d = _event_dict(event_id=f"evt_{i:026d}")
            d["actor"]["agent_id"] = f"agent-{rng.getrandbits(32)}"
            d["inputs"]["evidence_refs"] = [f"e{rng.getrandbits(16)}" for _ in range(i % 4)]
            salts = generate_salts(d)
            digest, commits = canonical_hash(d, salts)
            escrow.put(d["event_id"], salts)

            # Redaction: salt and value are deleted from the escrow and the event.
            escrow.delete(d["event_id"])
            assert escrow.get(d["event_id"]) == {}
            redacted = copy.deepcopy(d)
            redacted.pop("integrity")
            for path, commit in commits.items():
                parent = redacted
                *parents, key = path.split(".")
                for part in parents:
                    parent = parent[part]
                parent[key] = {"__commit": commit}

            # The hash is recomputable from the commitments alone.
            assert hashlib.sha256(canon(redacted)).hexdigest() == digest
            # Without the salt a fresh commitment cannot be built: fail closed.
            with pytest.raises(ProvenanceBuildError):
                committed_form(d, escrow.get(d["event_id"]))


class TestForbiddenKeys:
    """AC-14 part 1."""

    def test_schema_has_no_forbidden_key(self) -> None:
        schema = ProvenanceEvent.model_json_schema()
        assert not (_all_keys(schema) & FORBIDDEN_ANCHOR_KEYS)

    @pytest.mark.parametrize("key", sorted(FORBIDDEN_ANCHOR_KEYS))
    def test_forbidden_key_anywhere_in_the_payload_is_refused(self, key: str) -> None:
        d = _event_dict()
        d["assessment"]["hard_gate_results"][0][key] = 1
        with pytest.raises(ProvenanceBuildError, match="forbidden key"):
            canonical_hash(d, generate_salts(d))
        d = _event_dict()
        d["extra_top"] = [{"nested": {key: "x"}}]
        with pytest.raises(ProvenanceBuildError, match="forbidden key"):
            canonical_hash(d, generate_salts(d))

    def test_fuzzed_valid_events_never_serialise_a_forbidden_key(self) -> None:
        rng = random.Random(3)
        for i in range(300):
            d = _event_dict(event_id=f"evt_{i:026d}")
            d["assessment"]["outcome"] = rng.choice(
                ["EXECUTE", "REPLAN", "HOLD", "REJECT", "ESCALATE", None]
            )
            d["assessment"]["hard_gate_results"] = [
                {
                    "gate_id": f"HG-0{rng.randrange(1, 8)}",
                    "passed": rng.random() < 0.5,
                    "reason_code": None,
                    "rule_version": f"r{rng.randrange(9)}",
                    "inputs_hash": f"{rng.getrandbits(256):064x}",
                    "probabilistic": rng.random() < 0.5,
                }
                for _ in range(rng.randrange(0, 8))
            ]
            ev = ProvenanceEvent.model_validate(d)
            payload = ev.model_dump(mode="json")
            assert not (_all_keys(payload) & FORBIDDEN_ANCHOR_KEYS)
            canonical_hash(payload, generate_salts(payload))

    def test_event_fields_do_not_name_forbidden_keys(self) -> None:
        names: set[str] = set()
        for model in (
            pe.Actor,
            pe.Activity,
            pe.Inputs,
            pe.HardGateResult,
            pe.Assessment,
            pe.Ordering,
            pe.Signature,
            pe.AnchorRef,
            pe.Integrity,
            ProvenanceEvent,
        ):
            names |= set(model.model_fields)
        assert not (names & FORBIDDEN_ANCHOR_KEYS)


class TestNoNumericLiterals:
    """AC-14: the event module holds no numeric literal other than 0, 1, 32, 64."""

    ALLOWED = {0, 1, 32, 64}

    def test_provenance_event_has_no_stray_numeric_literal(self) -> None:
        tree = ast.parse(Path(pe.__file__).read_text(encoding="utf-8"))
        stray = sorted(
            {
                (n.value, n.lineno)
                for n in ast.walk(tree)
                if isinstance(n, ast.Constant)
                and isinstance(n.value, (int, float))
                and not isinstance(n.value, bool)
                and n.value not in self.ALLOWED
            }
        )
        assert stray == []

    def test_the_check_detects_a_stray_literal(self) -> None:
        tree = ast.parse("limit = 500\n")
        found = [
            n.value
            for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and n.value not in self.ALLOWED
        ]
        assert found == [500]
