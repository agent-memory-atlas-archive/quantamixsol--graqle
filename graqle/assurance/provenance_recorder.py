"""ProvenanceRecorder: build, hash, sign, link, persist, optionally anchor (CR-018 PR-018b, spec 5.3).

Order of effects: allocate the next slot (compare-and-swap) -> escrow the salts
-> persist the committed form -> optional ``Committer.submit``. Any failure
raises :class:`ProvenanceUnavailableError`; the gate maps that to HOLD and
execution never proceeds without its provenance event. A ``Committer`` failure
never propagates: the event stays valid and ``anchor_ref`` stays ``None``.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.provenance_recorder
# risk: MEDIUM (write path of the audit chain; new module, constructed only when GRAQLE_DAG_ENABLED)
# dependencies: graqle.assurance.{provenance_event,sequencer,salt_escrow,signing,provenance_store},
#   graqle.governance.tamper_evidence.merkle
# constraints: AC-14 no numeric literals other than 0/1/32/64; committer.py and
#   leaf_input_schema.py are NOT modified; no threshold or weight enters an event
# -- /graqle:intelligence --
import hashlib
import logging
import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any

from graqle.assurance._ids import NS_DAG, new_id, rfc3339, utcnow
from graqle.assurance.provenance_event import (
    Activity,
    Actor,
    Assessment,
    EventType,
    Inputs,
    Integrity,
    Ordering,
    ProvenanceEvent,
    Signature,
    _parse,
    canonical_hash,
    committed_form,
    generate_salts,
)
from graqle.assurance.provenance_settings import ProvenanceSettings
from graqle.assurance.salt_escrow import SaltEscrow
from graqle.assurance.sequencer import (
    SequenceConflictError,
    TrajectorySequencer,
    append_with_retry,
)
from graqle.assurance.signing import DagSigner
from graqle.core.exceptions import GraqleError
from graqle.governance.tamper_evidence.canonicalize import canon

__all__ = [
    "ProvenanceRecorder",
    "ProvenanceUnavailableError",
    "ALLOWED_KEYING",
    "leaf_record",
    "anchor_ref_from_commit",
]

_log = logging.getLogger("graqle.assurance.provenance_recorder")

#: Closed allow-list of ``config_provenance.keying`` tags that may be anchored.
#: A new scheme is added here, in the PR that can produce it, never before.
ALLOWED_KEYING: frozenset[str] = frozenset({"deployment_salt_v1"})

_PROOF_FORMAT_VERSION = "1.0.0"  # leaf axis, unchanged
_GOVERNANCE_SCHEMA_VERSION = "2"
_NO_OUTCOME = "NONE"
_SIG_REF_HEX = 32  # sha256 hex characters kept in signature_ref


class ProvenanceUnavailableError(GraqleError):
    """The event could not be recorded; ``reason_code`` is a registered DAG-PV code."""

    def __init__(self, reason_code: str, detail: str = "") -> None:
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {detail}" if detail else reason_code)


def leaf_record(event: ProvenanceEvent) -> dict[str, Any]:
    """The exact five-key record submitted to the Committer (spec 4.2)."""
    return {
        "proof_format_version": _PROOF_FORMAT_VERSION,
        "record_id": event.event_id,
        "content_hash": event.integrity.canonical_hash,
        "timestamp_unix": int(_parse(event.captured_at).timestamp()),
        "governance_metadata": {
            "schema_version": _GOVERNANCE_SCHEMA_VERSION,
            "outcome": event.assessment.outcome or _NO_OUTCOME,
            "event_schema_version": event.schema_version,
            "event_type": event.event_type.value,
            "trajectory_id": event.activity.trajectory_id,
            "checkpoint": event.activity.checkpoint,
            "sequence_number": event.ordering.sequence_number,
            "previous_event_hash": event.ordering.previous_event_hash,
        },
    }


def anchor_ref_from_commit(commit_record: Any) -> dict[str, Any] | None:
    """``AnchorRef`` dict from a ``CommitRecord``, or ``None`` until it is committed."""
    batch_id = getattr(commit_record, "batch_id", None)
    root = getattr(commit_record, "merkle_root_hex", None)
    if not batch_id or not root:
        return None  # PENDING (or FAILED): nothing to point at yet; reported honestly
    status = getattr(commit_record, "commit_status", None)
    return {
        "batch_id": batch_id,
        "merkle_root_hex": root,
        "leaf_hash": commit_record.record_hash,
        "rekor_log_index": getattr(commit_record, "rekor_log_index", None),
        "rekor_log_id": getattr(commit_record, "rekor_log_id", None),
        "commit_status": getattr(status, "value", str(status)),
    }


class ProvenanceRecorder:
    def __init__(
        self,
        cfg: ProvenanceSettings,
        signer: DagSigner,
        sequencer: TrajectorySequencer,
        escrow: SaltEscrow,
        store: Any,
        committer: Any | None = None,
        clock: Callable[[], datetime] = utcnow,
        keying: Callable[[], str] | None = None,
    ) -> None:
        self.cfg = cfg
        self.signer = signer
        self.sequencer = sequencer
        self.escrow = escrow
        self.store = store
        self.committer = committer
        self.clock = clock
        self._keying = keying

    def _anchoring(self) -> bool:
        return bool(self.cfg.merkle_batch and self.committer is not None)

    def _check_keying(self) -> None:
        if not self._anchoring():
            return
        keying = self._keying() if self._keying is not None else _config_keying()
        if keying not in ALLOWED_KEYING:  # closed set, exact match only
            raise ProvenanceUnavailableError("DAG-PV-KEYING_UNRECOGNISED")

    def record(
        self,
        *,
        event_type: EventType,
        actor: Actor,
        activity: Activity,
        inputs: Inputs,
        assessment: Assessment,
        occurred_at: str,
        signer: DagSigner | None = None,
    ) -> ProvenanceEvent:
        use_signer = signer or self.signer
        event_id = new_id("evt")
        built: dict[str, Any] = {}
        self._check_keying()

        def hash_for(seq: int, prev: str) -> str:
            draft = {
                "event_id": event_id,
                "event_type": event_type.value,
                "schema_version": "0.1.0",
                "occurred_at": occurred_at,
                "captured_at": rfc3339(self.clock()),
                "actor": actor.model_dump(mode="json"),
                "activity": activity.model_dump(mode="json"),
                "inputs": inputs.model_dump(mode="json"),
                "assessment": assessment.model_dump(mode="json"),
                "ordering": Ordering(sequence_number=seq, previous_event_hash=prev).model_dump(
                    mode="json"
                ),
            }
            salts = generate_salts(draft)
            chash, commits = canonical_hash(draft, salts)
            signed_at = rfc3339(self.clock())
            sig_hex, kid, kver = use_signer.sign_event(chash, prev, seq, signed_at)
            sig = Signature(kid=kid, key_version=kver, sig=sig_hex, signed_at=signed_at)
            sig_ref = "sig:" + _sha256_hex(canon(sig.model_dump(mode="json")))[:_SIG_REF_HEX]
            integrity = Integrity(
                canonical_hash=chash,
                field_commitments=commits,
                signature=sig,
                signature_ref=sig_ref,
            )
            built.update(
                event=ProvenanceEvent(**draft, integrity=integrity),
                committed={**committed_form(draft, salts), "integrity": integrity.model_dump(mode="json")},
                salts=salts,
            )
            return chash

        trajectory_id = activity.trajectory_id
        try:
            append_with_retry(self.sequencer, trajectory_id, hash_for, self.cfg.seq_retry_budget)
        except SequenceConflictError as exc:
            raise ProvenanceUnavailableError("DAG-PV-SEQ-CONFLICT", exc.reason) from exc
        except Exception as exc:  # fail closed: build, hash, sign or head read failed
            raise ProvenanceUnavailableError("DAG-PV-RECORD-FAILED", type(exc).__name__) from exc

        event: ProvenanceEvent = built["event"]
        try:
            self.escrow.put(event.event_id, built["salts"])  # BEFORE persist
            self.store.persist(built["committed"])
        except Exception as exc:
            # The head already advanced: the verifier reports this slot as a gap.
            raise ProvenanceUnavailableError("DAG-PV-RECORD-FAILED", type(exc).__name__) from exc
        self._submit(event)
        return event

    def _submit(self, event: ProvenanceEvent) -> None:
        if not self._anchoring():
            return
        try:
            cr = self.committer.submit(  # type: ignore[union-attr]
                leaf_record(event), trace_id=uuid.uuid5(NS_DAG, event.event_id)
            )
            self.refresh_anchor(event, cr)
        except Exception as exc:  # committer contract: never propagates
            _log.warning("dag.provenance.anchor_failed event=%s err=%s", event.event_id, type(exc).__name__)

    def refresh_anchor(self, event: ProvenanceEvent, commit_record: Any | None = None) -> bool:
        """Copy the Committer's current status into ``anchor_ref`` (outside ``canonical_hash``)."""
        if self.committer is None:
            return False
        cr = commit_record or self.committer.commit_record_for(leaf_record(event))
        ref = anchor_ref_from_commit(cr) if cr is not None else None
        if ref is None:
            return False
        self.store.attach_anchor(event.event_id, ref)
        return True


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _config_keying() -> str:
    # Deferred: settings imports the whole DAG config stack; keep it off the import path.
    from graqle.assurance.settings import config_provenance

    return config_provenance().get("keying", "")
