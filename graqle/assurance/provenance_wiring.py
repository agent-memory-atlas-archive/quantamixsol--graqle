"""Build a :class:`ProvenanceRecorder` from :class:`ProvenanceSettings` (CR-018 PR-018b).

The only place that maps ``sequencer`` / ``salt_escrow`` settings to backends.
A Neo4j backend needs a driver; asking for one without a driver fails closed.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.provenance_wiring
# risk: LOW (new module; consumer is `graq dag rotate-key`)
# dependencies: graqle.assurance.{provenance_recorder,provenance_store,salt_escrow,sequencer,signing}
# constraints: no backend is constructed unless the DAG flag path calls this
# -- /graqle:intelligence --
from typing import Any

from graqle.assurance.provenance_recorder import ProvenanceRecorder
from graqle.assurance.provenance_settings import ProvenanceSettings
from graqle.assurance.provenance_store import FileProvenanceStore, Neo4jProvenanceStore
from graqle.assurance.salt_escrow import FileSaltEscrow, Neo4jSaltEscrow
from graqle.assurance.sequencer import (
    FileLockTrajectorySequencer,
    Neo4jTrajectorySequencer,
    ensure_provenance_schema,
)
from graqle.assurance.signing import DagSigner
from graqle.config.exceptions import ConfigurationError

__all__ = ["build_recorder", "needs_neo4j"]


def needs_neo4j(cfg: ProvenanceSettings) -> bool:
    return "neo4j" in (cfg.sequencer, cfg.salt_escrow)


def build_recorder(
    cfg: ProvenanceSettings,
    signer: DagSigner,
    *,
    driver: Any | None = None,
    committer: Any | None = None,
) -> ProvenanceRecorder:
    if needs_neo4j(cfg) and driver is None:
        raise ConfigurationError("a Neo4j driver is required by GRAQLE_DAG_SEQUENCER/_SALT_ESCROW")
    if needs_neo4j(cfg):
        ensure_provenance_schema(driver)  # idempotent uniqueness constraints
    sequencer = Neo4jTrajectorySequencer(driver) if cfg.sequencer == "neo4j" else FileLockTrajectorySequencer()
    escrow = Neo4jSaltEscrow(driver) if cfg.salt_escrow == "neo4j" else FileSaltEscrow(cfg.salt_escrow_dir)
    # Events live where the chain head lives.
    store = Neo4jProvenanceStore(driver) if cfg.sequencer == "neo4j" else FileProvenanceStore()
    return ProvenanceRecorder(cfg, signer, sequencer, escrow, store, committer=committer)
