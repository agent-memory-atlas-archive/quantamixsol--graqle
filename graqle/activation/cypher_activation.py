# ──────────────────────────────────────────────────────────────────
# PATENT NOTICE — Quantamix Solutions B.V.
#
# This module implements methods covered by European Patent
# Applications EP26162901.8 and EP26166054.2, owned by
# Quantamix Solutions B.V.
#
# Use of this software is permitted under the graqle license.
# Reimplementation of the patented methods outside this software
# requires a separate patent license.
#
# Contact: legal@quantamix.io
# ──────────────────────────────────────────────────────────────────

"""CypherActivation — Neo4j vector search activation strategy.

Replaces PCST entirely for Neo4j mode. Uses Cypher vector search on
chunk embeddings to directly find content-bearing nodes via their chunks.
No tree algorithm needed — the vector index handles relevance scoring.
"""

# ── graqle:intelligence ──
# module: graqle.activation.cypher_activation
# risk: LOW (impact radius: 2 modules)
# consumers: __init__, test_cypher_activation
# dependencies: __future__, logging, typing
# constraints: none
# ── /graqle:intelligence ──

from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger("graqle.activation.cypher")

#: TTL for the diagnostic vector-index probe (sentinel M1). Short enough that
#: an operator fixing the index sees the change almost immediately; long enough
#: that a retry storm cannot amplify load on an already-failing substrate.
_PROBE_TTL_SECONDS = 30.0


class CypherActivation:
    """Activate subgraph nodes via Neo4j chunk-level vector search.

    Instead of PCST (embed query → cosine similarity on node descriptions →
    prize assignment → Steiner tree), CypherActivation:

    1. Embeds the query
    2. Calls ``db.index.vector.queryNodes()`` on chunk embeddings
    3. Maps chunks back to parent GraqleNode IDs
    4. Returns (node_ids, relevance_scores) — same interface as PCSTActivation

    This is faster, more accurate (searches chunk-level content), and
    eliminates PCST's structural bias toward directory/parent nodes.
    """

    def __init__(
        self,
        connector: Any,
        embedding_engine: Any,
        max_nodes: int = 50,
        k_chunks: int = 100,
        strict: bool = False,
    ) -> None:
        """
        Args:
            connector: Neo4jConnector with vector_search method.
            embedding_engine: Object with an ``embed(text) -> list[float]`` method.
            max_nodes: Maximum number of nodes to activate.
            k_chunks: Number of chunks to retrieve from vector index (more chunks
                      means better coverage but slower).
            strict: CR-012 PR-012d (ruling N7). When True, a substrate that
                cannot activate raises
                :class:`~graqle.core.exceptions.VectorIndexMissingError` instead
                of degrading to the full graph. Default False preserves
                v0.83.0 behaviour except that the degraded path now logs at
                ERROR and is reported via :attr:`activation_mode`.
        """
        self._connector = connector
        self._embedding_engine = embedding_engine
        self._max_nodes = max_nodes
        self._k_chunks = k_chunks
        self._strict = strict
        self.last_relevance: dict[str, float] = {}
        #: What actually executed on the last ``activate`` call — NOT what was
        #: configured. ``"semantic"`` is the healthy vector path;
        #: ``"keyword_fallback"`` means the whole graph was returned because
        #: activation could not run. Read by the graph-health probe, which
        #: treats ``keyword_fallback`` as degraded.
        self.activation_mode: str = "semantic"
        #: Chunks with no embedding at the last degradation, when known.
        self.chunks_unembedded: int = 0
        #: Cached ``probe_vector_index()`` result + monotonic timestamp.
        self._probe_cache: tuple[float, dict[str, Any]] | None = None

    def _probe_cached(self) -> dict[str, Any]:
        """Diagnostic probe with a short TTL.

        Sentinel M1: ``_degrade`` runs on a path that is ALREADY failing. Probing
        the substrate on every call amplifies load on the degraded resource at
        the worst possible moment — a retry loop or concurrent burst would issue
        one live round-trip per failure. The result is diagnostic metadata, so a
        few seconds of staleness costs nothing.

        Never raises: diagnosis must not become a second failure mode.
        """
        now = time.monotonic()
        if self._probe_cache is not None and (now - self._probe_cache[0]) < _PROBE_TTL_SECONDS:
            return self._probe_cache[1]

        probe: dict[str, Any] = {}
        try:
            probe_fn = getattr(self._connector, "probe_vector_index", None)
            if callable(probe_fn):
                probe = probe_fn() or {}
        except Exception:  # noqa: BLE001 — diagnosis must never mask the defect
            probe = {}

        self._probe_cache = (now, probe)
        return probe

    def _degrade(self, graph: Any, reason: str, exc: Exception | None = None) -> list[str]:
        """Fall back to the full graph, loudly.

        Every degraded activation logs at ERROR and is visible in
        ``graph_health`` — the silent-WARNING path this replaces is the defect
        ruling N7 was raised against. When ``strict`` is set the caller gets a
        typed error instead of a quietly wrong answer.
        """
        probe = self._probe_cached()

        total = probe.get("chunks_total")
        embedded = probe.get("chunks_embedded")
        self.chunks_unembedded = (
            max(0, int(total) - int(embedded))
            if isinstance(total, int) and isinstance(embedded, int)
            else 0
        )
        self.activation_mode = "keyword_fallback"

        # Sentinel B1: log LEVEL is an observable contract that alerting keys
        # on. The default (non-strict) path keeps v0.83.0's WARNING so a
        # graceful fallback does not start paging operators; only an opt-in
        # strict caller — who has asked to treat this as fatal — gets ERROR.
        # The enriched CONTENT (index state + coverage) lands on both paths,
        # which is the "log fields" improvement ruling N7 asked for.
        logger.log(
            logging.ERROR if self._strict else logging.WARNING,
            "CypherActivation DEGRADED (%s): returning the full graph, so this "
            "result is NOT retrieval-grounded. vector index %r state=%s "
            "chunk embedding coverage=%s/%s%s",
            reason,
            probe.get("index_name", "?"),
            probe.get("index_state", "?"),
            embedded if embedded is not None else "?",
            total if total is not None else "?",
            f" ({type(exc).__name__}: {exc})" if exc is not None else "",
        )

        if self._strict:
            from graqle.core.exceptions import VectorIndexMissingError

            raise VectorIndexMissingError(
                index_name=str(probe.get("index_name", "unknown")),
                database=probe.get("database"),
                index_state=probe.get("index_state"),
                chunks_total=total,
                chunks_embedded=embedded,
            ) from exc

        self.last_relevance = {nid: 1.0 for nid in graph.nodes}
        return list(graph.nodes.keys())[:self._max_nodes]

    def activate(
        self,
        graph: Any,
        query: str,
        strict: bool | None = None,
    ) -> list[str]:
        """Activate nodes by vector search on chunk embeddings.

        Side effect: stores relevance scores in ``self.last_relevance``
        for use in confidence calibration (Bug 18 fix), and records what
        actually ran in ``self.activation_mode``.

        Args:
            strict: per-call override of the constructor's ``strict``. When
                True, an unusable substrate raises ``VectorIndexMissingError``.

        Returns:
            List of activated node IDs present in the graph.
        """
        previous_strict = self._strict
        if strict is not None:
            self._strict = strict
        try:
            # 1. Embed the query
            try:
                query_embedding = self._embedding_engine.embed(query)
            except Exception as exc:
                return self._degrade(graph, "query embedding failed", exc)

            # 2. Vector search → (node_id, relevance) pairs
            try:
                hits = self._connector.vector_search(
                    query_embedding=query_embedding,
                    k=self._k_chunks,
                    max_nodes=self._max_nodes,
                )
            except Exception as exc:
                return self._degrade(graph, "vector search failed", exc)

            if not hits:
                return self._degrade(graph, "vector search returned 0 hits")
        finally:
            self._strict = previous_strict

        self.activation_mode = "semantic"

        # 3. Filter to nodes that exist in the in-memory graph
        activated = []
        relevance: dict[str, float] = {}
        for node_id, score in hits:
            if node_id in graph.nodes:
                activated.append(node_id)
                relevance[node_id] = score

        self.last_relevance = relevance

        logger.info(
            "CypherActivation: %d nodes activated (top relevance: %.3f)",
            len(activated),
            hits[0][1] if hits else 0.0,
        )
        return activated
