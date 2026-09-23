"""CR-012 PR-012d (ruling N7) — AC-23: activation must fail VISIBLY.

The defect: on a neo4j-first project whose substrate has no vector index (or
zero chunk embeddings), ``vector_search`` raised deep inside the driver, the
activator caught the bare ``Exception``, logged at WARNING, and returned the
whole graph. Every retrieval-dependent answer was then produced from a
substrate that could not activate — with no error, and no signal in
``graph_health`` or ``graq doctor``.

These tests assert OBSERVABLE BEHAVIOUR (raise / log level / reported mode),
never source strings.

NOTE ON LOCATION: this file lives in ``tests/test_activation/`` and NOT in
``test_cypher_activation.py`` because that module is in the ci.yml
``--ignore`` list — AC-23 tests placed there would never run in CI.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from graqle.activation.cypher_activation import CypherActivation
from graqle.activation.multi_signal import MultiSignalActivation
from graqle.core.exceptions import GraqleError, VectorIndexMissingError


class _Graph:
    def __init__(self, n: int = 5) -> None:
        self.nodes = {f"node{i}": object() for i in range(n)}


class _Embedder:
    def embed(self, query: str) -> list[float]:  # noqa: ARG002
        return [0.1] * 1024


class _FailingEmbedder:
    def embed(self, query: str) -> list[float]:  # noqa: ARG002
        raise RuntimeError("embedding backend unreachable")


_UNUSABLE_PROBE = {
    "index_name": "cogni_chunk_embedding_index",
    "database": "research",
    "index_state": "NOT_FOUND",
    "chunks_total": 3722,
    "chunks_embedded": 0,
    "usable": False,
}


class _Connector:
    """Connector whose vector_search fails the way a missing index does."""

    def __init__(self, mode: str = "raise") -> None:
        self._mode = mode

    def vector_search(self, **kwargs: Any) -> list[tuple[str, float]]:  # noqa: ARG002
        if self._mode == "raise":
            raise RuntimeError("no such vector index")
        return []  # index present but matched nothing

    def probe_vector_index(self) -> dict[str, Any]:
        return dict(_UNUSABLE_PROBE)


class _HealthyConnector:
    def vector_search(self, **kwargs: Any) -> list[tuple[str, float]]:  # noqa: ARG002
        return [("node1", 0.91), ("node2", 0.77)]

    def probe_vector_index(self) -> dict[str, Any]:
        return {**_UNUSABLE_PROBE, "index_state": "ONLINE",
                "chunks_embedded": 3722, "usable": True}


def _activators(strict: bool = False) -> list[Any]:
    """Both activators — the spec requires `strict` on BOTH."""
    return [
        CypherActivation(connector=_Connector(), embedding_engine=_Embedder(),
                         max_nodes=3, strict=strict),
        MultiSignalActivation(connector=_Connector(), embedding_engine=_Embedder(),
                              max_nodes=3, strict=strict),
    ]


class TestStrictRaises:
    """AC-23: ``strict=True`` ⇒ VectorIndexMissingError."""

    @pytest.mark.parametrize("activator", _activators(strict=True))
    def test_strict_constructor_raises(self, activator: Any) -> None:
        with pytest.raises(VectorIndexMissingError):
            activator.activate(_Graph(), "any query")

    @pytest.mark.parametrize("activator", _activators())
    def test_strict_per_call_override_raises(self, activator: Any) -> None:
        with pytest.raises(VectorIndexMissingError):
            activator.activate(_Graph(), "any query", strict=True)

    @pytest.mark.parametrize("activator", _activators())
    def test_per_call_strict_does_not_leak(self, activator: Any) -> None:
        # A strict call must not permanently flip the instance.
        with pytest.raises(VectorIndexMissingError):
            activator.activate(_Graph(), "q", strict=True)
        activator.activate(_Graph(), "q")  # must NOT raise

    def test_error_is_a_graqle_error(self) -> None:
        assert issubclass(VectorIndexMissingError, GraqleError)

    def test_error_carries_diagnostic_state(self) -> None:
        activator = CypherActivation(connector=_Connector(),
                                     embedding_engine=_Embedder(), strict=True)
        with pytest.raises(VectorIndexMissingError) as caught:
            activator.activate(_Graph(), "q")
        err = caught.value
        assert err.index_name == "cogni_chunk_embedding_index"
        assert err.chunks_total == 3722
        assert err.chunks_embedded == 0
        assert "graq doctor" in str(err)

    def test_zero_hits_also_raises_under_strict(self) -> None:
        # An index that matches nothing is indistinguishable from a missing one
        # to a bare except — strict must surface both.
        activator = CypherActivation(connector=_Connector(mode="empty"),
                                     embedding_engine=_Embedder(), strict=True)
        with pytest.raises(VectorIndexMissingError):
            activator.activate(_Graph(), "q")

    def test_embedding_failure_also_raises_under_strict(self) -> None:
        activator = CypherActivation(connector=_Connector(),
                                     embedding_engine=_FailingEmbedder(), strict=True)
        with pytest.raises(VectorIndexMissingError):
            activator.activate(_Graph(), "q")


class TestDefaultDegradesButLoudly:
    """Default preserves v0.83.0 behaviour EXCEPT the log level + health fields."""

    @pytest.mark.parametrize("activator", _activators())
    def test_default_returns_fallback_without_raising(self, activator: Any) -> None:
        result = activator.activate(_Graph(), "q")
        assert result == ["node0", "node1", "node2"]

    @pytest.mark.parametrize("activator", _activators())
    def test_default_path_logs_at_warning_not_error(
        self, activator: Any, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Sentinel B1: log LEVEL is an observable contract that alerting keys
        # on. `strict` defaults to False and must preserve v0.83.0's WARNING,
        # so a graceful fallback does not start paging operators. What ruling
        # N7 adds on this path is the CONTENT (index state + coverage), not a
        # level escalation.
        with caplog.at_level(logging.WARNING):
            activator.activate(_Graph(), "q")
        degraded = [r for r in caplog.records if "DEGRADED" in r.message]
        assert degraded, "a degraded activation must be logged"
        assert all(r.levelno == logging.WARNING for r in degraded)

    @pytest.mark.parametrize("activator", _activators())
    def test_degraded_log_names_index_state_and_coverage(
        self, activator: Any, caplog: pytest.LogCaptureFixture
    ) -> None:
        # The diagnostic content ruling N7 asked for, on the DEFAULT path.
        with caplog.at_level(logging.WARNING):
            activator.activate(_Graph(), "q")
        text = " ".join(r.getMessage() for r in caplog.records if "DEGRADED" in r.message)
        assert "NOT_FOUND" in text
        assert "0/3722" in text

    def test_strict_path_logs_at_error(self, caplog: pytest.LogCaptureFixture) -> None:
        # An opt-in strict caller has asked to treat this as fatal, so ERROR
        # is appropriate there — and only there.
        activator = CypherActivation(connector=_Connector(),
                                     embedding_engine=_Embedder(), strict=True)
        with caplog.at_level(logging.WARNING):
            with pytest.raises(VectorIndexMissingError):
                activator.activate(_Graph(), "q")
        degraded = [r for r in caplog.records if "DEGRADED" in r.message]
        assert degraded and all(r.levelno == logging.ERROR for r in degraded)


class TestProbeIsRateLimited:
    """Sentinel M1: _degrade runs on an ALREADY-failing path."""

    def test_probe_is_not_called_on_every_degradation(self) -> None:
        class _CountingConnector(_Connector):
            def __init__(self) -> None:
                super().__init__()
                self.probe_calls = 0

            def probe_vector_index(self) -> dict[str, Any]:
                self.probe_calls += 1
                return dict(_UNUSABLE_PROBE)

        conn = _CountingConnector()
        activator = CypherActivation(connector=conn, embedding_engine=_Embedder(),
                                     max_nodes=3)
        for _ in range(5):
            activator.activate(_Graph(), "q")
        # A retry storm must not issue one live round-trip per failure.
        assert conn.probe_calls == 1, (
            f"probe hit the substrate {conn.probe_calls}x across 5 degradations"
        )

    def test_cached_probe_still_reports_coverage(self) -> None:
        activator = CypherActivation(connector=_Connector(),
                                     embedding_engine=_Embedder(), max_nodes=3)
        activator.activate(_Graph(), "q")
        activator.activate(_Graph(), "q")
        assert activator.chunks_unembedded == 3722

    @pytest.mark.parametrize("activator", _activators())
    def test_activation_mode_reports_the_degradation(self, activator: Any) -> None:
        activator.activate(_Graph(), "q")
        assert activator.activation_mode == "keyword_fallback"

    @pytest.mark.parametrize("activator", _activators())
    def test_chunks_unembedded_is_surfaced(self, activator: Any) -> None:
        activator.activate(_Graph(), "q")
        assert activator.chunks_unembedded == 3722


class TestHealthyPathUnchanged:
    """A working substrate must behave exactly as before."""

    def test_semantic_mode_reported(self) -> None:
        activator = CypherActivation(connector=_HealthyConnector(),
                                     embedding_engine=_Embedder(), max_nodes=5)
        activated = activator.activate(_Graph(), "q")
        assert activated == ["node1", "node2"]
        assert activator.activation_mode == "semantic"

    def test_healthy_path_logs_no_error(self, caplog: pytest.LogCaptureFixture) -> None:
        activator = CypherActivation(connector=_HealthyConnector(),
                                     embedding_engine=_Embedder(), max_nodes=5)
        with caplog.at_level(logging.ERROR):
            activator.activate(_Graph(), "q")
        assert not [r for r in caplog.records if r.levelno >= logging.ERROR]

    def test_strict_does_not_raise_on_a_healthy_substrate(self) -> None:
        activator = CypherActivation(connector=_HealthyConnector(),
                                     embedding_engine=_Embedder(), strict=True)
        assert activator.activate(_Graph(), "q") == ["node1", "node2"]


class TestProbeNeverRaises:
    """The probe is a diagnostic — it must never become a new failure mode."""

    def test_activation_still_degrades_when_probe_itself_fails(self) -> None:
        class _BadProbe(_Connector):
            def probe_vector_index(self) -> dict[str, Any]:
                raise RuntimeError("probe exploded")

        activator = CypherActivation(connector=_BadProbe(),
                                     embedding_engine=_Embedder(), max_nodes=3)
        assert activator.activate(_Graph(), "q") == ["node0", "node1", "node2"]
        assert activator.activation_mode == "keyword_fallback"

    def test_connector_without_a_probe_still_degrades(self) -> None:
        class _Legacy:
            def vector_search(self, **kwargs: Any) -> list[tuple[str, float]]:  # noqa: ARG002
                raise RuntimeError("boom")

        activator = CypherActivation(connector=_Legacy(),
                                     embedding_engine=_Embedder(), max_nodes=3)
        assert activator.activate(_Graph(), "q") == ["node0", "node1", "node2"]
        assert activator.activation_mode == "keyword_fallback"
