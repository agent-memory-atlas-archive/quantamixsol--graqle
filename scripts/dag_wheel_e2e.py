#!/usr/bin/env python3
"""CR-DAG-087-1 PR-C: end-to-end check of the decision gate from the BUILT wheel.

``orchestrate`` (the default) builds the wheel from this checkout, installs the wheel (not the
source tree) into a fresh virtualenv and runs the README "turn it on" steps there, in a work
directory outside the checkout, as separate processes so the signed events are verified again
after a process restart.

The other sub-commands (``setup``, ``run``, ``verify``, ``flag-off``, ``bad-provider``) are the
steps executed inside the clean virtualenv. They use only the public API of the installed package.

Routing/threshold values below are symbolic test-environment values chosen for this script. They
are not product defaults and not private values.

Usage:
    python scripts/dag_wheel_e2e.py [--keep] [--workdir DIR]
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

EVENTS_DIR = Path(".graqle/dag/events")
MANIFEST = Path(".graqle/dag/key_manifest.json")
KID = "e2e-kid"
AGENT = "e2e-agent"

# Symbolic test-environment values (not product defaults).
TEST_ENV = {
    "GRAQLE_DAG_ENABLED": "1",
    "GRAQLE_DAG_CONFIG_SALT": "e2e-test-salt-" + "x" * 32,
    "GRAQLE_DAG_CAP_VALUE": "0.5",
    "GRAQLE_DAG_HG05_POISONING_THRESHOLD": "0.5",
    "GRAQLE_DAG_HG07_MATERIALITY_THRESHOLD": "0.5",
    "GRAQLE_DAG_CALIBRATOR_VERSION": "e2e",
    "GRAQLE_DAG_TRAJECTORY_ESTIMATOR": "causal_baseline",
    "GRAQLE_DAG_MAX_RETRY_BUDGET": "1",
    "GRAQLE_DAG_CIRCUIT_BREAKER_WINDOW": "1",
    "GRAQLE_DAG_SCOPE_KEY_FIELDS_REF": "e2e",
    "GRAQLE_DAG_MERGE_PRIORITY_REF": "sdk_default",
    "GRAQLE_DAG_SIGNING_KEY_ID": KID,
    "GRAQLE_DAG_SIGNING_KEY_VERSION": "1",
    "GRAQLE_DAG_SIGNING_KEY_PATH": "e2e_signing_key.pem",
    "GRAQLE_DAG_COVERAGE_POLICY_PATH": "coverage_policy.yaml",
    # HG-06 needs a registered role: a "senior" actor may take MEDIUM calls to HOLD.
    "GRAQLE_RBAC_ACTORS_JSON": json.dumps([{"actor_id": AGENT, "role": "senior"}]),
}


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    raise SystemExit(1)


def _ok(msg: str) -> None:
    print(f"ok: {msg}")


# ---------------------------------------------------------------- steps inside the clean venv


def cmd_setup() -> None:
    """README step: create an ed25519 signing key and the public key manifest."""
    from datetime import datetime, timedelta, timezone

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from graqle.assurance.key_manifest_store import save_manifest
    from graqle.governance.custody.ed25519_key_manifest import Ed25519KeyManifest

    key = Ed25519PrivateKey.generate()
    pem = Path(TEST_ENV["GRAQLE_DAG_SIGNING_KEY_PATH"])
    pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pem.chmod(0o600)
    now = datetime.now(timezone.utc)
    manifest = Ed25519KeyManifest()
    manifest.register(KID, key.public_key(), now - timedelta(days=1), now + timedelta(days=60))
    save_manifest(MANIFEST, manifest, {KID: 1})
    Path(TEST_ENV["GRAQLE_DAG_COVERAGE_POLICY_PATH"]).write_text("{}\n", encoding="utf-8")
    _ok("signing key (0600), key manifest and coverage policy file created")


def _check(**kw):
    from graqle.core.governance import GovernanceMiddleware

    return GovernanceMiddleware().check(**kw)


def cmd_run() -> None:
    """Flag on: the packaged provider registers at start-up and each call is decided + recorded."""
    from graqle.assurance import adapter

    adapter.ensure_runtime_registered()
    _ok("default runtime provider registered at start-up")

    # (label, check kwargs, expected outcome, expected reason code or None)
    cases = [
        ("LOW risk, zero impact", dict(risk_level="LOW", actor=AGENT), "EXECUTE", None),
        ("MEDIUM risk, registered senior actor", dict(risk_level="MEDIUM", actor=AGENT), "HOLD", "DAG-RT-NO-EVIDENCE"),
        ("MEDIUM risk, unregistered actor (HG-06)", dict(risk_level="MEDIUM", actor="e2e-unknown"), "REJECT", "DAG-HG06-ACTOR_UNAUTHORIZED"),
        ("HIGH risk, no provenance (HG-03)", dict(risk_level="HIGH", actor=AGENT), "REJECT", None),
    ]
    for label, kw, _outcome, _code in cases:
        res = _check(file_path="src/example.py", action="edit", impact_radius=0, **kw)
        print(f"  {label}: tier={res.tier} blocked={res.blocked} reason={res.reason!r}")
    events = [json.loads(p.read_text()) for p in EVENTS_DIR.glob("evt_*.json")]
    if len(events) != len(cases):
        _fail(f"expected {len(cases)} provenance events, found {len(events)}")
    events.sort(key=lambda e: e["ordering"]["sequence_number"])
    for (label, _kw, outcome, code), ev in zip(cases, events):
        got, codes = ev["assessment"]["outcome"], ev["assessment"]["reason_codes"]
        print(f"  recorded: {label}: outcome={got} reason_codes={codes}")
        if got != outcome or (code is not None and code not in codes):
            _fail(f"{label}: expected {outcome} {code}, recorded {got} {codes}")
        if len(ev["assessment"]["hard_gate_results"]) != 7:
            _fail(f"{label}: not all seven hard gates were evaluated")
        if "DAG-TR-010-EVALUATION_ERROR" in codes:
            _fail(f"{label}: DAG-TR-010 evaluation error")
    _ok("EXECUTE / HOLD / REJECT recorded with reason codes, seven hard gates each, one event per call")


def cmd_verify() -> None:
    """Fresh process: verify every event's signature and the hash chain from disk."""
    from datetime import datetime

    from graqle.assurance.key_manifest_store import load_manifest
    from graqle.assurance.signing import SCHEMA_VERSION
    from graqle.governance.tamper_evidence.canonicalize import canon

    manifest = load_manifest(MANIFEST).manifest
    events = [json.loads(p.read_text()) for p in EVENTS_DIR.glob("evt_*.json")]
    events.sort(key=lambda e: e["ordering"]["sequence_number"])
    if not events:
        _fail("no provenance events on disk")
    prev = "0" * 64
    for idx, ev in enumerate(events):
        order, integ = ev["ordering"], ev["integrity"]
        if order["sequence_number"] != idx:
            _fail(f"sequence gap at {idx}")
        if order["previous_event_hash"] != prev:
            _fail(f"chain broken at sequence {idx}")
        sig = integ["signature"]
        msg = canon(
            {
                "schema_version": SCHEMA_VERSION,
                "canonical_hash": integ["canonical_hash"],
                "previous_event_hash": order["previous_event_hash"],
                "sequence_number": order["sequence_number"],
                "kid": sig["kid"],
                "signed_at": sig["signed_at"],
            }
        )
        signed_at = datetime.fromisoformat(sig["signed_at"].replace("Z", "+00:00"))
        if not manifest.verify(sig["kid"], msg, bytes.fromhex(sig["sig"]), at=signed_at):
            _fail(f"signature does not verify at sequence {idx}")
        prev = integ["canonical_hash"]
    _ok(f"{len(events)} events: hash chain intact and every signature verifies")


def cmd_flag_off() -> None:
    """Flag off: legacy path only, the assurance adapter is never imported, nothing is recorded."""
    for name in list(os.environ):
        if name.startswith("GRAQLE_DAG_"):
            del os.environ[name]
    before = set(EVENTS_DIR.glob("evt_*.json"))
    res = _check(file_path="src/example.py", action="edit", actor="e2e-agent", risk_level="LOW")
    if "graqle.assurance.adapter" in sys.modules:
        _fail("adapter imported with the flag off")
    if set(EVENTS_DIR.glob("evt_*.json")) != before:
        _fail("provenance written with the flag off")
    print(f"  legacy result: tier={res.tier} blocked={res.blocked}")
    _ok("flag off: legacy path only, adapter not imported, no events written")


def cmd_bad_provider() -> None:
    """Flag on with an unusable signing key: start-up error naming register_runtime."""
    from graqle.assurance import adapter

    os.environ["GRAQLE_DAG_SIGNING_KEY_PATH"] = "does_not_exist.pem"
    adapter.register_runtime(None)
    try:
        adapter.ensure_runtime_registered()
    except adapter.RuntimeNotRegisteredError as exc:
        if "register_runtime" not in str(exc):
            _fail(f"start-up error does not name register_runtime: {exc}")
        print(f"  start-up error: {exc}")
        _ok("invalid provider -> start-up error naming register_runtime")
        return
    _fail("no start-up error with an unusable signing key")


# ---------------------------------------------------------------- orchestration (outside the venv)


def _run(cmd: list[str], *, cwd: Path, env: dict[str, str]) -> None:
    print(f"$ {' '.join(cmd)}", flush=True)
    done = subprocess.run(cmd, cwd=cwd, env=env, check=False)
    if done.returncode != 0:
        _fail(f"command exited {done.returncode}")


def orchestrate(workdir: Path | None, keep: bool) -> None:
    repo = Path(__file__).resolve().parent.parent
    root = Path(tempfile.mkdtemp(prefix="dag-wheel-e2e-")) if workdir is None else workdir
    root.mkdir(parents=True, exist_ok=True)
    dist, venv, run_dir = root / "dist", root / "venv", root / "run"
    run_dir.mkdir(exist_ok=True)
    base_env = {k: v for k, v in os.environ.items() if not k.startswith(("GRAQLE_", "PYTHON"))}

    _run([sys.executable, "-m", "build", "--wheel", "--outdir", str(dist)], cwd=repo, env=base_env)
    wheels = sorted(dist.glob("graqle-*.whl"))
    if len(wheels) != 1:
        _fail(f"expected one wheel in {dist}, found {wheels}")
    _run([sys.executable, "-m", "venv", str(venv)], cwd=root, env=base_env)
    py = str(venv / ("Scripts" if os.name == "nt" else "bin") / "python")
    _run([py, "-m", "pip", "install", "--quiet", str(wheels[0])], cwd=root, env=base_env)

    check = subprocess.run(
        [py, "-I", "-c", "import graqle; print(graqle.__file__)"],
        cwd=run_dir, env=base_env, capture_output=True, text=True, check=False,
    )
    print(f"installed package: {check.stdout.strip()}")
    if str(repo) in check.stdout or "site-packages" not in check.stdout:
        _fail("graqle is not imported from the installed wheel")

    me = str(Path(__file__).resolve())
    on_env = {**base_env, **TEST_ENV}
    for name in ("setup", "run", "verify", "flag-off", "bad-provider"):
        print(f"\n== {name}", flush=True)  # "verify" is a fresh process after "run": restart check
        _run([py, "-I", me, name], cwd=run_dir, env=on_env)
    print(f"\nALL STEPS PASSED (wheel: {wheels[0].name})")
    if not keep and workdir is None:
        print(f"work directory left at {root} (remove it when done)")


def main(argv: list[str]) -> None:
    sub = argv[1] if len(argv) > 1 and not argv[1].startswith("--") else "orchestrate"
    steps = {
        "setup": cmd_setup,
        "run": cmd_run,
        "verify": cmd_verify,
        "flag-off": cmd_flag_off,
        "bad-provider": cmd_bad_provider,
    }
    if sub in steps:
        steps[sub]()
        return
    workdir = Path(argv[argv.index("--workdir") + 1]) if "--workdir" in argv else None
    orchestrate(workdir, "--keep" in argv)


if __name__ == "__main__":
    main(sys.argv)
