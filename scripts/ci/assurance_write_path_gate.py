#!/usr/bin/env python3
"""DAG CR-016 PR-016b: the assurance write path is single, and CI proves it.

Research ruling 2026-09-28 (option B): every write of an assurance write-once
field, and every creation or deletion of a SUPERSEDES/CORRECTS edge, goes
through ONE private module,
``graqle/governance/tamper_evidence/_assurance_write.py``, reached only via
``Neo4jBatchPersister.persist_assurance_ops``. This gate fails when:

1. any string in a scanned file (constants, f-string text, ``+`` concatenations
   of literals) looks like Cypher that writes a protected field or
   creates/sets/deletes a SUPERSEDES/CORRECTS edge, outside the allowed module;
2. anything other than ``kg_persist.py`` imports the private module.

It parses the AST; it never greps (Research standing rule 3). Docstrings are
skipped, because prose is not Cypher. It is a lint and can be evaded (runtime
string building with ``str.join``, ``exec``); the read-only
``verify_assurance_integrity`` is the backstop that DETECTS any write the gate
missed.

Scope: ``--root`` may be repeated. The default is ``graqle``. Research asked for
their scripts to be scanned too; a follow-up adds those roots in CI.

Usage:
    python scripts/ci/assurance_write_path_gate.py [--root graqle] [--root <dir>] ...
Exit 0 = clean, 1 = violations (listed), 2 = usage error.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

#: The one module allowed to carry protected Cypher.
ALLOWED_WRITER = "graqle/governance/tamper_evidence/_assurance_write.py"
#: The one module allowed to import it.
ALLOWED_IMPORTER = "graqle/governance/tamper_evidence/kg_persist.py"
PRIVATE_MODULE = "graqle.governance.tamper_evidence._assurance_write"

_FIELDS = (
    r"valid_from|asserted_at|canonical_id|scope_key|assurance_type|integrity_digest|"
    r"integrity_hmac_version|supersedes_in|supersedes_out|corrects_in|corrects_out|assurance_filled_fields"
)
_KINDS = r"SUPERSEDES|CORRECTS"
#: (name, pattern). Case-insensitive, because Cypher keywords are.
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "protected-field write",
        re.compile(rf"\b(SET|REMOVE)\b[^;]*?\b\w+\s*\.\s*({_FIELDS})\b", re.I | re.S),
    ),
    # Order-independent: the kind may be matched BEFORE the write clause
    # (``MATCH ()-[r {kind:'SUPERSEDES'}]->() DELETE r``).
    (
        "ordered-edge create",
        re.compile(rf"\A(?=.*\b(CREATE|MERGE)\b)(?=.*\b({_KINDS})\b).*", re.I | re.S),
    ),
    ("ordered-edge set", re.compile(rf"\A(?=.*\bSET\b)(?=.*\b({_KINDS})\b).*", re.I | re.S)),
    ("ordered-edge delete", re.compile(rf"\A(?=.*\bDELETE\b)(?=.*\b({_KINDS})\b).*", re.I | re.S)),
)


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    rule: str
    excerpt: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.rule}: {self.excerpt}"


def _docstring_ids(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                if isinstance(body[0].value.value, str):
                    ids.add(id(body[0].value))
    return ids


def _fold(node: ast.AST, names: dict[str, str] | None = None) -> str | None:
    """Text of a string expression: literals, f-string text, ``+`` chains, and
    module-level string constants referenced by name (so a statement split
    across named constants is still read as one)."""
    names = names or {}
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return names.get(node.id)
    if isinstance(node, ast.JoinedStr):
        return "".join(
            v.value if isinstance(v, ast.Constant) and isinstance(v.value, str) else "{}"
            for v in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _fold(node.left, names), _fold(node.right, names)
        if left is None and right is None:
            return None
        return (left or "{}") + (right or "{}")
    return None


def _module_strings(tree: ast.Module) -> dict[str, str]:
    """``NAME = <string expression>`` at module level, resolved in order."""
    names: dict[str, str] = {}
    for stmt in tree.body:
        targets = (
            stmt.targets
            if isinstance(stmt, ast.Assign)
            else [stmt.target]
            if isinstance(stmt, ast.AnnAssign)
            else []
        )
        value = getattr(stmt, "value", None)
        if value is None:
            continue
        text = _fold(value, names)
        for t in targets:
            if isinstance(t, ast.Name) and text is not None:
                names[t.id] = text
    return names


def _string_exprs(tree: ast.Module) -> list[tuple[int, str]]:
    names = _module_strings(tree)
    skip = _docstring_ids(tree)
    inner: set[int] = set()
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if id(node) in skip or id(node) in inner:
            continue
        if isinstance(node, (ast.Constant, ast.JoinedStr, ast.BinOp)):
            text = _fold(node, names)
            if text is None:
                continue
            # Mark folded children so a chain is scanned once, as a whole.
            for child in ast.walk(node):
                if child is not node:
                    inner.add(id(child))
            out.append((getattr(node, "lineno", 0), text))
    return out


def _imports_private(tree: ast.AST) -> list[int]:
    lines: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(
                a.name == PRIVATE_MODULE or a.name.startswith(PRIVATE_MODULE + ".")
                for a in node.names
            ):
                lines.append(node.lineno)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod == PRIVATE_MODULE or (
                mod.endswith("tamper_evidence")
                and any(a.name == "_assurance_write" for a in node.names)
            ):
                lines.append(node.lineno)
    return lines


def scan_file(path: Path, rel: str) -> list[Violation]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
    except SyntaxError as exc:  # fail closed: an unparsable file is not "clean"
        return [Violation(rel, exc.lineno or 0, "unparsable", "cannot verify this file")]
    found: list[Violation] = []
    if rel != ALLOWED_WRITER:
        for line, text in _string_exprs(tree):
            for rule, pat in PATTERNS:
                m = pat.search(text)
                if m:
                    found.append(Violation(rel, line, rule, " ".join(m.group(0).split())[:120]))
                    break
    if rel != ALLOWED_IMPORTER:
        for line in _imports_private(tree):
            found.append(Violation(rel, line, "private-module import", PRIVATE_MODULE))
    return found


def scan(roots: list[Path], base: Path = REPO) -> list[Violation]:
    found: list[Violation] = []
    for root in roots:
        root = root if root.is_absolute() else base / root
        if not root.exists():
            raise FileNotFoundError(f"scan root does not exist: {root}")
        files = [root] if root.is_file() else sorted(root.rglob("*.py"))
        for f in files:
            try:
                rel = f.resolve().relative_to(base.resolve()).as_posix()
            except ValueError:
                rel = f.as_posix()
            found.extend(scan_file(f, rel))
    return found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--root", action="append", dest="roots", help="directory or file to scan (repeatable)"
    )
    args = ap.parse_args(argv)
    roots = [Path(r) for r in (args.roots or ["graqle"])]
    try:
        violations = scan(roots)
    except FileNotFoundError as exc:
        print(f"assurance write-path gate: {exc}", file=sys.stderr)
        return 2
    for v in violations:
        print(v)
    print(
        f"assurance write-path gate: {len(violations)} violation(s) in {', '.join(map(str, roots))}"
    )
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
