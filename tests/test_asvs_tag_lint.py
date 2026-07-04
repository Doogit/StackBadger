"""Offline tag-lint for ASVS-scope probes (Tier-2 CI gate).

Every heavy ASVS probe carries ``@pytest.mark.asvs_extended`` so it is
deselected outside ``SCAN_SCOPE=asvs``. Two invariants must hold for each such
probe, and this module enforces them as a normal pytest assertion failure:

1. **Coverage tagging.** It must also carry BOTH ``@pytest.mark.asvs(<id>)``
   AND ``@pytest.mark.cwe(<id>)`` — the ids the coverage ledger joins on. A
   probe tagged ``asvs_extended`` but missing either one would run under asvs
   scope yet contribute nothing to the ASVS/CWE crosswalk.
2. **Write-probe gating.** If it issues a mutating HTTP method
   (POST/PUT/PATCH/DELETE) it must carry ``@pytest.mark.write_probe`` so it
   stays gated behind ``--full``/``--branch`` and never fires read-only.

Why a static AST scan (and NOT pytest collection)
-------------------------------------------------
A collection-based check would be corrupted by the very markers it audits:
``-m "not write_probe"`` deselects the write probes, and core scope
skip-marks every ``asvs_extended`` node — so the tests to audit would be
absent from the collected set. A ``.py`` source scan is deterministic,
offline, profile-independent, and sees every probe regardless of any ``-m``
filter or ``SCAN_SCOPE``.

Marker resolution
-----------------
Markers are collected from three places, mirroring how pytest applies them:
function decorators, an enclosing ``class`` (its decorators and its body-level
``pytestmark``), and module-level ``pytestmark`` (single value or list, plain or
annotated assignment). Both the ``pytest.mark.<name>`` / ``pt.mark.<name>`` and
the ``mark.<name>`` (``from pytest import mark``) forms are recognised. A marker
hidden behind a local alias variable (``pytestmark = requires_bash``; ``W =
pytest.mark.write_probe`` then ``@W``) is NOT resolved and is treated as absent —
apply these markers directly so the lint can see them.

Mutation detection rule (heuristic — documented limitations)
-----------------------------------------------------------
Within an ``asvs_extended`` test's own body (including inline nested helpers) a
call is treated as mutating when EITHER:
  * it is an attribute call ``.post(`` / ``.put(`` / ``.patch(`` / ``.delete(``
    (e.g. ``client.post(...)``), OR
  * it is a request helper — ``send_request(...)`` or ``*.request(...)`` — whose
    FIRST positional argument is a string literal ``"POST"``/``"PUT"``/
    ``"PATCH"``/``"DELETE"`` (case-insensitive).

Known, deliberate limitations (a heuristic, not a proof):
  * False negatives. A method built dynamically (``method =
    endpoint.get("method")`` then ``send_request(method, ...)``) is NOT flagged
    — the literal is not visible statically, and this is the dominant mutation
    shape in the suite. A mutation hidden inside a module-level helper the test
    merely calls is likewise not followed (only the test's own AST subtree is
    walked). For these, the ``write_probe`` gate rests on author diligence, not
    on this lint.
  * False positives. The attribute-call rule keys on the method name alone, so a
    non-HTTP call in a probe body (``mock.patch(...)``, ``cache.delete(...)``,
    ORM ``session.delete(...)``) can be flagged, over-demanding ``write_probe``.
    If a genuinely read-only probe is flagged this way, narrow the call or
    restructure it — do NOT paper over it by adding ``write_probe`` (that would
    deselect the probe from read-only runs and silently drop ASVS coverage).
    Markers are only seen when applied as literal ``@pytest.mark.<name>`` /
    ``@mark.<name>`` decorators or plain/annotated ``pytestmark`` values; a
    marker behind a local alias variable is not resolved.
"""

from __future__ import annotations

import ast
from pathlib import Path

_TESTS_DIR = Path(__file__).resolve().parent

_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# Helpers whose FIRST positional arg is the HTTP method string.
_METHOD_FIRST_HELPERS = {"send_request"}
_MUTATING_ATTR_CALLS = {"post", "put", "patch", "delete"}


def _mark_name(node: ast.expr) -> str | None:
    """Return the marker name for a ``pytest.mark.<name>`` expr, else ``None``.

    Accepts both the bare attribute (``pytest.mark.foo``) and the called form
    (``pytest.mark.foo(...)``). Any other expression (a bare ``Name`` alias, a
    ``skipif`` on something that is not ``.mark.``) returns ``None``.
    """
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute):
        base = node.value
        # ``pytest.mark.<name>`` / ``pt.mark.<name>`` (base is a ``*.mark`` attr),
        # or ``mark.<name>`` from ``from pytest import mark`` (base is ``mark``).
        # pytest treats ``pytest.mark`` and an imported ``mark`` as the same
        # MarkGenerator, so both must count or an ``@mark.asvs_extended`` probe
        # would silently escape the lint.
        if isinstance(base, ast.Attribute) and base.attr == "mark":
            return node.attr
        if isinstance(base, ast.Name) and base.id == "mark":
            return node.attr
    return None


def _decorator_marks(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> set[str]:
    return {name for d in node.decorator_list if (name := _mark_name(d)) is not None}


def _pytestmark_marks(body: list[ast.stmt]) -> set[str]:
    """Collect marker names from any ``pytestmark = ...`` assignment in *body*.

    Handles both plain (``pytestmark = ...``) and annotated
    (``pytestmark: list = ...``) assignment forms.
    """
    marks: set[str] = set()
    for stmt in body:
        value: ast.expr | None = None
        if isinstance(stmt, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "pytestmark" for t in stmt.targets
        ):
            value = stmt.value
        elif (
            isinstance(stmt, ast.AnnAssign)
            and isinstance(stmt.target, ast.Name)
            and stmt.target.id == "pytestmark"
        ):
            value = stmt.value
        if value is None:
            continue
        elts = value.elts if isinstance(value, (ast.List, ast.Tuple)) else [value]
        for elt in elts:
            name = _mark_name(elt)
            if name is not None:
                marks.add(name)
    return marks


def _is_mutating_call(call: ast.Call) -> bool:
    """True when *call* issues a mutating HTTP method per the documented rule."""
    func = call.func
    # (b) attribute call: client.post(...), anon_client.delete(...), ...
    if isinstance(func, ast.Attribute) and func.attr in _MUTATING_ATTR_CALLS:
        return True
    # (a) request helper with a literal mutating method as first positional arg.
    is_helper = (isinstance(func, ast.Name) and func.id in _METHOD_FIRST_HELPERS) or (
        isinstance(func, ast.Attribute) and func.attr == "request"
    )
    if is_helper and call.args:
        first = call.args[0]
        if (
            isinstance(first, ast.Constant)
            and isinstance(first.value, str)
            and first.value.upper() in _MUTATING_METHODS
        ):
            return True
    return False


def _function_mutates(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Walk the test's own body (incl. inline nested defs) for a mutating call."""
    for stmt in func.body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call) and _is_mutating_call(node):
                return True
    return False


def _iter_test_functions(tree: ast.Module):
    """Yield ``(qualname, func_node, marks)`` for every ``test_*`` function.

    Marks are the union of the function's own decorators, any enclosing class's
    decorators and body-level ``pytestmark``, and module-level ``pytestmark`` —
    matching how pytest applies markers.
    """
    results: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef, set[str]]] = []

    def visit(body: list[ast.stmt], inherited: frozenset[str], qualprefix: str) -> None:
        current = inherited | _pytestmark_marks(body)
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name.startswith("test_"):
                marks = current | _decorator_marks(stmt)
                results.append((qualprefix + stmt.name, stmt, marks))
            elif isinstance(stmt, ast.ClassDef):
                cls_marks = current | _decorator_marks(stmt)
                visit(stmt.body, cls_marks, qualprefix + stmt.name + "::")

    visit(tree.body, frozenset(), "")
    return results


def find_violations_in_source(source: str, filename: str) -> list[str]:
    """Return actionable ``file::function — reason`` messages for *source*."""
    violations: list[str] = []
    tree = ast.parse(source, filename=filename)
    for qualname, func, marks in _iter_test_functions(tree):
        if "asvs_extended" not in marks:
            continue
        where = f"{filename}::{qualname}"
        missing = [m for m in ("asvs", "cwe") if m not in marks]
        if missing:
            violations.append(
                f"{where} — carries @pytest.mark.asvs_extended but is missing "
                f"@pytest.mark.{'/@pytest.mark.'.join(missing)} "
                "(both asvs(<id>) and cwe(<id>) are required for the coverage ledger)."
            )
        if "write_probe" not in marks and _function_mutates(func):
            violations.append(
                f"{where} — issues a mutating HTTP method (POST/PUT/PATCH/DELETE) "
                "but is missing @pytest.mark.write_probe (asvs_extended mutation "
                "probes must stay gated behind --full/--branch)."
            )
    return violations


def _probe_source_files() -> list[Path]:
    return sorted(_TESTS_DIR.glob("*.py"))


def test_asvs_extended_probes_are_fully_tagged() -> None:
    """Every asvs_extended probe carries asvs+cwe, and write_probe when it mutates."""
    all_violations: list[str] = []
    for path in _probe_source_files():
        all_violations.extend(
            find_violations_in_source(path.read_text(encoding="utf-8"), path.name)
        )
    assert not all_violations, (
        "ASVS tag-lint found improperly tagged asvs_extended probe(s):\n  - "
        + "\n  - ".join(all_violations)
    )


def test_tag_lint_detects_synthetic_violations() -> None:
    """Self-test the detector against crafted good/bad sources.

    Guards against the lint silently degrading into an always-pass no-op.
    """
    clean = (
        "import pytest\n"
        "@pytest.mark.asvs_extended\n"
        "@pytest.mark.asvs('1.2.3')\n"
        "@pytest.mark.cwe('89')\n"
        "def test_ok(profile):\n"
        "    resp = send_request('GET', url)\n"
    )
    assert find_violations_in_source(clean, "clean.py") == []

    # Missing both asvs() and cwe().
    missing_ids = (
        "import pytest\n"
        "@pytest.mark.asvs_extended\n"
        "def test_untagged(profile):\n"
        "    resp = send_request('GET', url)\n"
    )
    v = find_violations_in_source(missing_ids, "bad.py")
    assert len(v) == 1 and "missing" in v[0]

    # `from pytest import mark` decorator form must still be recognised, else a
    # mutating probe would silently escape the write_probe gate.
    from_import_form = (
        "from pytest import mark\n"
        "@mark.asvs_extended\n"
        "@mark.asvs('1.2.3')\n"
        "@mark.cwe('89')\n"
        "def test_imported_mark(profile, client):\n"
        "    resp = client.post(url)\n"
    )
    v = find_violations_in_source(from_import_form, "bad.py")
    assert len(v) == 1 and "write_probe" in v[0]

    # Only one of asvs()/cwe() present ⇒ still a coverage violation.
    partial_tag = (
        "import pytest\n"
        "@pytest.mark.asvs_extended\n"
        "@pytest.mark.asvs('1.2.3')\n"
        "def test_partial(profile):\n"
        "    resp = send_request('GET', url)\n"
    )
    v = find_violations_in_source(partial_tag, "bad.py")
    assert len(v) == 1 and "cwe" in v[0]

    # Module-level pytestmark (list form) supplies asvs_extended to every test.
    module_scoped = (
        "import pytest\n"
        "pytestmark = [pytest.mark.asvs_extended]\n"
        "def test_module_probe(profile):\n"
        "    resp = send_request('GET', url)\n"
    )
    v = find_violations_in_source(module_scoped, "bad.py")
    assert len(v) == 1 and "missing" in v[0]

    # Mutating literal via send_request, no write_probe.
    mutating_helper = (
        "import pytest\n"
        "@pytest.mark.asvs_extended\n"
        "@pytest.mark.asvs('1.2.3')\n"
        "@pytest.mark.cwe('89')\n"
        "def test_mutates(profile):\n"
        "    resp = send_request('POST', url, json_body=b)\n"
    )
    v = find_violations_in_source(mutating_helper, "bad.py")
    assert len(v) == 1 and "write_probe" in v[0]

    # Mutating .delete() attribute call, no write_probe.
    mutating_attr = (
        "import pytest\n"
        "@pytest.mark.asvs_extended\n"
        "@pytest.mark.asvs('1.2.3')\n"
        "@pytest.mark.cwe('89')\n"
        "def test_deletes(profile, client):\n"
        "    resp = client.delete(url)\n"
    )
    v = find_violations_in_source(mutating_attr, "bad.py")
    assert len(v) == 1 and "write_probe" in v[0]

    # write_probe present ⇒ mutation is allowed, no violation.
    gated = (
        "import pytest\n"
        "@pytest.mark.write_probe\n"
        "@pytest.mark.asvs_extended\n"
        "@pytest.mark.asvs('1.2.3')\n"
        "@pytest.mark.cwe('89')\n"
        "def test_gated(profile):\n"
        "    resp = send_request('POST', url, json_body=b)\n"
    )
    assert find_violations_in_source(gated, "ok.py") == []

    # Class-method probe with class-level pytestmark supplying asvs_extended,
    # and a mutating call ⇒ still flagged for the missing write_probe.
    class_scoped = (
        "import pytest\n"
        "class TestGroup:\n"
        "    pytestmark = pytest.mark.asvs_extended\n"
        "    @pytest.mark.asvs('1.2.3')\n"
        "    @pytest.mark.cwe('89')\n"
        "    def test_method(self, profile):\n"
        "        resp = send_request('PUT', url, json_body=b)\n"
    )
    v = find_violations_in_source(class_scoped, "bad.py")
    assert len(v) == 1 and "TestGroup::test_method" in v[0]

    # A non-asvs_extended test that mutates is irrelevant to this lint.
    unrelated = (
        "import pytest\n"
        "@pytest.mark.write_probe\n"
        "def test_plain(profile):\n"
        "    resp = send_request('POST', url, json_body=b)\n"
    )
    assert find_violations_in_source(unrelated, "ok.py") == []
