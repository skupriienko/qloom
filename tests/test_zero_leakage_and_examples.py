"""Zero-leakage, zero-external-import, heritage isolation, and example verification tests."""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import qloom

_REPO_ROOT = Path(__file__).resolve().parents[1]

_FORBIDDEN_INTERNAL_TOKENS: tuple[str, ...] = (
    "".join(["tok", "qor"]),
    "".join(["syn", "tex"]),
    "".join(["mem", "palace"]),
    "".join(["vue", ".gov"]),
    "".join(["gate", "0"]),
    "".join(["dou-", "62577"]),
    "".join(["ccm_", "layer"]),
    "".join(["alek", "sakha"]),
    "".join(["progres", "sology"]),
    "".join(["ur", "ton"]),
)

_PRIVATE_PATH_OR_SECRET_RE = re.compile(
    r"(?:/home/[a-z0-9._-]+/|/users/[a-z0-9._-]+/|[a-z]:\\users\\[a-z0-9._-]+\\"
    r"|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16})",
    re.IGNORECASE,
)

_FORBIDDEN_LEGACY_TERMS: tuple[str, ...] = (
    "".join(["kay", "te"]),
    "".join(["can", "uto"]),
    "".join(["ino", "katha"]),
    "".join(["ya", "pa"]),
    "".join(["qhin", "cha"]),
    "".join(["waran", "qa"]),
    "".join(["pach", "aka"]),
    "".join(["yup", "ana"]),
    "".join(["enla", "zado"]),
    "".join(["han", "an"]),
    "".join(["hur", "in"]),
    "".join(["nak", "ku"]),
    "".join(["ayl", "lu"]),
    "".join(["pok", "cha"]),
    "".join(["qull", "qa"]),
    "".join(["chak", "ana"]),
    "".join(["moi", "ety"]),
)

_LEGACY_TERM_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(term) for term in _FORBIDDEN_LEGACY_TERMS) + r")\b",
    re.IGNORECASE,
)


def _iter_repo_files() -> list[Path]:
    files: list[Path] = []
    for dir_name in ("src", "docs", "tests", "examples", ".github"):
        sub = _REPO_ROOT / dir_name
        if sub.is_dir():
            for path in sorted(sub.rglob("*")):
                if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                    files.append(path)
    for top_name in (
        "README.md",
        "SKILL.md",
        "pyproject.toml",
        "CHANGELOG.md",
        "LICENSE",
        "MANIFEST.in",
        "install.sh",
        "setup.py",
        ".gitignore",
        ".pre-commit-config.yaml",
    ):
        top_path = _REPO_ROOT / top_name
        if top_path.is_file():
            files.append(top_path)
    return files


def test_examples_parse_verify_draw_and_plan_waves() -> None:
    examples_dir = _REPO_ROOT / "examples"
    example_files = sorted(examples_dir.rglob("*.qloom"))
    assert len(example_files) == 4
    for path in example_files:
        raw = path.read_text(encoding="utf-8")
        doc = qloom.parse_qloom(raw)
        assert doc.doc_id
        report = qloom.verify_qloom(raw)
        assert report["valid"] is True, f"{path.name} failed verification: {report['findings']}"
        ascii_diagram = qloom.draw(raw)
        assert doc.doc_id in ascii_diagram
        waves = qloom.plan_weave_waves(doc)
        assert isinstance(waves, list)


def test_zero_internal_token_leakage() -> None:
    repo_files = _iter_repo_files()
    assert repo_files, "Expected standalone repository files to scan"
    home_token = Path.home().as_posix().lower()
    violations: list[str] = []
    for path in repo_files:
        raw_text = path.read_text(encoding="utf-8", errors="replace")
        text = raw_text.lower()
        rel = path.relative_to(_REPO_ROOT)
        for token in _FORBIDDEN_INTERNAL_TOKENS:
            if token in text:
                violations.append(f"{rel} contains {token!r}")
        if home_token in text:
            violations.append(f"{rel} contains runtime home path")
        if _PRIVATE_PATH_OR_SECRET_RE.search(raw_text):
            violations.append(f"{rel} matches private path or secret pattern")
    assert not violations, "Internal leakage detected:\n" + "\n".join(violations)


def test_zero_external_or_sibling_imports_in_src() -> None:
    src_dir = _REPO_ROOT / "src" / "qloom"
    py_files = sorted(p for p in src_dir.rglob("*.py") if "__pycache__" not in p.parts)
    assert py_files, "Expected Python sources under src/qloom/"
    stdlib_names: frozenset[str] = getattr(sys, "stdlib_module_names", frozenset())
    violations: list[str] = []
    for path in py_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".", 1)[0]
                    if top != "qloom" and top not in stdlib_names:
                        violations.append(f"{path.name} imports non-stdlib module {alias.name!r}")
            elif isinstance(node, ast.ImportFrom):
                if node.level > 0:
                    continue
                top = (node.module or "").split(".", 1)[0]
                if top != "qloom" and top not in stdlib_names:
                    violations.append(f"{path.name} imports non-stdlib module {node.module!r}")
    assert not violations, "External/sibling imports detected:\n" + "\n".join(violations)


def test_zero_legacy_terminology_in_python_sources() -> None:
    py_files: list[Path] = []
    for sub_dir in (_REPO_ROOT / "src" / "qloom", _REPO_ROOT / "tests"):
        if sub_dir.is_dir():
            py_files.extend(
                p for p in sorted(sub_dir.rglob("*.py")) if "__pycache__" not in p.parts
            )
    assert py_files, "Expected Python files under src/qloom/ and tests/"
    violations: list[str] = []
    for path in py_files:
        content = path.read_text(encoding="utf-8")
        matches = sorted({m.group(0).lower() for m in _LEGACY_TERM_RE.finditer(content)})
        if matches:
            violations.append(f"{path.relative_to(_REPO_ROOT)}: {matches}")
    assert not violations, "Legacy terminology detected:\n" + "\n".join(violations)
