import ast
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SHELL_FUNCTION_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\(\)\s*\{")


def test_every_python_script_function_has_a_purpose_docstring():
    """Keep operational entry points understandable without tracing their bodies."""
    missing: list[str] = []
    for source in sorted((ROOT / "scripts").glob("*.py")):
        tree = ast.parse(source.read_text(encoding="utf-8-sig"), filename=str(source))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not ast.get_docstring(node):
                missing.append(f"{source.relative_to(ROOT)}:{node.lineno}:{node.name}")
    assert missing == []


def test_every_shell_function_has_an_immediate_purpose_comment():
    """Require a concise comment immediately above each operational shell function."""
    missing: list[str] = []
    sources = [ROOT / "RUN_AFTER_UPLOAD.sh", *(ROOT / "scripts").glob("*.sh"), *(ROOT / "ops").glob("*.sh")]
    for source in sources:
        lines = source.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if not SHELL_FUNCTION_RE.match(line):
                continue
            previous = lines[index - 1].strip() if index else ""
            if not previous.startswith("#"):
                missing.append(f"{source.relative_to(ROOT)}:{index + 1}:{line.split('(', 1)[0]}")
    assert missing == []
