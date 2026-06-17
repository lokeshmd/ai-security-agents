#!/usr/bin/env python3
"""
=================================================================
  AI Code Security Reviewer  —  Python Edition
  Local-folder scanning, powered by Ollama (runs fully offline)
=================================================================

WHAT THIS DOES:
  Scans Python files in a folder for common security vulnerabilities
  using a local LLM, and produces a structured report (terminal +
  Markdown file) with severity, explanation, and suggested fixes.

SETUP (same stack as the IR agent):
  python3 -m venv venv
  source venv/bin/activate
  pip install requests ollama colorama

  ollama serve &
  ollama pull mistral      # recommended — better code reasoning than phi3
                            # (phi3 also works if RAM is tight)

USAGE:
  python3 code_reviewer.py --path ./my_project
  python3 code_reviewer.py --path ./my_project --model mistral
  python3 code_reviewer.py --file ./app.py
  python3 code_reviewer.py --path . --output report.md

=================================================================
"""

import argparse
import json
import os
import sys
import fnmatch
import datetime
from pathlib import Path

# ── Dependency check ────────────────────────────────────────
def check_dependencies():
    missing = []
    try:
        import ollama
    except ImportError:
        missing.append("ollama")
    try:
        import colorama
    except ImportError:
        missing.append("colorama")
    if missing:
        print(f"\n[ERROR] Missing packages: {', '.join(missing)}")
        print(f"Fix:  pip3 install {' '.join(missing)}\n")
        sys.exit(1)

check_dependencies()

import ollama as ollama_client
from colorama import Fore, Style, init
init(autoreset=True)


# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────

DEFAULT_MODEL   = "mistral"   # better at code reasoning than phi3; use phi3 if RAM-constrained
MAX_FILE_CHARS  = 6000        # chunk large files to keep responses fast/accurate
EXCLUDE_DIRS    = {".git", "venv", "env", "__pycache__", "node_modules", ".venv", "ir_agent_env"}
EXCLUDE_PATTERNS = ["*.pyc", "*.min.js", "*_test.py", "test_*.py"]  # adjust as needed


# ─────────────────────────────────────────────
#  VULNERABILITY CATEGORIES  (guides the LLM's focus)
# ─────────────────────────────────────────────

SECURITY_FOCUS_AREAS = """
- Hardcoded secrets: API keys, passwords, tokens, connection strings
- SQL injection: string concatenation or f-strings building SQL queries
- Command injection: os.system(), subprocess with shell=True, unsanitized input to shell commands
- Insecure deserialization: pickle.loads(), yaml.load() without SafeLoader, eval()/exec() on untrusted input
- Path traversal: file paths built from user input without sanitization
- Insecure randomness: using random module (not secrets module) for tokens, passwords, or crypto
- Server-Side Request Forgery (SSRF): fetching URLs built from unvalidated user input
- Weak cryptography: MD5/SHA1 for security purposes, hardcoded encryption keys/IVs, ECB mode
- Debug/insecure config: DEBUG=True in production code, overly permissive CORS, disabled SSL verification
- Missing input validation: especially on deserialization, file uploads, or template rendering
- Insecure use of XML parsers: vulnerable to XXE (XML External Entity) attacks
- Authentication/authorization flaws: missing auth checks, weak session handling
"""

SYSTEM_PROMPT = f"""You are a senior application security engineer performing a code review.
You focus ONLY on security vulnerabilities — not style, performance, or general code quality.

Focus areas:
{SECURITY_FOCUS_AREAS}

For each finding, you must be specific about the line of code and why it's a risk.
Do not flag theoretical issues with no real exploitation path.
If the code has no security issues, say so clearly — do not invent findings."""


# ─────────────────────────────────────────────
#  FILE DISCOVERY
# ─────────────────────────────────────────────

def find_python_files(root_path: str) -> list[Path]:
    """Walk a directory and return all .py files, respecting exclusions."""
    root = Path(root_path)

    if root.is_file():
        return [root] if root.suffix == ".py" else []

    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune excluded directories in-place so os.walk skips them
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]

        for filename in filenames:
            if not filename.endswith(".py"):
                continue
            if any(fnmatch.fnmatch(filename, pat) for pat in EXCLUDE_PATTERNS):
                continue
            files.append(Path(dirpath) / filename)

    return sorted(files)


def chunk_file_content(content: str, max_chars: int = MAX_FILE_CHARS) -> list[str]:
    """Split large files into chunks on line boundaries to preserve context."""
    if len(content) <= max_chars:
        return [content]

    lines = content.split("\n")
    chunks, current = [], []
    current_len = 0

    for line in lines:
        if current_len + len(line) > max_chars and current:
            chunks.append("\n".join(current))
            current, current_len = [], 0
        current.append(line)
        current_len += len(line) + 1

    if current:
        chunks.append("\n".join(current))

    return chunks


# ─────────────────────────────────────────────
#  AI ANALYSIS
# ─────────────────────────────────────────────

def review_code_chunk(filename: str, code: str, model: str, chunk_info: str = "") -> dict:
    """
    Send one file/chunk to the LLM for security review.
    Returns dict: {"findings": [...], "clean": bool}
    """
    prompt = f"""Review this Python file for security vulnerabilities.

Filename: {filename}{chunk_info}

Code:
```python
{code}
```

Respond ONLY with valid JSON in this exact structure, no other text:
{{
  "findings": [
    {{
      "severity": "Critical|High|Medium|Low",
      "vulnerability_type": "<short name, e.g. SQL Injection>",
      "line_reference": "<line number or function name where issue occurs>",
      "explanation": "<why this is a security risk, 1-2 sentences>",
      "suggested_fix": "<concrete fix, 1-2 sentences>"
    }}
  ],
  "clean": <true if no issues found, false otherwise>
}}

If there are no security issues, return {{"findings": [], "clean": true}}."""

    try:
        response = ollama_client.chat(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            options={"temperature": 0.1, "num_predict": 1200}
        )
        raw = response["message"]["content"].strip()

        # Strip markdown fences if present
        if "```" in raw:
            parts = raw.split("```")
            for part in parts:
                part = part.strip()
                if part.startswith("json"):
                    part = part[4:].strip()
                if part.startswith("{"):
                    raw = part
                    break

        result = json.loads(raw)
        result.setdefault("findings", [])
        result.setdefault("clean", len(result["findings"]) == 0)
        return result

    except json.JSONDecodeError:
        return {
            "findings": [{
                "severity": "Unknown",
                "vulnerability_type": "Parse Error",
                "line_reference": "N/A",
                "explanation": f"Model returned non-JSON output: {raw[:200]}",
                "suggested_fix": "Re-run review manually or try a different model"
            }],
            "clean": False
        }
    except Exception as e:
        return {
            "findings": [{
                "severity": "Error",
                "vulnerability_type": "Tool Error",
                "line_reference": "N/A",
                "explanation": f"LLM call failed: {e}",
                "suggested_fix": "Check Ollama is running: ollama serve"
            }],
            "clean": False
        }


def review_file(filepath: Path, model: str) -> list[dict]:
    """Review a single file, chunking if needed. Returns list of findings with filename attached."""
    try:
        content = filepath.read_text(errors="replace")
    except Exception as e:
        return [{
            "severity": "Error",
            "vulnerability_type": "Read Error",
            "line_reference": "N/A",
            "explanation": f"Could not read file: {e}",
            "suggested_fix": "Check file permissions",
            "file": str(filepath)
        }]

    if not content.strip():
        return []

    chunks = chunk_file_content(content)
    all_findings = []

    for i, chunk in enumerate(chunks, 1):
        chunk_info = f" (part {i}/{len(chunks)})" if len(chunks) > 1 else ""
        result = review_code_chunk(str(filepath), chunk, model, chunk_info)

        for finding in result.get("findings", []):
            finding["file"] = str(filepath)
            all_findings.append(finding)

    return all_findings


# ─────────────────────────────────────────────
#  DISPLAY & REPORTING
# ─────────────────────────────────────────────

SEV_COLOR = {
    "Critical": Fore.RED + Style.BRIGHT,
    "High":     Fore.RED,
    "Medium":   Fore.YELLOW,
    "Low":      Fore.GREEN,
    "Unknown":  Fore.WHITE,
    "Error":    Fore.WHITE,
}

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4, "Error": 5}


def print_banner(model: str, file_count: int):
    print(f"""
{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════╗
║      AI Code Security Reviewer                   ║
║      Python Edition  —  Local Ollama              ║
║      Model: {model:<20}  Files: {file_count:<5}    ║
╚══════════════════════════════════════════════════╝
{Style.RESET_ALL}""")


def print_findings(filepath: str, findings: list[dict]):
    print(f"{Fore.CYAN}{Style.BRIGHT}{'─' * 62}")
    print(f"  {filepath}")
    print(f"{'─' * 62}{Style.RESET_ALL}")

    if not findings:
        print(f"  {Fore.GREEN}✓ No security issues found\n")
        return

    sorted_findings = sorted(findings, key=lambda f: SEV_ORDER.get(f.get("severity", "Unknown"), 4))

    for f in sorted_findings:
        sev = f.get("severity", "Unknown")
        color = SEV_COLOR.get(sev, Fore.WHITE)
        print(f"\n  {color}[{sev}] {f.get('vulnerability_type', 'Unknown')}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Location: {f.get('line_reference', 'N/A')}")
        print(f"  Issue:    {f.get('explanation', '')}")
        print(f"  Fix:      {Fore.GREEN}{f.get('suggested_fix', '')}")
    print()


def generate_markdown_report(all_results: dict, model: str, scan_path: str) -> str:
    """Build a Markdown report string from all findings."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    total_findings = sum(len(findings) for findings in all_results.values())
    by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for findings in all_results.values():
        for f in findings:
            sev = f.get("severity", "Unknown")
            if sev in by_severity:
                by_severity[sev] += 1

    lines = [
        "# Code Security Review Report",
        "",
        f"**Scan date:** {timestamp}  ",
        f"**Scanned path:** `{scan_path}`  ",
        f"**Model used:** {model}  ",
        f"**Files scanned:** {len(all_results)}  ",
        f"**Total findings:** {total_findings}",
        "",
        "## Summary by Severity",
        "",
        "| Severity | Count |",
        "|---|---|",
        f"| Critical | {by_severity['Critical']} |",
        f"| High | {by_severity['High']} |",
        f"| Medium | {by_severity['Medium']} |",
        f"| Low | {by_severity['Low']} |",
        "",
        "## Detailed Findings",
        "",
    ]

    for filepath, findings in all_results.items():
        lines.append(f"### `{filepath}`")
        lines.append("")

        if not findings:
            lines.append("No security issues found.")
            lines.append("")
            continue

        sorted_findings = sorted(findings, key=lambda f: SEV_ORDER.get(f.get("severity", "Unknown"), 4))
        for f in sorted_findings:
            lines.append(f"**[{f.get('severity', 'Unknown')}] {f.get('vulnerability_type', 'Unknown')}**")
            lines.append(f"- Location: {f.get('line_reference', 'N/A')}")
            lines.append(f"- Issue: {f.get('explanation', '')}")
            lines.append(f"- Suggested fix: {f.get('suggested_fix', '')}")
            lines.append("")

    return "\n".join(lines)


# ─────────────────────────────────────────────
#  ENTRYPOINT
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AI Code Security Reviewer — Python Edition (local Ollama)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 code_reviewer.py --path ./my_project
  python3 code_reviewer.py --file ./app.py
  python3 code_reviewer.py --path . --output security_report.md
  python3 code_reviewer.py --path . --model phi3
        """
    )
    parser.add_argument("--path", type=str, help="Folder to scan recursively for .py files")
    parser.add_argument("--file", type=str, help="Scan a single Python file")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL,
                        help=f"Ollama model to use (default: {DEFAULT_MODEL})")
    parser.add_argument("--output", type=str, default="security_report.md",
                        help="Markdown report output path (default: security_report.md)")
    args = parser.parse_args()

    if not args.path and not args.file:
        parser.print_help()
        sys.exit(1)

    target = args.file if args.file else args.path
    files = find_python_files(target)

    if not files:
        print(f"{Fore.YELLOW}No Python files found in: {target}")
        sys.exit(0)

    print_banner(args.model, len(files))
    print(f"{Fore.WHITE}Files to review:")
    for f in files:
        print(f"  • {f}")
    print()

    all_results = {}
    for i, filepath in enumerate(files, 1):
        print(f"{Fore.YELLOW}[{i}/{len(files)}] Reviewing {filepath}...", end="\r", flush=True)
        findings = review_file(filepath, args.model)
        all_results[str(filepath)] = findings
        print(" " * 80, end="\r")  # clear the progress line
        print_findings(str(filepath), findings)

    # Summary
    total = sum(len(f) for f in all_results.values())
    critical_high = sum(
        1 for findings in all_results.values()
        for f in findings if f.get("severity") in ("Critical", "High")
    )

    print(f"{Fore.CYAN}{Style.BRIGHT}{'═' * 62}")
    print(f"  SCAN COMPLETE")
    print(f"  Files scanned: {len(files)}  |  Total findings: {total}  |  Critical/High: {critical_high}")
    print(f"{'═' * 62}{Style.RESET_ALL}\n")

    # Write Markdown report
    report_md = generate_markdown_report(all_results, args.model, target)
    Path(args.output).write_text(report_md)
    print(f"{Fore.GREEN}Report saved to: {args.output}\n")


if __name__ == "__main__":
    main()

