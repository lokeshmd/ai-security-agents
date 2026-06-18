#!/usr/bin/env python3
"""
=================================================================
  AI Mac Security Agent
  Checkup + Monitor modes, powered by local Ollama
  Tested on: Intel Mac mini, should work on Apple Silicon too
=================================================================

WHAT THIS DOES:
  CHECKUP MODE  — runs macOS security posture checks (FileVault,
                   firewall, Gatekeeper, SIP, updates, login items)
                   and has a local LLM interpret + prioritise findings.

  MONITOR MODE  — point-in-time snapshot of running processes with
                   network connections, open ports, and recently
                   modified startup items — flags anything unusual.

  Both modes can suggest fixes. A small, deliberately narrow set of
  LOW-RISK items can be auto-fixed, but ONLY after you approve each
  one individually. Nothing destructive happens without your explicit
  yes.

SETUP (same stack as your other agents):
  python3 -m venv venv
  source venv/bin/activate
  pip install ollama colorama

  ollama serve &
  ollama pull mistral     # or phi3 if RAM-constrained

USAGE:
  python3 mac_security_agent.py --checkup
  python3 mac_security_agent.py --monitor
  python3 mac_security_agent.py --checkup --monitor    # run both
  python3 mac_security_agent.py --checkup --model phi3

NOTE ON PERMISSIONS:
  Some checks (FileVault status, SIP status) may prompt for your
  password — this is macOS asking, not this script. Nothing is sent
  anywhere; all analysis happens locally via Ollama.
=================================================================
"""

import argparse
import json
import subprocess
import sys
import datetime
import shlex
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

DEFAULT_MODEL = "mistral"
ACTION_LOG    = Path("mac_security_agent.log")

SYSTEM_PROMPT = """You are a Mac security analyst helping a non-expert user
understand their laptop's security posture. Be direct and practical.
Explain risk in plain English. Do not be alarmist about low-risk items.
Always return valid JSON when asked, with no extra commentary outside it."""


# ─────────────────────────────────────────────
#  SAFE COMMAND RUNNER
# ─────────────────────────────────────────────

def run_cmd(cmd: str, timeout: int = 15) -> str:
    """Run a shell command and return stdout, or an error string."""
    try:
        result = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip() if result.returncode == 0 else result.stderr.strip()
    except subprocess.TimeoutExpired:
        return "[timed out]"
    except FileNotFoundError:
        return "[command not found]"
    except Exception as e:
        return f"[error: {e}]"


# ─────────────────────────────────────────────
#  CHECKUP MODE — DATA COLLECTION
# ─────────────────────────────────────────────

def collect_checkup_data() -> dict:
    """Run all security posture checks and return raw results."""
    print(f"{Fore.WHITE}Running security checks (some may prompt for your password)...\n")

    data = {}

    print(f"  {Fore.CYAN}• FileVault status...")
    data["filevault"] = run_cmd("fdesetup status")

    print(f"  {Fore.CYAN}• Firewall status...")
    data["firewall"] = run_cmd(
        "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
    )

    print(f"  {Fore.CYAN}• Gatekeeper status...")
    data["gatekeeper"] = run_cmd("spctl --status")

    print(f"  {Fore.CYAN}• System Integrity Protection...")
    data["sip"] = run_cmd("csrutil status")

    print(f"  {Fore.CYAN}• macOS software update status...")
    data["software_update"] = run_cmd("softwareupdate -l")

    print(f"  {Fore.CYAN}• Screen lock settings...")
    data["screensaver_lock"] = run_cmd(
        "defaults read com.apple.screensaver askForPassword"
    )
    data["screensaver_delay"] = run_cmd(
        "defaults read com.apple.screensaver askForPasswordDelay"
    )

    print(f"  {Fore.CYAN}• Remote login (SSH) status...")
    data["remote_login"] = run_cmd("systemsetup -getremotelogin")

    print(f"  {Fore.CYAN}• Guest account status...")
    data["guest_account"] = run_cmd(
        "defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled"
    )

    print(f"  {Fore.CYAN}• Login items / launch agents...")
    user_agents = run_cmd(f"ls -la {Path.home()}/Library/LaunchAgents")
    system_agents = run_cmd("ls -la /Library/LaunchAgents")
    system_daemons = run_cmd("ls -la /Library/LaunchDaemons")
    data["launch_agents"] = (
        f"USER LaunchAgents:\n{user_agents}\n\n"
        f"SYSTEM LaunchAgents:\n{system_agents}\n\n"
        f"SYSTEM LaunchDaemons:\n{system_daemons}"
    )

    print(f"  {Fore.CYAN}• macOS version...")
    data["os_version"] = run_cmd("sw_vers")

    print()
    return data


# ─────────────────────────────────────────────
#  MONITOR MODE — DATA COLLECTION
# ─────────────────────────────────────────────

def collect_monitor_data() -> dict:
    """Snapshot of processes, network connections, and startup items."""
    print(f"{Fore.WHITE}Capturing system snapshot...\n")

    data = {}

    print(f"  {Fore.CYAN}• Processes with active network connections...")
    data["network_processes"] = run_cmd("lsof -i -n -P")

    print(f"  {Fore.CYAN}• Listening ports...")
    data["listening_ports"] = run_cmd("lsof -i -n -P -sTCP:LISTEN")

    print(f"  {Fore.CYAN}• Top processes by CPU...")
    data["top_processes"] = run_cmd("ps aux -r")

    print(f"  {Fore.CYAN}• Recently modified files in startup locations...")
    data["recent_launch_changes"] = run_cmd(
        f"find {Path.home()}/Library/LaunchAgents /Library/LaunchAgents "
        f"/Library/LaunchDaemons -type f -mtime -30"
    )

    print(f"  {Fore.CYAN}• Installed browser extensions (Safari)...")
    safari_ext = run_cmd(
        f"ls {Path.home()}/Library/Safari/Extensions"
    )
    data["safari_extensions"] = safari_ext

    print()
    return data


# ─────────────────────────────────────────────
#  AI ANALYSIS
# ─────────────────────────────────────────────

def analyze_checkup(data: dict, model: str) -> dict:
    """Send checkup data to LLM, get structured findings back."""

    prompt = f"""Analyse this macOS security checkup data. For each area, assess
whether it represents a security risk, and if so, how severe.

Data collected:
{json.dumps(data, indent=2)[:6000]}

Respond ONLY with valid JSON in this structure:
{{
  "findings": [
    {{
      "area": "<e.g. FileVault, Firewall, Login Items>",
      "severity": "Critical|High|Medium|Low|Info",
      "current_state": "<what you found>",
      "risk_explanation": "<why this matters, plain English, 1-2 sentences>",
      "recommended_fix": "<what should change>",
      "fix_command": "<exact terminal command to fix it, or null if it requires GUI/System Settings>",
      "safe_to_auto_fix": <true only if the fix is non-destructive, reversible, and low-risk — e.g. enabling firewall. false for anything involving encryption, deleting files, or system-level changes>
    }}
  ],
  "overall_summary": "<2-3 sentence plain-English summary of the laptop's security posture>"
}}"""

    return _call_llm(prompt, model)


def analyze_monitor(data: dict, model: str) -> dict:
    """Send monitor snapshot to LLM, get structured findings back."""

    prompt = f"""Analyse this macOS system snapshot for signs of suspicious activity —
unusual processes with network connections, unexpected listening ports,
recently added startup items, or unfamiliar browser extensions.

Be specific. Common legitimate macOS/Apple processes (e.g. WindowServer,
mDNSResponder, Spotlight, Finder, cloudd) should NOT be flagged as suspicious
just for having network activity — that's normal. Focus on genuinely unusual
findings: unsigned processes, unfamiliar binary names, unexpected ports,
or startup items in odd locations.

Data collected (truncated):
{json.dumps(data, indent=2)[:6000]}

Respond ONLY with valid JSON in this structure:
{{
  "findings": [
    {{
      "area": "<e.g. Network Connection, Listening Port, Startup Item>",
      "severity": "Critical|High|Medium|Low|Info",
      "current_state": "<what you found>",
      "risk_explanation": "<why this matters, plain English>",
      "recommended_fix": "<what to do about it>",
      "fix_command": "<exact terminal command, or null>",
      "safe_to_auto_fix": false
    }}
  ],
  "overall_summary": "<2-3 sentence summary of what's currently running>"
}}

If nothing looks unusual, return an empty findings list and say so in the summary."""

    return _call_llm(prompt, model)


def _call_llm(prompt: str, model: str) -> dict:
    try:
        response = ollama_client.chat(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            options={"temperature": 0.1, "num_predict": 1800}
        )
        raw = response["message"]["content"].strip()

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
        result.setdefault("overall_summary", "")
        return result

    except json.JSONDecodeError:
        return {
            "findings": [],
            "overall_summary": f"[Could not parse model output] {raw[:300]}"
        }
    except Exception as e:
        return {
            "findings": [],
            "overall_summary": f"[LLM error: {e}] Check Ollama is running: ollama serve"
        }


# ─────────────────────────────────────────────
#  DISPLAY
# ─────────────────────────────────────────────

SEV_COLOR = {
    "Critical": Fore.RED + Style.BRIGHT,
    "High":     Fore.RED,
    "Medium":   Fore.YELLOW,
    "Low":      Fore.GREEN,
    "Info":     Fore.CYAN,
}
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def print_results(result: dict, mode_name: str):
    findings = result.get("findings", [])
    summary  = result.get("overall_summary", "")

    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'═' * 62}")
    print(f"  {mode_name} RESULTS")
    print(f"{'═' * 62}{Style.RESET_ALL}\n")

    print(f"{Fore.WHITE}{summary}\n")

    if not findings:
        print(f"{Fore.GREEN}No issues to report.\n")
        return

    sorted_findings = sorted(findings, key=lambda f: SEV_ORDER.get(f.get("severity", "Info"), 4))

    for f in sorted_findings:
        sev = f.get("severity", "Info")
        color = SEV_COLOR.get(sev, Fore.WHITE)
        print(f"{color}[{sev}] {f.get('area', 'Unknown')}{Style.RESET_ALL}")
        print(f"  Current state: {f.get('current_state', '')}")
        print(f"  Risk: {f.get('risk_explanation', '')}")
        print(f"  Fix:  {Fore.GREEN}{f.get('recommended_fix', '')}")
        if f.get("fix_command"):
            print(f"  {Fore.WHITE}Command: {Fore.YELLOW}{f.get('fix_command')}")
        print()


# ─────────────────────────────────────────────
#  AUTO-REMEDIATION  (narrow, confirmed, logged)
# ─────────────────────────────────────────────

# Hard allowlist — only commands matching these patterns can ever be auto-run,
# regardless of what the LLM marks as "safe_to_auto_fix". This is the real
# safety boundary, not just trusting the model's judgement.
ALLOWED_FIX_PATTERNS = [
    "socketfilterfw --setglobalstate on",   # enable firewall
    "systemsetup -setremotelogin off",      # disable SSH remote login
]


def is_command_allowlisted(command: str) -> bool:
    if not command:
        return False
    return any(pattern in command for pattern in ALLOWED_FIX_PATTERNS)


def offer_remediation(findings: list):
    """Walk through auto-fixable findings one at a time, asking permission."""
    fixable = [
        f for f in findings
        if f.get("safe_to_auto_fix") and is_command_allowlisted(f.get("fix_command", ""))
    ]

    if not fixable:
        return

    print(f"{Fore.CYAN}{Style.BRIGHT}{'─' * 62}")
    print(f"  {len(fixable)} item(s) eligible for auto-fix")
    print(f"{'─' * 62}{Style.RESET_ALL}\n")

    for f in fixable:
        print(f"{Fore.YELLOW}Fix available: {f.get('area')}")
        print(f"  Issue:   {f.get('current_state')}")
        print(f"  Command: {f.get('fix_command')}")

        answer = input(f"\n  Apply this fix? [y/N]: ").strip().lower()

        if answer == "y":
            cmd = f.get("fix_command")
            print(f"  {Fore.WHITE}Running: {cmd}")
            # sudo-requiring commands will prompt interactively — that's expected
            result = subprocess.run(shlex.split(f"sudo {cmd}"))
            success = result.returncode == 0
            log_action(f.get("area"), cmd, success)
            print(f"  {Fore.GREEN if success else Fore.RED}"
                  f"{'Applied successfully.' if success else 'Command failed — check manually.'}\n")
        else:
            print(f"  {Fore.WHITE}Skipped.\n")
            log_action(f.get("area"), f.get("fix_command"), None, skipped=True)


def log_action(area: str, command: str, success, skipped: bool = False):
    ts = datetime.datetime.now().isoformat()
    status = "SKIPPED" if skipped else ("SUCCESS" if success else "FAILED")
    with open(ACTION_LOG, "a") as f:
        f.write(f"{ts} | {area} | {command} | {status}\n")


# ─────────────────────────────────────────────
#  ENTRYPOINT
# ─────────────────────────────────────────────

def print_banner(model: str, modes: list):
    print(f"""
{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════╗
║      AI Mac Security Agent                        ║
║      Mode(s): {', '.join(modes):<33}   ║
║      Model: {model:<20}              ║
╚══════════════════════════════════════════════════╝
{Style.RESET_ALL}""")


def main():
    parser = argparse.ArgumentParser(
        description="AI Mac Security Agent — checkup + monitor modes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 mac_security_agent.py --checkup
  python3 mac_security_agent.py --monitor
  python3 mac_security_agent.py --checkup --monitor
  python3 mac_security_agent.py --checkup --model phi3
  python3 mac_security_agent.py --checkup --auto-fix
        """
    )
    parser.add_argument("--checkup", action="store_true", help="Run security posture checkup")
    parser.add_argument("--monitor", action="store_true", help="Run system activity snapshot")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL, help=f"Ollama model (default: {DEFAULT_MODEL})")
    parser.add_argument("--auto-fix", action="store_true",
                        help="After checkup, offer to apply safe fixes (asks before each one)")
    args = parser.parse_args()

    if not args.checkup and not args.monitor:
        parser.print_help()
        sys.exit(1)

    modes = []
    if args.checkup: modes.append("checkup")
    if args.monitor: modes.append("monitor")

    print_banner(args.model, modes)

    all_findings = []

    if args.checkup:
        data = collect_checkup_data()
        print(f"{Fore.WHITE}Analysing with {args.model}...\n")
        result = analyze_checkup(data, args.model)
        print_results(result, "CHECKUP")
        all_findings.extend(result.get("findings", []))

    if args.monitor:
        data = collect_monitor_data()
        print(f"{Fore.WHITE}Analysing with {args.model}...\n")
        result = analyze_monitor(data, args.model)
        print_results(result, "MONITOR")
        all_findings.extend(result.get("findings", []))

    if args.auto_fix and all_findings:
        offer_remediation(all_findings)

    print(f"{Fore.GREEN}Done. Actions logged to: {ACTION_LOG}\n")


if __name__ == "__main__":
    main()


# =================================================================
#  WHY AUTO-FIX IS DELIBERATELY LIMITED
# =================================================================
#
# The LLM's "safe_to_auto_fix" judgement is NOT trusted on its own —
# notice ALLOWED_FIX_PATTERNS is a hard-coded allowlist that the
# actual command must match, regardless of what the model says.
# This means even if the LLM hallucinates that something risky is
# "safe", the script physically cannot run it through --auto-fix.
#
# Currently allowlisted:
#   - Enabling the firewall (reversible, no data risk)
#   - Disabling SSH remote login (reversible, no data risk)
#
# Deliberately EXCLUDED from auto-fix, always report-only:
#   - FileVault (encryption) — can be disruptive, requires restart,
#     recovery key handling — must be done manually via System Settings
#   - Removing LaunchAgents/LaunchDaemons — could break legitimate
#     software if misidentified; always review the file path yourself
#   - SIP / Gatekeeper changes — security-critical, should not be
#     toggled by a script
#
# =================================================================
#  ROADMAP
# =================================================================
#
# 1. Scheduled mode via launchd (run checkup weekly, log results)
# 2. Diff mode — only show what changed since last checkup
# 3. Integration with the code_reviewer.py agent for dev-machine
#    specific checks (exposed .env files, world-readable SSH keys)
# 4. Slack/email notification on Critical/High findings
# =================================================================
