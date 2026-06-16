#!/usr/bin/env python3
"""
=================================================================
  AI Incident Response Agent  —  Intel Mac Edition
  Tested on: Mac mini (Intel, 2018–2020), MacBook Pro (Intel)
=================================================================

FIRST-TIME SETUP (copy/paste each block into Terminal):

── Step 1: Install Homebrew ────────────────────────────────────
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

── Step 2: Install Python 3 ────────────────────────────────────
  brew install python3
  python3 --version          # should show 3.10 or higher

── Step 3: Install Ollama ──────────────────────────────────────
  # Direct download (more reliable than brew on Intel Mac):
  curl -fsSL https://ollama.com/install.sh | sh

  # Start Ollama as a background service:
  ollama serve > /tmp/ollama.log 2>&1 &

  # Pull a model suited to Intel hardware.
  # Pick ONE based on your RAM:
  #   8 GB  RAM  →  ollama pull phi3
  #   16 GB RAM  →  ollama pull mistral
  #   32 GB RAM  →  ollama pull llama3
  ollama pull phi3            # recommended default for Intel Mac mini

── Step 4: Install Python packages ─────────────────────────────
  pip3 install requests ollama colorama

── Step 5: Test without Wazuh ──────────────────────────────────
  python3 ir_agent_intel_mac.py --demo

── Step 6: Install Docker Desktop (for Wazuh) ──────────────────
  brew install --cask docker
  # Open Docker Desktop, go to Settings → Resources
  # Set Memory to at least 6 GB, CPUs to 4
  # Then start Wazuh (see WAZUH SETUP section at bottom of file)

=================================================================
USAGE:
  python3 ir_agent_intel_mac.py --demo              # no setup needed
  python3 ir_agent_intel_mac.py --file auth.log     # analyse a log file
  python3 ir_agent_intel_mac.py --limit 10          # live Wazuh alerts
  python3 ir_agent_intel_mac.py --demo --model phi3 # force a specific model
=================================================================
"""

import argparse
import json
import os
import sys
import datetime
import platform
import subprocess
import urllib3
from pathlib import Path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Dependency check with friendly error messages ─────────────
def check_dependencies():
    missing = []
    try:
        import requests
    except ImportError:
        missing.append("requests")
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

import requests
import ollama as ollama_client
from colorama import Fore, Style, init
init(autoreset=True)


# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────

# Intel Mac default: phi3 is fast enough and uses ~4GB RAM.
# Change to "mistral" if you have 16GB, "llama3" if you have 32GB.
DEFAULT_MODEL = "phi3"

WAZUH_URL   = os.getenv("WAZUH_URL",  "https://localhost:55000")
WAZUH_USER  = os.getenv("WAZUH_USER", "wazuh")
WAZUH_PASS  = os.getenv("WAZUH_PASS", "wazuh")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
ACTION_LOG  = Path("agent_actions.log")


# ─────────────────────────────────────────────
#  DEMO ALERTS  (no Wazuh needed)
# ─────────────────────────────────────────────

DEMO_ALERTS = [
    {
        "id": "demo-001",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "rule": {
            "id": "5763",
            "description": "SSH brute-force attack detected",
            "level": 10,
            "groups": ["authentication_failures", "sshd"]
        },
        "agent": {"name": "web-server-01", "ip": "10.0.0.5"},
        "data": {
            "srcip": "185.220.101.42",
            "dstuser": "root",
            "attempts": "47",
            "program_name": "sshd"
        },
        "location": "/var/log/auth.log"
    },
    {
        "id": "demo-002",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "rule": {
            "id": "87103",
            "description": "Possible web shell uploaded to server",
            "level": 12,
            "groups": ["web", "attack", "intrusion_attempt"]
        },
        "agent": {"name": "web-server-01", "ip": "10.0.0.5"},
        "data": {
            "srcip": "203.0.113.99",
            "url": "/uploads/shell.php",
            "method": "POST",
            "response_code": "200"
        },
        "location": "/var/log/nginx/access.log"
    },
    {
        "id": "demo-003",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "rule": {
            "id": "40111",
            "description": "Suspicious new user account created outside business hours",
            "level": 8,
            "groups": ["account_changes", "pam"]
        },
        "agent": {"name": "db-server-02", "ip": "10.0.0.10"},
        "data": {
            "dstuser": "svc_backup99",
            "program_name": "useradd",
            "uid": "0"
        },
        "location": "/var/log/auth.log"
    },
    {
        "id": "demo-004",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "rule": {
            "id": "31530",
            "description": "Malware detected by antivirus",
            "level": 14,
            "groups": ["malware", "virus"]
        },
        "agent": {"name": "workstation-05", "ip": "10.0.1.25"},
        "data": {
            "file": "C:\\Users\\jsmith\\Downloads\\invoice.exe",
            "virus": "Trojan.GenericKD.46666",
            "action": "found"
        },
        "location": "WinEvtLog"
    }
]


# ─────────────────────────────────────────────
#  INTEL MAC: OLLAMA HEALTH CHECK
# ─────────────────────────────────────────────

def check_ollama_running(model: str) -> bool:
    """Check Ollama is up and the requested model is available."""
    try:
        r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
        if r.status_code != 200:
            return False
        available = [m["name"].split(":")[0] for m in r.json().get("models", [])]
        if model not in available:
            print(f"\n{Fore.YELLOW}[WARNING] Model '{model}' not found locally.")
            print(f"Pulling it now — this may take a few minutes on Intel...")
            subprocess.run(["ollama", "pull", model], check=True)
        return True
    except requests.exceptions.ConnectionError:
        return False


def ensure_ollama(model: str):
    """Start Ollama if it's not running (Intel Mac friendly)."""
    if check_ollama_running(model):
        return

    print(f"{Fore.YELLOW}Ollama not running. Attempting to start it...")
    try:
        subprocess.Popen(
            ["ollama", "serve"],
            stdout=open("/tmp/ollama.log", "w"),
            stderr=subprocess.STDOUT
        )
        import time
        time.sleep(4)  # Give Intel CPU a moment to start the server
        if check_ollama_running(model):
            print(f"{Fore.GREEN}Ollama started successfully.")
        else:
            print(f"{Fore.RED}Could not start Ollama.")
            print("Try manually:  ollama serve &")
            sys.exit(1)
    except FileNotFoundError:
        print(f"{Fore.RED}Ollama not installed.")
        print("Install it:  curl -fsSL https://ollama.com/install.sh | sh")
        sys.exit(1)


# ─────────────────────────────────────────────
#  WAZUH API
# ─────────────────────────────────────────────

def get_wazuh_token() -> str:
    try:
        r = requests.post(
            f"{WAZUH_URL}/security/user/authenticate",
            auth=(WAZUH_USER, WAZUH_PASS),
            verify=False,
            timeout=10
        )
        r.raise_for_status()
        return r.json()["data"]["token"]
    except requests.exceptions.ConnectionError:
        print(f"\n{Fore.RED}Cannot connect to Wazuh at {WAZUH_URL}")
        print("Is Docker running? Try:  docker compose up -d")
        print("Or test without Wazuh:   python3 ir_agent_intel_mac.py --demo\n")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Wazuh auth error: {e}")
        sys.exit(1)


def get_recent_alerts(token: str, limit: int = 10) -> list:
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(
            f"{WAZUH_URL}/alerts",
            headers=headers,
            params={"limit": limit, "sort": "-timestamp"},
            verify=False,
            timeout=10
        )
        r.raise_for_status()
        return r.json()["data"]["affected_items"]
    except Exception as e:
        print(f"{Fore.RED}Failed to fetch alerts: {e}")
        return []


# ─────────────────────────────────────────────
#  AI ANALYSIS  (Intel-tuned prompts)
# ─────────────────────────────────────────────

# Shorter, more direct prompt = faster inference on Intel CPU
SYSTEM_PROMPT = (
    "You are a cybersecurity incident response analyst. "
    "Analyse alerts concisely. Return only valid JSON when asked. "
    "No markdown, no preamble, no explanation outside the JSON."
)


def analyze_alert(alert: dict, model: str) -> dict:
    """Triage one alert. Returns structured dict."""

    # Keep the prompt tight for Intel — smaller context = faster response
    alert_summary = {
        "rule":      alert.get("rule", {}),
        "agent":     alert.get("agent", {}),
        "data":      alert.get("data", {}),
        "timestamp": alert.get("timestamp", ""),
        "location":  alert.get("location", "")
    }

    prompt = f"""Analyse this security alert. Reply ONLY with this JSON, no other text:

{{
  "severity": "Critical|High|Medium|Low",
  "summary": "<one sentence: what happened>",
  "likely_attack": "<attack name>",
  "immediate_actions": ["<action 1>", "<action 2>", "<action 3>"],
  "evidence_to_collect": ["<item 1>", "<item 2>"],
  "decision": "ESCALATE|BLOCK_IP|ISOLATE_HOST|MONITOR|FALSE_POSITIVE",
  "decision_target": "<IP or hostname, or null>"
}}

Alert:
{json.dumps(alert_summary, indent=2)}"""

    try:
        response = ollama_client.chat(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt}
            ],
            options={
                "temperature": 0.1,   # low temp = consistent, factual output
                "num_predict": 400,   # cap tokens for Intel speed
            }
        )
        raw = response["message"]["content"].strip()

        # Strip markdown fences if model adds them
        if "```" in raw:
            parts = raw.split("```")
            for part in parts:
                part = part.strip()
                if part.startswith("json"):
                    part = part[4:].strip()
                if part.startswith("{"):
                    raw = part
                    break

        return json.loads(raw)

    except json.JSONDecodeError:
        # Model returned non-JSON — wrap it gracefully
        return {
            "severity": "Unknown",
            "summary": raw[:250] if raw else "Parse error",
            "likely_attack": "Unknown",
            "immediate_actions": ["Manual review required"],
            "evidence_to_collect": [],
            "decision": "ESCALATE",
            "decision_target": None
        }
    except Exception as e:
        return {
            "severity": "Error",
            "summary": str(e),
            "likely_attack": "N/A",
            "immediate_actions": [f"LLM error — check ollama is running: {e}"],
            "evidence_to_collect": [],
            "decision": "ESCALATE",
            "decision_target": None
        }


def analyze_log_file(filepath: str, model: str) -> None:
    """Analyse a local log file — useful for CyberDefenders lab downloads."""
    path = Path(filepath)
    if not path.exists():
        print(f"{Fore.RED}File not found: {filepath}")
        sys.exit(1)

    print(f"\n{Fore.CYAN}{Style.BRIGHT}Analysing: {path.name}  ({path.stat().st_size // 1024} KB)")
    print("─" * 60)

    with open(path, "r", errors="replace") as f:
        content = f.read()

    # Intel: smaller chunks to avoid long wait times
    chunk_size  = 2500
    max_content = 12000   # limit total to keep it snappy on Intel
    chunks = [
        content[i:i+chunk_size]
        for i in range(0, min(len(content), max_content), chunk_size)
    ]

    print(f"Processing {len(chunks)} chunk(s) — this may take "
          f"~{len(chunks) * 20}s on Intel...\n")

    for i, chunk in enumerate(chunks, 1):
        print(f"{Fore.YELLOW}[Chunk {i}/{len(chunks)}]")

        prompt = (
            "Analyse these log entries for security threats. "
            "List: attack type, attacker IPs, affected accounts, "
            "MITRE ATT&CK technique if applicable, and top 2 recommended actions.\n\n"
            f"Logs:\n{chunk}"
        )

        try:
            resp = ollama_client.chat(
                model=model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": prompt}
                ],
                options={"temperature": 0.1, "num_predict": 500}
            )
            print(resp["message"]["content"])
            print()
        except Exception as e:
            print(f"{Fore.RED}Error on chunk {i}: {e}\n")


# ─────────────────────────────────────────────
#  ACTION SIMULATION
# ─────────────────────────────────────────────

def simulate_action(decision: str, target: str | None, alert_id: str) -> None:
    """Log the decision. In production, call Wazuh active-response or cloud APIs here."""
    ts = datetime.datetime.utcnow().isoformat()
    with open(ACTION_LOG, "a") as f:
        f.write(f"{ts} | alert={alert_id} | decision={decision} | target={target}\n")

    messages = {
        "ESCALATE":       "📧  Would page on-call analyst and open incident ticket",
        "BLOCK_IP":       f"🚫  Would block {target} via Wazuh active-response firewall rule",
        "ISOLATE_HOST":   f"🔌  Would isolate {target} — cut all traffic except management",
        "MONITOR":        "👁️   Would raise log verbosity and set 24h watchlist",
        "FALSE_POSITIVE": "✅  Would add suppression rule for this alert pattern",
    }
    msg = messages.get(decision, "❓  Unknown decision")
    print(f"\n  {Fore.MAGENTA}{msg}")
    print(f"  {Fore.WHITE}Logged → {ACTION_LOG}")


# ─────────────────────────────────────────────
#  DISPLAY HELPERS
# ─────────────────────────────────────────────

SEV_COLOR = {
    "Critical": Fore.RED + Style.BRIGHT,
    "High":     Fore.RED,
    "Medium":   Fore.YELLOW,
    "Low":      Fore.GREEN,
}

def sev_color(s: str) -> str:
    return SEV_COLOR.get(s, Fore.WHITE)


def print_banner(model: str):
    mac_info = platform.mac_ver()[0]
    cpu_info = "Intel x86_64"
    print(f"""
{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════╗
║      AI Incident Response Agent                  ║
║      Intel Mac Edition                           ║
║      macOS {mac_info:<8}  CPU: {cpu_info:<14}  ║
║      LLM: {model:<20}              ║
╚══════════════════════════════════════════════════╝
{Style.RESET_ALL}""")


def process_alerts(alerts: list, model: str) -> None:
    if not alerts:
        print(f"{Fore.YELLOW}No alerts to process.")
        return

    print(f"\n{Fore.CYAN}Processing {len(alerts)} alert(s) with {model}...")
    print(f"{Fore.WHITE}(Intel tip: each alert takes ~15–30s depending on RAM)\n")

    for i, alert in enumerate(alerts, 1):
        alert_id   = alert.get("id", f"alert-{i}")
        rule_desc  = alert.get("rule", {}).get("description", "Unknown")
        level      = alert.get("rule", {}).get("level", "?")
        agent_name = alert.get("agent", {}).get("name", "unknown")
        timestamp  = alert.get("timestamp", "")[:19]

        print(f"{Fore.CYAN}{Style.BRIGHT}{'─' * 62}")
        print(f"  Alert {i}/{len(alerts)}: {rule_desc}")
        print(f"  Wazuh Level: {level}  |  Agent: {agent_name}  |  {timestamp}")
        print(f"{'─' * 62}{Style.RESET_ALL}")

        print(f"  {Fore.WHITE}Analysing...", end="", flush=True)
        result = analyze_alert(alert, model)
        print(f"\r{' ' * 20}\r", end="")

        sev = result.get("severity", "Unknown")
        print(f"\n  {sev_color(sev)}SEVERITY :  {sev}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}ATTACK   :  {result.get('likely_attack', 'N/A')}")
        print(f"\n  SUMMARY  :  {result.get('summary', '')}")

        actions = result.get("immediate_actions", [])
        if actions:
            print(f"\n  {Fore.YELLOW}IMMEDIATE ACTIONS:")
            for a in actions:
                print(f"    • {a}")

        evidence = result.get("evidence_to_collect", [])
        if evidence:
            print(f"\n  {Fore.YELLOW}COLLECT AS EVIDENCE:")
            for e in evidence:
                print(f"    • {e}")

        decision = result.get("decision", "ESCALATE")
        target   = result.get("decision_target")
        print(f"\n  {Fore.CYAN}DECISION :  {Style.BRIGHT}{decision}"
              + (f" → {target}" if target else "") + Style.RESET_ALL)

        simulate_action(decision, target, alert_id)
        print()

    print(f"\n{Fore.GREEN}Done. All decisions logged to: {ACTION_LOG}")


# ─────────────────────────────────────────────
#  ENTRYPOINT
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AI IR Agent — Intel Mac Edition (Wazuh + Ollama)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ir_agent_intel_mac.py --demo
  python3 ir_agent_intel_mac.py --file ~/Downloads/auth.log
  python3 ir_agent_intel_mac.py --limit 5
  python3 ir_agent_intel_mac.py --demo --model mistral
        """
    )
    parser.add_argument("--demo",  action="store_true",
                        help="Use built-in demo alerts — no Wazuh needed")
    parser.add_argument("--file",  type=str, metavar="PATH",
                        help="Analyse a local log file (CyberDefenders lab download)")
    parser.add_argument("--limit", type=int, default=5,
                        help="Number of live Wazuh alerts to fetch (default: 5)")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL,
                        help=f"Ollama model to use (default: {DEFAULT_MODEL}). "
                             "Intel 8GB→phi3, 16GB→mistral, 32GB→llama3")
    args = parser.parse_args()

    print_banner(args.model)

    # Verify Ollama is up before doing anything else
    ensure_ollama(args.model)

    if args.file:
        analyze_log_file(args.file, args.model)

    elif args.demo:
        print(f"{Fore.YELLOW}DEMO MODE — using {len(DEMO_ALERTS)} synthetic alerts.\n")
        process_alerts(DEMO_ALERTS, args.model)

    else:
        print(f"{Fore.WHITE}Connecting to Wazuh at {WAZUH_URL}...")
        token  = get_wazuh_token()
        alerts = get_recent_alerts(token, limit=args.limit)
        process_alerts(alerts, args.model)


if __name__ == "__main__":
    main()


# =================================================================
#  WAZUH SETUP ON INTEL MAC  (via Docker Desktop)
# =================================================================
#
# 1. Install Docker Desktop:
#      brew install --cask docker
#    Open Docker Desktop → Settings → Resources:
#      Memory: 6 GB minimum (8 GB recommended for Intel)
#      CPUs:   4
#      Swap:   2 GB
#
# 2. Save this as docker-compose.yml in a new folder:
#
# ---
# version: '3.9'
# services:
#   wazuh.manager:
#     image: wazuh/wazuh-manager:4.7.0
#     hostname: wazuh.manager
#     ports:
#       - "1514:1514/udp"
#       - "1515:1515"
#       - "514:514/udp"
#       - "55000:55000"
#     environment:
#       - INDEXER_URL=https://wazuh.indexer:9200
#       - INDEXER_USERNAME=admin
#       - INDEXER_PASSWORD=SecretPassword
#       - FILEBEAT_SSL_VERIFICATION_MODE=full
#     volumes:
#       - wazuh_api_configuration:/var/ossec/api/configuration
#       - wazuh_etc:/var/ossec/etc
#       - wazuh_logs:/var/ossec/logs
#       - wazuh_queue:/var/ossec/queue
# volumes:
#   wazuh_api_configuration:
#   wazuh_etc:
#   wazuh_logs:
#   wazuh_queue:
# ---
#
# 3. Start it:
#      docker compose up -d
#    (First start takes ~3 minutes on Intel — be patient)
#
# 4. Get the auto-generated password:
#      docker exec -it <wazuh-manager-container> /var/ossec/bin/wazuh-control status
#
# 5. Set env vars so the script connects:
#      export WAZUH_URL=https://localhost:55000
#      export WAZUH_USER=wazuh
#      export WAZUH_PASS=<your-password>
#
# 6. Run the agent:
#      python3 ir_agent_intel_mac.py --limit 5
#
# FULL DOCKER SETUP (recommended — includes dashboard):
#   https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html
#
# =================================================================
#  MODEL GUIDE FOR INTEL MAC
# =================================================================
#
#  Model      RAM needed   Speed on Intel    Quality
#  ─────────  ──────────   ───────────────   ───────
#  phi3       4 GB         Fast (~10s)       Good for triage
#  mistral    8 GB         Medium (~20s)     Better reasoning
#  llama3     16 GB        Slow (~45s)       Best quality
#  tinyllama  2 GB         Very fast (~5s)   Basic only
#
#  Switch model any time:
#    ollama pull mistral
#    python3 ir_agent_intel_mac.py --demo --model mistral
#
# =================================================================
#  CYBERDEFENDERS FREE LABS TO TEST WITH
# =================================================================
#
#  1. Go to cyberdefenders.org → sign up free
#  2. Open any lab and download the artifacts (log files, PCAPs)
#  3. Run:  python3 ir_agent_intel_mac.py --file ~/Downloads/<lab-file>.log
#
#  Recommended free labs to start:
#    • WebStrike    — web server attack logs
#    • Tomcat Takeover — Apache Tomcat intrusion
#    • PsExec Hunt  — lateral movement investigation
# =================================================================
