# AI Security Agents

A collection of AI-powered agents for cybersecurity tasks, built on local
LLMs (via Ollama) so everything runs free and offline.

## Agents

### 1. Incident Response Agent — `ir_agent_intel_mac.py`

Pulls alerts from Wazuh, triages them with a local LLM, and recommends/logs
a response action (escalate, block IP, isolate host, monitor, or mark as
false positive).

**Setup:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install requests ollama colorama

ollama serve &
ollama pull phi3   # or mistral / llama3 depending on available RAM
```

**Usage:**
```bash
python3 ir_agent_intel_mac.py --demo              # no Wazuh needed, uses sample alerts
python3 ir_agent_intel_mac.py --file auth.log     # analyse a log file
python3 ir_agent_intel_mac.py --limit 10          # live Wazuh alerts
```

Full setup instructions (Wazuh via Docker, model recommendations by RAM)
are documented in the comments at the top and bottom of the script.

---

### 2. Code Security Reviewer — `code_reviewer.py`

Scans Python files for common security vulnerabilities using a local LLM —
hardcoded secrets, SQL injection, command injection, insecure
deserialization, path traversal, weak cryptography, and more. Produces a
terminal report plus a saved Markdown report.

**Setup:** uses the same virtual environment and dependencies as the IR
agent above. Recommended model is `mistral` for better code reasoning
(`phi3` also works if RAM is limited).

```bash
ollama pull mistral
```

**Usage:**
```bash
python3 code_reviewer.py --file app.py                    # scan a single file
python3 code_reviewer.py --path ./my_project              # scan a folder recursively
python3 code_reviewer.py --path . --output report.md      # custom report filename
python3 code_reviewer.py --path . --model phi3            # use a different model
```

**Currently supports:** Python only. GitHub PR integration and
multi-language support are planned — see roadmap in the script's comments.

---

## Requirements

- macOS (tested on Intel Mac mini; should also work on Apple Silicon)
- Python 3.10+
- [Ollama](https://ollama.com) for local LLM inference
- Wazuh (optional, only needed for the IR agent's live-alert mode)

## Notes

These are personal learning/portfolio projects exploring AI-assisted
security operations. Not intended for production use without further
hardening, testing, and human review of agent decisions.
