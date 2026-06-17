# AI Security Agents

A collection of AI-powered agents for cybersecurity tasks — starting with an
incident response (IR) triage agent built on lokeshmd + Ollama.

## Agents

### `ir_agent_intel_mac.py`
Local AI agent that pulls alerts from Wazuh, triages them with a local LLM
(via Ollama), and recommends/logs a response action. Built and tested on
Intel Mac.

**Setup:** see comments at the top of the script for full installation steps.

**Quick start:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install requests ollama colorama
python3 ir_agent_intel_mac.py --demo
```
