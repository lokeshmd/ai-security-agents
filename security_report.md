# Code Security Review Report

**Scan date:** 2026-06-17 10:55  
**Scanned path:** `test_vulnerable.py`  
**Model used:** mistral  
**Files scanned:** 1  
**Total findings:** 1

## Summary by Severity

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |

## Detailed Findings

### `test_vulnerable.py`

**[Unknown] Parse Error**
- Location: N/A
- Issue: Model returned non-JSON output: {
  "findings": [
    {
      "severity": "Critical",
      "vulnerability_type": "Hardcoded secrets",
      "line_reference": "10",
      "explanation": "The API key is hardcoded in the script, which
- Suggested fix: Re-run review manually or try a different model
