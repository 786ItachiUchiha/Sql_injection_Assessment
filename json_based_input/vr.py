#!/usr/bin/env python3
"""
verify_remediation.py — SQLi Remediation Verifier (Configurable)

Usage:
    python verify_remediation.py
    python verify_remediation.py --config config1.json
    python verify_remediation.py --config config1.json --save
"""

import requests
import hashlib
import json
import time
from datetime import datetime, timezone
import argparse
from pathlib import Path
import sys


# ──────────────────────────────────────────────
# Defaults
# ──────────────────────────────────────────────
DEFAULT_CONFIG = {
    "target": "http://127.0.0.1:5000/login",
    "method": "GET",
    "finding": "sql_injection",
    "parameter": "username",
    "benign_value": "safeuser",
    "extra_params": {
        "password": "wrongpass"
    },
    "payloads": [
        "' OR '1'='1",
        "' AND 1=1--",
        "'; WAITFOR DELAY '0:0:5'--"
    ],
    "baseline_response_hash": None
}

TIMING_THRESHOLD = 4.0


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_config(path):
    try:
        with open(path, "r") as f:
            config = json.load(f)
        print(f"[*] Loaded config from {path}")
        return config
    except Exception as e:
        print(f"[ERROR] Failed to load config: {e}")
        sys.exit(1)


def send_request(url, parameter, value, method="GET", extra_params=None):
    result = {
        "status": None,
        "time": None,
        "hash": None,
        "snippet": None,
        "error": None
    }

    try:
        t0 = time.monotonic()

        params = extra_params.copy() if extra_params else {}
        params[parameter] = value

        if method.upper() == "POST":
            resp = requests.post(
                url,
                data=params,
                timeout=10,
                allow_redirects=False
            )
        else:
            resp = requests.get(
                url,
                params=params,
                timeout=10,
                allow_redirects=False
            )

        elapsed = time.monotonic() - t0

        result["status"]  = resp.status_code
        result["time"]    = round(elapsed, 2)
        result["hash"]    = sha256(resp.content)
        result["snippet"] = resp.text[:120].replace("\n", " ")

    except requests.exceptions.Timeout:
        result["time"]  = TIMING_THRESHOLD
        result["error"] = "TIMEOUT"
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"CONNECTION_ERROR: {e}"
    except Exception as e:
        result["error"] = f"UNKNOWN_ERROR: {e}"

    return result


def detect_anomaly(result, baseline_status, baseline_hash):
    reasons = []

    if result["error"]:
        reasons.append(result["error"])
        return reasons

    if result["status"] != baseline_status:
        reasons.append(f"Status code changed ({baseline_status} -> {result['status']})")

    if result["hash"] != baseline_hash:
        reasons.append("Response hash deviation")

    if result["time"] and result["time"] > TIMING_THRESHOLD:
        reasons.append(f"Timing anomaly ({result['time']}s > {TIMING_THRESHOLD}s threshold)")

    if result["snippet"] and "Welcome" in result["snippet"]:
        reasons.append("AUTH_BYPASS detected ('Welcome' in response)")

    return reasons


# ──────────────────────────────────────────────
# Core Engine
# ──────────────────────────────────────────────

def run_verification(config):
    url          = config["target"]
    method       = config.get("method", "GET")
    param        = config["parameter"]
    payloads     = config["payloads"]
    extra_params = config.get("extra_params", {})
    benign_value = config.get("benign_value", "safeuser")

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    print("\n===== REMEDIATION VERIFICATION REPORT =====")
    print(f"Finding  : {config['finding']}")
    print(f"Target   : {url}")
    print(f"Method   : {method}")
    print(f"Timestamp: {timestamp}")

    # ── Baseline ───────────────────────────────
    print("\n[*] Sending baseline request...")
    baseline = send_request(url, param, benign_value, method, extra_params)

    if baseline["error"]:
        print("[FATAL] Baseline request failed:", baseline["error"])
        sys.exit(1)

    # Allow override from config
    baseline_hash   = config.get("baseline_response_hash") or baseline["hash"]
    baseline_status = baseline["status"]

    print(f"[*] Baseline status={baseline_status} hash={baseline_hash[:12]}...")

    results = []
    failed  = 0

    # ── Tests ──────────────────────────────────
    for i, payload in enumerate(payloads, 1):
        tc = f"TC-{i:02d}"

        res       = send_request(url, param, payload, method, extra_params)
        anomalies = detect_anomaly(res, baseline_status, baseline_hash)

        hash_match = "YES" if res["hash"] == baseline_hash else "NO"
        status     = res["status"] if res["status"] else "ERR"
        time_taken = f"{res['time']}s" if res["time"] is not None else "N/A"

        print(f"\n[{tc}] Payload : {payload}")
        print(f"      Status : {status} | Time: {time_taken} | Hash Match: {hash_match}")

        if res["snippet"]:
            print(f"      Snippet: {res['snippet'][:80]}")

        if anomalies:
            failed += 1
            print(f"      Result : FAIL  --  {', '.join(anomalies)}")
        else:
            print("      Result : PASS")

        results.append({
            "test_id":   tc,
            "payload":   payload,
            "status":    status,
            "time":      res["time"],
            "hash_match": res["hash"] == baseline_hash,
            "anomalies": anomalies,
            "passed":    len(anomalies) == 0
        })

    verdict = "REMEDIATION FAILED" if failed > 0 else "REMEDIATION PASSED"

    print(f"\n===== VERDICT: {verdict} =====")
    print(f"Failed Tests: {failed} / {len(payloads)}\n")

    return {
        "finding":         config["finding"],
        "target":          url,
        "method":          method,
        "timestamp":       timestamp,
        "baseline_status": baseline_status,
        "baseline_hash":   baseline_hash,
        "results":         results,
        "failed":          failed,
        "total":           len(payloads),
        "verdict":         verdict
    }


# ──────────────────────────────────────────────
# Save Evidence
# ──────────────────────────────────────────────

def save_evidence(report):
    ts       = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"evidence_{ts}.json"

    data      = json.dumps(report, indent=2).encode()
    file_hash = sha256(data)

    report["sha256"] = file_hash
    Path(filename).write_text(json.dumps(report, indent=2))

    print(f"[+] Evidence saved : {filename}")
    print(f"[+] SHA-256        : {file_hash}")


# ──────────────────────────────────────────────
# Entry
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", help="Path to JSON config file")
    parser.add_argument("--save",   "-s", action="store_true", help="Save JSON evidence")
    args = parser.parse_args()

    if args.config:
        config = load_config(args.config)
    else:
        print("[*] Using default config")
        config = DEFAULT_CONFIG

    report = run_verification(config)

    if args.save:
        save_evidence(report)


if __name__ == "__main__":
    main()
