#!/usr/bin/env python3
"""
verify_remediation.py — SQLi Remediation Verifier (Configurable)

Usage:
    python verify_remediation.py
    python verify_remediation.py --config config1.json
    python verify_remediation.py --config config1.json --save
    python verify_remediation.py --config config_httpbin.json        # demo/echo mode
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
    "baseline_response_hash": None,
    "demo_mode": False
}

TIMING_THRESHOLD = 4.0

# Payload substrings that trigger simulated delay in demo mode
TIMING_KEYWORDS = ["SLEEP", "WAITFOR", "DELAY", "BENCHMARK", "pg_sleep"]

# Constant hash used for ALL requests in demo mode
# (echo endpoints always differ — only timing matters there)
DEMO_STABLE_HASH = "demo_stable_hash_not_real"


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


def is_timing_payload(payload: str) -> bool:
    upper = payload.upper()
    return any(kw in upper for kw in TIMING_KEYWORDS)


def send_request(url, parameter, value, method="GET", extra_params=None, demo_mode=False):
    result = {
        "status":  None,
        "time":    None,
        "hash":    None,
        "snippet": None,
        "error":   None,
    }

    try:
        t0 = time.monotonic()

        params = extra_params.copy() if extra_params else {}
        params[parameter] = value

        if method.upper() == "POST":
            resp = requests.post(
                url,
                data=params,
                timeout=15,
                allow_redirects=False,
            )
        else:
            resp = requests.get(
                url,
                params=params,
                timeout=15,
                allow_redirects=False,
            )

        elapsed = time.monotonic() - t0

        result["status"]  = resp.status_code
        result["snippet"] = resp.text[:120].replace("\n", " ")

        if demo_mode:
            # In demo mode (echo endpoint like httpbin):
            # 1. Always return the same stable hash — echo endpoints
            #    reflect the payload so every response differs; we only
            #    care about timing here, not hash deviation.
            # 2. Simulate a realistic delay for time-based payloads.
            result["hash"] = DEMO_STABLE_HASH
            elapsed = 5.83 if is_timing_payload(value) else elapsed
        else:
            result["hash"] = sha256(resp.content)

        result["time"] = round(elapsed, 2)

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
        reasons.append(f"Timing anomaly detected ({result['time']}s > {TIMING_THRESHOLD}s threshold)")

    if result["snippet"] and "Welcome" in result["snippet"]:
        reasons.append("AUTH_BYPASS detected ('Welcome' in response)")

    return reasons


# ──────────────────────────────────────────────
# Core Engine
# ──────────────────────────────────────────────

def run_verification(config):
    url          = config["target"]
    method       = config.get("method", "POST")
    param        = config["parameter"]
    payloads     = config["payloads"]
    extra_params = config.get("extra_params", {})
    benign_value = config.get("benign_value", "safeuser")
    demo_mode    = config.get("demo_mode", False)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    print("\n===== REMEDIATION VERIFICATION REPORT =====")
    print(f"Finding  : {config['finding']}")
    print(f"Target   : {url}")
    print(f"Timestamp: {timestamp}")
    if demo_mode:
        print("[*] Demo mode ON — timing simulation enabled, hash checks skipped")

    # ── Baseline ────────────────────────────────
    print("\n[*] Sending baseline request...")
    baseline = send_request(url, param, benign_value, method, extra_params, demo_mode)

    if baseline["error"]:
        print("[FATAL] Baseline request failed:", baseline["error"])
        sys.exit(1)

    # In demo mode the stable hash is always DEMO_STABLE_HASH so baseline
    # and all payloads match — only timing anomalies fire.
    baseline_hash   = config.get("baseline_response_hash") or baseline["hash"]
    baseline_status = baseline["status"]

    print(f"[*] Baseline status={baseline_status} hash={str(baseline_hash)[:12]}...")

    results = []
    failed  = 0

    # ── Tests ────────────────────────────────────
    for i, payload in enumerate(payloads, 1):
        tc = f"TC-{i:02d}"

        res       = send_request(url, param, payload, method, extra_params, demo_mode)
        anomalies = detect_anomaly(res, baseline_status, baseline_hash)

        hash_match = "YES" if res["hash"] == baseline_hash else "NO"
        status     = res["status"] if res["status"] else "ERR"
        time_taken = f"{res['time']}s" if res["time"] is not None else "N/A"

        print(f"\n[{tc}] Payload: {payload}")
        print(f"Status : {status} | Time: {time_taken} | Hash Match: {hash_match}")

        if anomalies:
            failed += 1
            print(f"Result : FAIL  --  {', '.join(anomalies)}")
        else:
            print("Result : PASS")

        results.append({
            "test_id":    tc,
            "payload":    payload,
            "status":     status,
            "time":       res["time"],
            "hash_match": res["hash"] == baseline_hash,
            "anomalies":  anomalies,
            "passed":     len(anomalies) == 0,
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
        "verdict":         verdict,
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
