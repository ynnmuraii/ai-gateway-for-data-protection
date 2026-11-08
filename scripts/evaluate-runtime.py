"""Measure local detection + masking latency without DB or an LLM/network call.

This measures warm sequential CPU work, not end-to-end production capacity. Pool
queue exhaustion, worker replacement and cancellation have dedicated pytest tests.
"""

import argparse
import json
import platform
import statistics
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from gateway.detection import CATEGORIES, Detector, profile_checksum, protect

SCOPE = {
    "integration_id": "11111111-1111-1111-1111-111111111111",
    "issuer": "runtime-fixture",
    "sub": "synthetic-user",
    "user_id": "22222222-2222-2222-2222-222222222222",
    "chat_id": "benchmark",
}


def percentile(values, fraction):
    values = sorted(values)
    location = (len(values) - 1) * fraction
    lower = int(location)
    upper = min(len(values) - 1, lower + 1)
    return values[lower] + (values[upper] - values[lower]) * (location - lower)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=30)
    parser.add_argument("--sizes", nargs="+", type=int, default=[1024, 4096, 16384])
    parser.add_argument(
        "--output", type=Path, default=ROOT / ".runtime" / "qa-sprint2" / "runtime-evaluation.json"
    )
    args = parser.parse_args()
    if not 5 <= args.iterations <= 1000 or any(not 512 <= size <= 262144 for size in args.sizes):
        parser.error("Use 5–1000 iterations and input sizes 512–262144 characters.")
    started = time.perf_counter()
    detector = Detector()
    load_ms = (time.perf_counter() - started) * 1000
    seed = "Contact fixture@example.com via 10.20.30.40 or node.internal. "
    filler = "request=ok; elapsed_ms=12; status=ready; "
    results = []
    for size in args.sizes:
        text = (seed + filler * (size // len(filler) + 1))[:size]
        messages = [{"role": "user", "content": text}]
        durations = []
        for iteration in range(args.iterations + 3):
            start = time.perf_counter()
            findings = detector.analyze(messages, [])
            result = protect(messages, findings, dict.fromkeys(CATEGORIES, "MASK"), SCOPE, b"f" * 32)
            elapsed = (time.perf_counter() - start) * 1000
            assert result.decision == "MASK"
            assert "fixture@example.com" not in result.messages[0]["content"]
            assert "10.20.30.40" not in result.messages[0]["content"]
            if iteration >= 3:
                durations.append(elapsed)
        results.append(
            {
                "input_characters": len(text),
                "input_utf8_bytes": len(text.encode()),
                "iterations": len(durations),
                "warmup_iterations_excluded": 3,
                "p50_ms": round(statistics.median(durations), 3),
                "p95_ms": round(percentile(durations, 0.95), 3),
                "p99_ms": round(percentile(durations, 0.99), 3),
                "max_ms": round(max(durations), 3),
                "local_processing_target_500ms_met": percentile(durations, 0.95) <= 500,
            }
        )
    report = {
        "schema": "gateway-local-runtime-evaluation-v1",
        "measured_at": datetime.now(UTC).isoformat(),
        "python": platform.python_version(),
        "os": platform.platform(),
        "processor": platform.processor(),
        "profile_checksum": profile_checksum(),
        "model_load_ms": round(load_ms, 3),
        "results": results,
        "limitations": [
            "Warm sequential detection plus HMAC masking only; excludes IPC/queue wait, DB audit and provider latency.",
            "No real provider or load/concurrent capacity claim; queue/timeout/cancellation verified by separate pytest suite.",
            "Three small input sizes do not establish worst-case behavior at the 256 KiB limit.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(args.output), "results": results}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
