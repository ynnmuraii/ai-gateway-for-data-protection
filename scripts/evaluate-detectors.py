"""Reproducible, offline synthetic span evaluation. This never calls an LLM.

The generator and labels are versioned; generated JSONL and measured reports go to
.runtime/qa-sprint2 by default. Tuning and held-out examples use disjoint value
sequences and context templates (finite fictional phone ranges may recur). Generated
data is not evidence of production accuracy.
"""

import argparse
import base64
import hashlib
import json
import platform
import random
import string
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from gateway.detection import CATEGORIES, Detector, profile_checksum

SEED = 20261109
POSITIVE_COUNT = 300
NEGATIVE_COUNT = 300
TUNING_CONTEXTS = ("Contact: {v}", "Контакт: {v}", 'value="{v}"', "[{v}]", "{v}")
HELDOUT_CONTEXTS = (
    "Журнал 😀\n  поле: {v}\nконец",
    "Incident report: '{v}'; completed.",
    "status=failed; address={v}; retry=false",
    "Диагностика ({v}) завершена.",
    "Service record\t{v}\tOK",
)


def encoded(value):
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")


def jwt_value(index):
    return ".".join(
        (
            encoded({"alg": "HS256", "typ": "JWT"}),
            encoded({"sub": f"synthetic-user-{index}", "fixture": True}),
            base64.urlsafe_b64encode(hashlib.sha256(str(index).encode()).digest()).decode().rstrip("="),
        )
    )


def token(rng, length, alphabet=string.ascii_letters + string.digits):
    return "".join(rng.choice(alphabet) for _ in range(length))


def sample_value(category, positive, index, rng):
    """Return (rendered value, exact expected entity, format family)."""
    variant = index % 6
    if category == "EMAIL":
        local = (
            f"person{index}",
            f"first.last{index}",
            f"qa+case{index}",
            f"support-{index}",
            f"dev_{index}",
            f"a{index}.b",
        )[variant]
        value = f"{local}@team{index}.example.com"
        if positive:
            return value, value, f"email-{variant}"
        value = (
            f"{local} at example.com",
            f"{local}@",
            f"@team{index}",
            f"{local}..bad@example.com",
            f"{local}@example",
            f"{local}@@example.com",
        )[variant]
        return value, None, f"email-negative-{variant}"
    if category == "PHONE":
        # US 555-01xx is a fictional range. Other forms are synthetic format
        # fixtures only; they must never be dialled or treated as contact data.
        last = index % 100
        value = (
            f"+1 202-555-01{last:02d}",
            f"(202) 555-01{last:02d}",
            f"+120255501{last:02d}",
            f"+44 20 7946 00{last:02d}",
            f"+7 (912) 345-{index % 100:02d}-{(index * 7) % 100:02d}",
            f"8 (912) 345-{index % 100:02d}-{(index * 7) % 100:02d}",
        )[variant]
        if positive:
            return value, value, f"phone-{variant}"
        value = (
            f"build-{index:04d}",
            f"202-55-{index % 100:02d}",
            f"+000 12 {index:04d}",
            "12345",
            f"version=1.2.{index}",
            f"order={index:08d}",
        )[variant]
        return value, None, f"phone-negative-{variant}"
    if category == "IP_ADDRESS":
        a, b = (index // 250) % 250 + 1, index % 250 + 1
        value = (
            f"10.{a}.{b}.4",
            f"172.{16 + index % 16}.{a}.{b}",
            f"192.168.{a}.{b}",
            f"100.{64 + index % 64}.{a}.{b}",
            f"fd{index % 256:02x}::{index + 1:x}",
            f"fe80::{index + 1:x}",
        )[variant]
        if positive:
            return value, value, f"private-ip-{variant}"
        value = (
            f"8.8.{a}.{b}",
            f"1.1.{a}.{b}",
            f"2001:4860::{index + 1:x}",
            f"999.2.{a}.{b}",
            f"192.169.{a}.{b}",
            f"172.32.{a}.{b}",
        )[variant]
        return value, None, f"public-or-invalid-ip-{variant}"
    if category == "INTERNAL_HOSTNAME":
        value = (
            f"db-{index}.internal",
            f"node{index}.prod.corp",
            f"svc{index}.local",
            f"NODE{index}.INTERNAL",
            f"api-{index}.qa.corp",
            f"x{index}.y.z.local",
        )[variant]
        if positive:
            return value, value, f"internal-host-{variant}"
        value = (
            f"node{index}.example.com",
            f"db{index}.internal.evil",
            f"db{index}.corp.example.org",
            f"node{index}.locally",
            f"node{index}.corporate",
            f"internal-node-{index}",
        )[variant]
        return value, None, f"public-host-{variant}"
    if category == "API_KEY":
        value = (
            ("AKIA" if variant % 2 == 0 else "ASIA") + token(rng, 16, string.ascii_uppercase + string.digits)
            if variant < 2
            else ("sk-", "sk-proj-", "sk-svcacct-", "sk-")[variant - 2] + token(rng, 36)
        )
        if positive:
            return value, value, f"api-key-{variant}"
        value = (
            "AKIA" + token(rng, 15, string.ascii_uppercase),
            "ASIA" + token(rng, 17, string.ascii_uppercase),
            "sk-" + token(rng, 19),
            "AKIA" + token(rng, 16, string.ascii_lowercase),
            "sk-project",
            f"api_key=short{index}",
        )[variant]
        return value, None, f"malformed-api-key-{variant}"
    if category == "ACCESS_TOKEN":
        if variant < 3:
            value = ("ghp_", "gho_", "ghs_")[variant] + token(rng, 36)
        elif variant == 3:
            value = "github_pat_" + token(rng, 64)
        elif variant == 4:
            value = "xoxb-123456789012-123456789012-" + token(rng, 24)
        else:
            value = token(rng, 32)
            if positive:
                return "Authorization: Bearer " + value, value, "bearer-context"
        if positive:
            return value, value, f"access-token-{variant}"
        value = (
            "ghp_" + token(rng, 35),
            "gho_" + token(rng, 37),
            "ghs_short",
            "github_pat_" + token(rng, 20),
            "xoxb-123-456-short",
            "token=short",
        )[variant]
        return value, None, f"malformed-access-token-{variant}"
    if category == "JWT":
        value = jwt_value(index)
        if positive:
            return value, value, "jwt-local-format"
        parts = value.split(".")
        value = (
            "not-json." + parts[1] + "." + parts[2],
            encoded({"alg": 123}) + "." + parts[1] + "." + parts[2],
            parts[0] + "." + encoded(["not-a-claims-object"]) + "." + parts[2],
            parts[0] + "." + parts[1] + ".",
            "a.b.c",
            f"v{index}.2.3",
        )[variant]
        return value, None, f"malformed-jwt-{variant}"
    raise AssertionError(category)


def build_corpus():
    rng = random.Random(SEED)
    corpus = []
    for category in CATEGORIES:
        for positive in (True, False):
            for index in range(POSITIVE_COUNT if positive else NEGATIVE_COUNT):
                split = "tuning" if index < 100 else "heldout"
                # Values in the two partitions use separate deterministic sequences.
                value, expected, family = sample_value(
                    category, positive, index + (10000 if split == "heldout" else 0), rng
                )
                contexts = TUNING_CONTEXTS if split == "tuning" else HELDOUT_CONTEXTS
                text = contexts[index % len(contexts)].format(v=value)
                labels = []
                if expected is not None:
                    start = text.index(expected)
                    labels = [{"category": category, "start": start, "end": start + len(expected)}]
                corpus.append(
                    {
                        "id": f"{category}-{int(positive)}-{index:03d}",
                        "category": category,
                        "positive": positive,
                        "split": split,
                        "family": family,
                        "text": text,
                        "labels": labels,
                    }
                )
    return corpus


def evaluate(detector, corpus):
    counts = {(split, category): Counter() for split in ("tuning", "heldout") for category in CATEGORIES}
    errors = []
    for sample in corpus:
        found = detector.analyze([{"role": "user", "content": sample["text"]}], [])
        expected = {(f["category"], f["start"], f["end"]) for f in sample["labels"]}
        actual = {(f.category, f.start, f.end) for f in found}
        for category in CATEGORIES:
            bucket = counts[sample["split"], category]
            want = {f for f in expected if f[0] == category}
            got = {f for f in actual if f[0] == category}
            bucket.update(tp=len(want & got), fp=len(got - want), fn=len(want - got))
            bucket.update(
                covered_entities=sum(any(g[1] <= w[1] and g[2] >= w[2] for g in got) for w in want),
                boundary_expansions=sum(
                    any(g[1] <= w[1] and g[2] >= w[2] and g != w for g in got) for w in want
                ),
            )
            if category == sample["category"]:
                bucket.update(
                    positive_samples=int(sample["positive"]), negative_samples=int(not sample["positive"])
                )
        if expected != actual:
            errors.append(
                {
                    "id": sample["id"],
                    "split": sample["split"],
                    "family": sample["family"],
                    "expected": [list(f) for f in sorted(expected)],
                    "actual": [list(f) for f in sorted(actual)],
                }
            )
    result = {}
    for (split, category), count in counts.items():
        tp, fp, fn = (count[name] for name in ("tp", "fp", "fn"))
        result.setdefault(split, {})[category] = dict(count) | {
            "precision": round(tp / (tp + fp), 6) if tp + fp else 0,
            "recall": round(tp / (tp + fn), 6) if tp + fn else 0,
            "sensitive_value_coverage": round(count["covered_entities"] / (tp + fn), 6) if tp + fn else 0,
        }
    return result, errors


def markdown_report(report):
    lines = [
        "# Synthetic detector evaluation",
        "",
        f"Measured: {report['measured_at']}",
        f"Profile checksum: `{report['profile_checksum']}`",
        "",
        (
            f"{report['samples']} deterministic samples; 300 positive + 300 negative per category; "
            "tuning: 100 + 100, held-out: 200 + 200. Exact category and Python Unicode spans are scored."
        ),
        "",
        "| Split | Category | TP | FP | FN | Precision | Recall | Value coverage | Expanded spans |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for split, rows in report["metrics"].items():
        for category, row in rows.items():
            lines.append(
                f"| {split} | {category} | {row['tp']} | {row['fp']} | {row['fn']} | "
                f"{row['precision']:.3f} | {row['recall']:.3f} | "
                f"{row['sensitive_value_coverage']:.3f} | {row['boundary_expansions']} |"
            )
    lines.extend(
        [
            "",
            "## Interpretation and limits",
            "",
            "- Goal: precision and recall >= 0.95 on held-out examples, reported separately per category.",
            "- Every unexpected category/span is counted as a false positive, including cross-category findings.",
            (
                "- Value coverage separately measures whether the whole labeled value is covered by a finding of its category; "
                "an expanded span may mask the value safely while losing context. It does not replace exact-span precision/recall."
            ),
            "- JSON mismatches contain sample IDs and offsets, never copies of submitted values.",
            (
                "- Samples are generated from supported formats and hard negatives; rendered texts and context templates are disjoint across partitions. "
                "Phone values can recur within finite fictional ranges, and format families overlap. This is a regression/coverage set, "
                "not an independent real-world benchmark."
            ),
            (
                "- The held-out labels are generated before evaluation. If these cases drive detector changes, treat this set as regression "
                "data and obtain a fresh independent corpus before claiming validated production accuracy."
            ),
            "- No online key validation, production data, real credentials, external LLM, or network is used.",
            (
                "- Encodings, zero-width characters, deliberate obfuscation, novel secret formats and context reconstruction remain limitations; "
                "syntactic detection cannot establish that an API key is genuine or that masking removes all identifying context."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / ".runtime" / "qa-sprint2")
    parser.add_argument("--generate-only", action="store_true")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit nonzero if any held-out category misses precision/recall 0.95.",
    )
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    corpus = build_corpus()
    data = "".join(json.dumps(sample, ensure_ascii=False, sort_keys=True) + "\n" for sample in corpus)
    (args.output / "detector-corpus.jsonl").write_text(data, encoding="utf-8")
    if args.generate_only:
        print(f"Generated {len(corpus)} labeled synthetic examples at {args.output}")
        return 0
    started = time.perf_counter()
    detector = Detector()
    loaded = time.perf_counter()
    metrics, errors = evaluate(detector, corpus)
    report = {
        "schema": "gateway-synthetic-evaluation-v1",
        "measured_at": datetime.now(UTC).isoformat(),
        "seed": SEED,
        "python": platform.python_version(),
        "profile_checksum": profile_checksum(),
        "corpus_sha256": hashlib.sha256(data.encode()).hexdigest(),
        "samples": len(corpus),
        "model_load_seconds": round(loaded - started, 3),
        "evaluation_seconds": round(time.perf_counter() - loaded, 3),
        "metrics": metrics,
        "mismatches": errors,
    }
    (args.output / "detector-evaluation.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (args.output / "detector-evaluation.md").write_text(markdown_report(report), encoding="utf-8")
    passed = all(row["precision"] >= 0.95 and row["recall"] >= 0.95 for row in metrics["heldout"].values())
    print(
        json.dumps(
            {
                "samples": len(corpus),
                "mismatches": len(errors),
                "heldout_target_met": passed,
                "evaluation_seconds": report["evaluation_seconds"],
                "output": str(args.output),
            }
        )
    )
    return 0 if passed or not args.check else 1


if __name__ == "__main__":
    raise SystemExit(main())
