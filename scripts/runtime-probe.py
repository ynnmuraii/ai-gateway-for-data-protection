"""Bounded local preview probe; prints timings/status counts, never credentials or original text."""

import asyncio
import json
import statistics
import time
from collections import Counter
from pathlib import Path

import httpx

root = Path(__file__).resolve().parents[1]


async def main():
    access = json.loads((root / ".runtime/compose-access.json").read_text("utf-8"))
    async with httpx.AsyncClient(base_url="http://localhost:8080", timeout=30, trust_env=False) as client:
        login = await client.post(
            "/admin/api/auth/login",
            headers={"Origin": "http://localhost:8080"},
            json={"username": access["admin_username"], "password": access["admin_password"]},
        )
        login.raise_for_status()
        headers = {
            "Origin": "http://localhost:8080",
            "X-CSRF-Token": login.json()["csrf_token"],
            "Cookie": "gw_admin_session=" + login.cookies["gw_admin_session"],
        }

        async def check(text):
            started = time.perf_counter()
            response = await client.post(
                "/admin/api/preview", headers=headers, json={"messages": [{"role": "user", "content": text}]}
            )
            if response.status_code == 200:
                assert response.json()["decision"] == "MASK"
                assert "probe@example.com" not in response.text
            return response.status_code, (time.perf_counter() - started) * 1000

        sequential = [await check("Лог: probe@example.com at 10.0.0.1") for _ in range(20)]
        concurrent = await asyncio.gather(
            *(check("probe@example.com " + ("ordinary log line\n" * 150)) for _ in range(12))
        )
        assert all(code == 200 for code, _ in sequential)
        assert all(code in (200, 429) for code, _ in concurrent)
        assert any(code == 429 for code, _ in concurrent)
        assert (await client.get("/health/ready")).status_code == 200
        values = sorted(duration for _, duration in sequential)
        result = {
            "sequential_requests": len(sequential),
            "median_ms": round(statistics.median(values), 2),
            "observed_p95_ms": round(values[18], 2),
            "simultaneous_requests_single_user": len(concurrent),
            "status_counts": dict(Counter(code for code, _ in concurrent)),
            "healthy_after": True,
        }
        (root / ".runtime/runtime-probe.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result))
        await client.post("/admin/api/auth/logout", headers=headers)


if __name__ == "__main__":
    asyncio.run(main())
