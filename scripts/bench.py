#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import ssl
import statistics
import time
import urllib.request


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round((pct / 100.0) * (len(ordered) - 1))))
    return ordered[index]


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark Serverware proxy overhead against the demo echo route.")
    parser.add_argument("--url", default="https://demo-upstream:8443/echo")
    parser.add_argument("--proxy", default="http://localhost:8080")
    parser.add_argument("--ca", default=".tmp/serverware-ca.pem")
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=10)
    args = parser.parse_args()

    context = ssl.create_default_context(cafile=args.ca)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": args.proxy, "https": args.proxy}),
        urllib.request.HTTPSHandler(context=context),
    )

    latencies_ms: list[float] = []
    total = args.warmup + args.requests
    for index in range(total):
        request = urllib.request.Request(args.url, headers={"X-Serverware-Agent": "demo-agent"})
        start = time.perf_counter()
        with opener.open(request, timeout=15) as response:
            body = response.read()
            if response.status != 200:
                raise SystemExit(f"unexpected status {response.status}: {body!r}")
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        if index >= args.warmup:
            latencies_ms.append(elapsed_ms)

    result = {
        "url": args.url,
        "proxy": args.proxy,
        "requests": args.requests,
        "warmup": args.warmup,
        "p50_ms": round(statistics.median(latencies_ms), 3),
        "p95_ms": round(percentile(latencies_ms, 95), 3),
        "p99_ms": round(percentile(latencies_ms, 99), 3),
        "min_ms": round(min(latencies_ms), 3),
        "max_ms": round(max(latencies_ms), 3),
        "mean_ms": round(statistics.mean(latencies_ms), 3),
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
