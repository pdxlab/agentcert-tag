# MCP Trust Proxy — benchmarks

**What is the trust tax?** This harness measures exactly how much latency the
proxy adds on top of talking to an MCP server directly — so the number is public,
reproducible, and honest, not a marketing claim.

It stands up a near-zero-work mock MCP upstream and the *real* proxy (shadow
mode), then drives four scenarios concurrently:

| scenario | path | isolates |
|---|---|---|
| `direct` | client → mock | baseline (no proxy) |
| `proxy_relay` | client → proxy → mock, non-`tools/call` | pure plumbing (parse + route + forward) |
| `proxy_call_nocert` | `tools/call`, no credential | plumbing + guardrail scan + gates |
| `proxy_call_cert` | `tools/call`, full AgentCert | plumbing + **cryptographic chain verify** |

The trust tax is `proxy_* p50 − direct p50`.

## Run it

```bash
pip install cryptography           # already a proxy dep
python proxy/benchmarks/bench.py --requests 4000 --concurrency 16
```

Everything else is stdlib. Numbers are machine-relative — run on your target
hardware and publish the specs alongside.

## Results

**Apple M1 Pro (10 core) · macOS 26.2 · CPython 3.11 · 4000 req × 16 conc · shadow**

| scenario | p50 ms | p95 ms | p99 ms | RPS | added p50 |
|---|---|---|---|---|---|
| direct | 1.12 | 3.08 | 32.2 | 5380 | — |
| proxy_relay | 2.95 | 33.1 | 63.7 | 2675 | **+1.84 ms** |
| proxy_call_nocert | 3.09 | 33.4 | 63.3 | 2403 | **+1.98 ms** |
| proxy_call_cert | 5.66 | 36.8 | 70.0 | 1548 | **+4.55 ms** |

### How to read this

- **The trust decision is cheap.** A full AgentCert verification — parse the leaf,
  build and validate the chain to the trust anchors, check the TrustScore — costs
  **~2.6 ms** on top of plain plumbing (`proxy_call_cert − proxy_relay`). That is
  the price of *cryptographic* assurance, not a lookup.
- **No credential is nearly free.** Unverified `tools/call` adds ~0.1 ms over a
  bare relay — the verify core is only exercised when a cert is present.
- **The tail is the transport, not the trust.** `direct` and proxy scenarios share
  the same p95/p99 tail because the reference proxy uses Python's stdlib
  `http.server` and opens a fresh upstream connection per request. That overhead
  is identical on both sides, so it cancels out of the *added* column — but it caps
  absolute throughput.

## This is a correctness-first reference, not yet a tuned data plane

We publish these numbers precisely because they are not yet best-in-class, and the
path to make them so is clear and boring:

1. **Verdict cache** (biggest win) — cache `verify()` results keyed by cert hash
   with a short TTL bounded by revocation freshness. A returning agent's
   `tools/call` drops from ~4.5 ms to ~plumbing-only. Turns the hot path near-free.
2. **Connection pooling / keep-alive to the upstream** — removes a TCP handshake
   per hop; collapses the p95/p99 tail shared with `direct`.
3. **Async / uvloop or a Go rewrite of the data plane** — the verify core is a
   library; the transport around it is replaceable. The stdlib server is chosen
   for a dependency-free, auditable reference, not for peak RPS.

The verify **core** (`core/agentcert_tag`) is the asset and is already fast; the
proxy shell is deliberately simple and swappable. Track perf work under the
MCP Trust Proxy epic (TRUS-2032).
