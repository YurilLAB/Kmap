#!/usr/bin/env bash
#
# measure-live.sh -- the Kmap benchmarks that need a running binary + a target.
#
# Produces the metrics the component benches in bench/ cannot: network IPs/sec,
# peak RSS, and screenshot throughput. Needs a built ./kmap on Linux and GNU
# /usr/bin/time (not the bash builtin) for peak RSS.
#
# SAFETY: every scan target here is loopback (127.0.0.0/24) or TEST-NET-1
# (192.0.2.0/24, RFC 5737, non-routable) so NO real host is ever contacted.
# TEST-NET is in Kmap's built-in excludes, so --no-builtin-excludes is required
# to measure the raw send loop against it.
#
# Quote every result with the env/flags it used -- each figure is a function of
# KMAP_NETSCAN_CONCURRENCY / KMAP_PROBE_TIMEOUT_MS / --fast / --rate.

set -euo pipefail
KMAP="${KMAP:-./kmap}"
TIME="${TIME:-/usr/bin/time}"
OUT="$(mktemp -d)"
echo "kmap: $KMAP   output: $OUT"

# --- METRIC 1: discovery IPs/sec (network connect rate), SAFE on loopback ----
# A listener on :8000 makes some probes report OPEN; short timeout frees the
# filtered-port workers quickly so the measured rate reflects real throughput.
python3 -m http.server 8000 --bind 127.0.0.1 >/dev/null 2>&1 & SRV=$!
KMAP_NETSCAN_CONCURRENCY=1000 KMAP_PROBE_TIMEOUT_MS=100 \
  "$TIME" -v "$KMAP" --net-scan 127.0.0.1/24 -p 8000 --data-dir "$OUT/d1" \
  2>"$OUT/m1.time" | tee "$OUT/m1.log" || true
kill "$SRV" 2>/dev/null || true
echo "  METRIC 1 IPs/sec = (#IPs probed) / Elapsed(wall) from $OUT/m1.time"
echo "           floor    = concurrency / timeout_s = 1000 / 0.1 = 10000"

# --- METRIC 2: peak RSS (Maximum resident set size), off real hosts ----------
"$TIME" -v "$KMAP" --net-scan 192.0.2.0/24 -p 80,443 --no-builtin-excludes \
  --data-dir "$OUT/d2" 2>"$OUT/m2.time" >/dev/null || true
grep -E "Maximum resident set size|Elapsed" "$OUT/m2.time" || true
"$TIME" -v "$KMAP" --net-scan --fast 192.0.2.0/24 -p 80,443 --no-builtin-excludes \
  --data-dir "$OUT/d2f" 2>"$OUT/m2f.time" >/dev/null || true
echo "  METRIC 2 --fast peak RSS:"; grep -E "Maximum resident set size" "$OUT/m2f.time" || true

# --- METRIC 3: pure send-loop pps WITHOUT touching real hosts (TEST-NET) ------
KMAP_NETSCAN_CONCURRENCY=1000 KMAP_PROBE_TIMEOUT_MS=50 \
  "$TIME" -v "$KMAP" --net-scan 192.0.2.0/24 -p 80 --no-builtin-excludes \
  --rate 25000 --data-dir "$OUT/d3" 2>"$OUT/m3.time" | tee "$OUT/m3.log" || true
echo "  METRIC 3 pps = (probes done from summary) / Elapsed; cross-check vs --rate"

# --- METRIC 4: screenshot rate (needs headless Chromium on PATH) -------------
python3 -m http.server 8001 --bind 127.0.0.1 >/dev/null 2>&1 & SS=$!
"$TIME" -v "$KMAP" --net-scan 127.0.0.1/32 -p 8001 --screenshot \
  --screenshot-dir "$OUT/shots" --data-dir "$OUT/d4" 2>"$OUT/m4.time" >/dev/null || true
kill "$SS" 2>/dev/null || true
echo "  METRIC 4 rate = (#PNGs in $OUT/shots) / Elapsed -- expect <1/sec (serial)"

# --- METRIC 5: enrichment hosts/sec (seed a shard, then --enrich-only) --------
# KMAP_NETSCAN_ENRICH_CONCURRENCY=40  $TIME -v $KMAP --enrich-only --data-dir <seeded>
# KMAP_NETSCAN_ENRICH_CONCURRENCY=256 $TIME -v $KMAP --enrich-only --data-dir <seeded>
# hps = hosts / Elapsed; also read the per-pass avg=/max=/budget-bailed= line.
echo "  METRIC 5: see comments -- run --enrich-only over a seeded shard at conc 40 vs 256"

# --- METRIC 6: real bytes/row (confirm the bench_db estimate on YOUR data) ----
# sqlite3 <shard>.db 'VACUUM;' ; stat -c%s <shard>.db
# sqlite3 <shard>.db 'SELECT count(*) FROM hosts; SELECT count(*) FROM fingerprints;'
echo "done. results under $OUT"
