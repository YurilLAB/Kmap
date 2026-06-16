// test_throughput.cc -- pins the hosts/sec throughput-rate contract used by the
// net-scan / watchlist completion summaries (net_scan.cc) and the regular-scan
// "Kmap done" line (output.cc). The rate is computed as
//     rate = secs > 0.001 ? count / secs : 0.0
// The load-bearing property is the guard: a scan that finishes in <=1 ms, or
// that pipelined 0 hosts, must NEVER divide by zero / emit inf or nan -- it
// must report 0.0. This is a copy-pin (the production sites are one-liners
// inlined in net_scan.cc/output.cc); keep it byte-identical to those.
#include <cstdint>
#include <cstdio>
#include <cmath>
#include <cstdlib>

// Verbatim copy of the production rate expression.
static double rate(uint64_t count, double secs) {
    return secs > 0.001 ? static_cast<double>(count) / secs : 0.0;
}

static int fails = 0;
static void check(bool ok, const char *msg) {
    if (!ok) { printf("FAIL: %s\n", msg); fails++; }
}
// approx compare: 1% relative tolerance plus a small absolute floor so it
// works across the wide magnitude range (sub-1 hosts/sec up to ~135 IPs/sec).
static bool near(double a, double b) {
    return std::fabs(a - b) <= 0.01 * std::fabs(b) + 0.01;
}

int main(int argc, char **argv) {
    // 1. Div-by-zero guard: secs == 0 -> 0.0 (no inf/nan).
    double r0 = rate(100, 0.0);
    check(r0 == 0.0, "secs=0 must yield 0.0");
    check(std::isfinite(r0), "secs=0 must be finite (no inf/nan)");

    // 2. Sub-millisecond denom (<=0.001) -> 0.0, also finite.
    check(rate(1000, 0.0005) == 0.0, "secs=0.5ms must yield 0.0");
    check(rate(1000, 0.001) == 0.0, "secs=1ms (boundary, not >) must yield 0.0");
    check(std::isfinite(rate(1000000, 0.0)), "huge count / 0 secs must be finite");

    // 3. Zero hosts pipelined -> 0.0 regardless of duration.
    check(rate(0, 50.0) == 0.0, "0 hosts over 50s must be 0.0");

    // 4. Correct arithmetic on representative real values.
    check(near(rate(72, 22.5), 3.2), "72 hosts / 22.5s ~= 3.2 hosts/sec");
    check(near(rate(256, 1.9), 134.7), "256 IPs / 1.9s ~= 134.7 IPs/sec");
    check(near(rate(1, 11.55), 0.0866), "1 host / 11.55s ~= 0.09 hosts/sec");
    check(near(rate(1196, 132.0), 9.06), "1196 hosts / 132s ~= 9.06 hosts/sec");

    // 5. Just past the guard boundary computes (not zeroed).
    check(rate(1, 0.002) > 0.0, "secs just over 1ms must compute a real rate");

    // 6. Monotonic: more hosts in same time => higher rate; longer time same
    //    hosts => lower rate. Catches an accidental inversion of the division.
    check(rate(200, 10.0) > rate(100, 10.0), "more hosts -> higher rate");
    check(rate(100, 5.0)  > rate(100, 10.0), "less time -> higher rate");

    // 7. Always finite and non-negative across a randomized sweep.
    unsigned seed = (argc > 1) ? (unsigned)strtoul(argv[1], nullptr, 10) : 1u;
    uint64_t st = seed ? seed : 1u;
    for (int i = 0; i < 2000000; i++) {
        st = st * 6364136223846793005ULL + 1442695040888963407ULL;
        uint64_t cnt = st % 5000000ULL;
        double secs = (double)((st >> 20) % 1000000ULL) / 1000.0; // 0..1000s
        double r = rate(cnt, secs);
        if (!std::isfinite(r) || r < 0.0) {
            printf("FAIL: non-finite/negative rate cnt=%llu secs=%f r=%f\n",
                   (unsigned long long)cnt, secs, r);
            fails++; break;
        }
    }

    if (fails) { printf("throughput test: %d FAILURE(S)\n", fails); return 1; }
    printf("throughput test: PASS\n");
    return 0;
}
