/*
 * yuril_export.cc -- Kmap -> Yuril Security Suite export writer.
 *
 * Emits a versioned JSON bundle into a caller-supplied directory:
 *
 *   <dir>/kmap-yuril-export.json         (data; extends --json schema)
 *   <dir>/kmap-yuril-export.meta.json    (integrity metadata)
 *
 * Both files are written atomically (tmpfile + rename) so a partially
 * written export is never observable by a concurrent Yuril reader.
 *
 * SHA-256 is computed in-tree so this file has no dependency on OpenSSL
 * (Kmap can be built without it).
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "yuril_export.h"
#include "output_json.h"

#include "third-party/nlohmann/json.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <string>

#ifdef WIN32
#  include <direct.h>
#  include <io.h>
#  include <windows.h>
#else
#  include <sys/stat.h>
#  include <unistd.h>
#endif

/* =======================================================================
 * Self-contained SHA-256 (FIPS 180-4).
 * Small and dependency-free: one hash per export, not perf-critical.
 * ======================================================================= */

namespace {

struct Sha256Ctx {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
};

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline uint32_t rotr32(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

static void sha256_transform(Sha256Ctx *c, const uint8_t *blk) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = (uint32_t)blk[i*4+0] << 24 | (uint32_t)blk[i*4+1] << 16 |
               (uint32_t)blk[i*4+2] <<  8 | (uint32_t)blk[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i-15], 7)  ^ rotr32(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2], 17)  ^ rotr32(w[i-2], 19) ^ (w[i-2]  >>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=c->state[0],b=c->state[1],d=c->state[2],e=c->state[3],
             f=c->state[4],g=c->state[5],h=c->state[6],i2=c->state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(f,6) ^ rotr32(f,11) ^ rotr32(f,25);
        uint32_t ch = (f & g) ^ (~f & h);
        uint32_t t1 = i2 + S1 + ch + K256[i] + w[i];
        uint32_t S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        uint32_t mj = (a & b) ^ (a & d) ^ (b & d);
        uint32_t t2 = S0 + mj;
        i2 = h; h = g; g = f; f = e + t1;
        e = d; d = b; b = a; a = t1 + t2;
    }
    c->state[0]+=a; c->state[1]+=b; c->state[2]+=d; c->state[3]+=e;
    c->state[4]+=f; c->state[5]+=g; c->state[6]+=h; c->state[7]+=i2;
}

static void sha256_init(Sha256Ctx *c) {
    c->state[0]=0x6a09e667; c->state[1]=0xbb67ae85;
    c->state[2]=0x3c6ef372; c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f; c->state[5]=0x9b05688c;
    c->state[6]=0x1f83d9ab; c->state[7]=0x5be0cd19;
    c->bitlen = 0;
    c->buflen = 0;
}

static void sha256_update(Sha256Ctx *c, const uint8_t *data, size_t len) {
    c->bitlen += (uint64_t)len * 8;
    while (len > 0) {
        size_t space = 64 - c->buflen;
        size_t take  = (len < space) ? len : space;
        memcpy(c->buf + c->buflen, data, take);
        c->buflen += take;
        data      += take;
        len       -= take;
        if (c->buflen == 64) {
            sha256_transform(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void sha256_final(Sha256Ctx *c, uint8_t out[32]) {
    uint64_t bitlen = c->bitlen;
    c->buf[c->buflen++] = 0x80;
    if (c->buflen > 56) {
        while (c->buflen < 64) c->buf[c->buflen++] = 0;
        sha256_transform(c, c->buf);
        c->buflen = 0;
    }
    while (c->buflen < 56) c->buf[c->buflen++] = 0;
    for (int i = 7; i >= 0; i--) c->buf[c->buflen++] = (uint8_t)(bitlen >> (i*8));
    sha256_transform(c, c->buf);
    for (int i = 0; i < 8; i++) {
        out[i*4+0] = (uint8_t)(c->state[i] >> 24);
        out[i*4+1] = (uint8_t)(c->state[i] >> 16);
        out[i*4+2] = (uint8_t)(c->state[i] >>  8);
        out[i*4+3] = (uint8_t)(c->state[i]);
    }
}

static std::string sha256_hex(const std::string &data) {
    Sha256Ctx c;
    uint8_t digest[32];
    sha256_init(&c);
    sha256_update(&c, reinterpret_cast<const uint8_t *>(data.data()), data.size());
    sha256_final(&c, digest);
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.resize(64);
    for (int i = 0; i < 32; i++) {
        out[i*2+0] = hex[(digest[i] >> 4) & 0xF];
        out[i*2+1] = hex[digest[i] & 0xF];
    }
    return out;
}

/* =======================================================================
 * Filesystem helpers
 * ======================================================================= */

static std::string path_join(const std::string &dir, const std::string &name) {
    if (dir.empty()) return name;
    char last = dir[dir.size()-1];
    if (last == '/' || last == '\\') return dir + name;
#ifdef WIN32
    return dir + "\\" + name;
#else
    return dir + "/" + name;
#endif
}

static int write_atomic(const std::string &path, const std::string &content) {
    std::string tmp = path + ".tmp";

    {
        std::ofstream ofs(tmp, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) {
            fprintf(stderr,
                "KMAP WARNING: --yuril-export: cannot open %s for writing.\n",
                tmp.c_str());
            return 1;
        }
        /* Parenthesize the member name so the preprocessor sees ')' after
         * 'write' and skips expanding nbase.h's #define write _write
         * (MSVC POSIX-shim alias). Without this, ofs.write(...) becomes
         * ofs._write(...) on Windows and the linker can't find that
         * member. Same trick used for ofs.close() above. */
        (ofs.write)(content.data(), static_cast<std::streamsize>(content.size()));
        if (!ofs.good()) {
            fprintf(stderr,
                "KMAP WARNING: --yuril-export: write error on %s.\n", tmp.c_str());
            /* Parenthesize the member name so the preprocessor sees ')'
             * after 'close' and skips expanding nbase_winunix.h's
             * #define close(x) closesocket(x), which would otherwise
             * mangle ofs.close() into ofs.closesocket() on Windows. */
            (ofs.close)();
            std::remove(tmp.c_str());
            return 1;
        }
    }

#ifdef WIN32
    if (!MoveFileExA(tmp.c_str(), path.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        fprintf(stderr,
            "KMAP WARNING: --yuril-export: rename %s -> %s failed (err=%lu).\n",
            tmp.c_str(), path.c_str(), (unsigned long)GetLastError());
        std::remove(tmp.c_str());
        return 1;
    }
#else
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        fprintf(stderr,
            "KMAP WARNING: --yuril-export: rename %s -> %s failed: %s.\n",
            tmp.c_str(), path.c_str(), std::strerror(errno));
        std::remove(tmp.c_str());
        return 1;
    }
#endif
    return 0;
}

static bool dir_is_writable(const std::string &dir) {
    if (dir.empty()) return false;
    std::string probe = path_join(dir, ".kmap-yuril-probe");
    FILE *f = std::fopen(probe.c_str(), "wb");
    if (!f) return false;
    std::fclose(f);
    std::remove(probe.c_str());
    return true;
}

static std::string iso8601_utc(long epoch) {
    std::time_t t = static_cast<std::time_t>(epoch);
    std::tm tmv{};
#ifdef WIN32
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return std::string(buf);
}

/* =======================================================================
 * Module state — one export per run, mirroring the json_* pattern.
 * ======================================================================= */

static nlohmann::json g_doc;
static std::string    g_dir;
static std::string    g_kmap_version;
static int            g_host_count  = 0;
static int            g_cve_count   = 0;
static bool           g_active      = false;

} /* namespace */

/* =======================================================================
 * Public API
 * ======================================================================= */

void yuril_export_initialize(const char *out_dir) {
    if (out_dir == nullptr || out_dir[0] == '\0') {
        g_active = false;
        return;
    }

    if (!dir_is_writable(out_dir)) {
        fprintf(stderr,
            "KMAP WARNING: --yuril-export: directory %s is not writable; "
            "export will be skipped.\n", out_dir);
        g_active = false;
        return;
    }

    g_dir          = out_dir;
    g_host_count   = 0;
    g_cve_count    = 0;
    g_kmap_version.clear();
    g_doc = {
        {"schema_version", KMAP_YURIL_SCHEMA_VERSION},
        {"export_type",    "yuril"},
        {"kmap",           nlohmann::json::object()},
        {"hosts",          nlohmann::json::array()},
        {"stats",          nlohmann::json::object()}
    };
    g_active = true;
}

void yuril_export_write_scaninfo(const char *kmap_version,
                                 const char *args,
                                 long start_time) {
    if (!g_active) return;
    g_kmap_version = kmap_version ? std::string(kmap_version) : std::string();
    g_doc["kmap"]["version"] = g_kmap_version;
    g_doc["kmap"]["args"]    = args ? std::string(args) : std::string();
    g_doc["kmap"]["start"]   = static_cast<long long>(start_time);
}

void yuril_export_write_host(const Target *t) {
    if (!g_active || t == nullptr) return;
    nlohmann::json h = build_host_json(t);
    if (h.contains("cves"))
        g_cve_count += static_cast<int>(h["cves"].size());
    g_doc["hosts"].push_back(std::move(h));
    g_host_count++;
}

void yuril_export_write_stats(int up, int down, int total, float elapsed) {
    if (!g_active) return;
    g_doc["stats"]["hosts_up"]    = up;
    g_doc["stats"]["hosts_down"]  = down;
    g_doc["stats"]["hosts_total"] = total;
    g_doc["stats"]["elapsed"]     = static_cast<double>(elapsed);
}

void yuril_export_finalize(void) {
    if (!g_active) return;

    std::string data_json;
    try {
        data_json = g_doc.dump(2);
        data_json += "\n";
    } catch (const std::exception &e) {
        fprintf(stderr,
            "KMAP WARNING: --yuril-export: JSON serialization failed: %s\n",
            e.what());
        g_active = false;
        g_doc = nlohmann::json{};
        return;
    }

    std::string sha = sha256_hex(data_json);

    nlohmann::json meta;
    meta["schema_version"] = KMAP_YURIL_SCHEMA_VERSION;
    meta["export_type"]    = "yuril";
    meta["produced_at"]    = iso8601_utc(std::time(nullptr));
    meta["kmap_version"]   = g_kmap_version;
    meta["sha256"]         = sha;
    meta["host_count"]     = g_host_count;
    meta["cve_count"]      = g_cve_count;
    meta["data_file"]      = KMAP_YURIL_EXPORT_DATA_FILE;

    std::string meta_json;
    try {
        meta_json = meta.dump(2);
        meta_json += "\n";
    } catch (const std::exception &e) {
        fprintf(stderr,
            "KMAP WARNING: --yuril-export: metadata serialization failed: %s\n",
            e.what());
        g_active = false;
        g_doc = nlohmann::json{};
        return;
    }

    std::string data_path = path_join(g_dir, KMAP_YURIL_EXPORT_DATA_FILE);
    std::string meta_path = path_join(g_dir, KMAP_YURIL_EXPORT_META_FILE);

    if (write_atomic(data_path, data_json) != 0) {
        g_active = false;
        g_doc = nlohmann::json{};
        return;
    }
    if (write_atomic(meta_path, meta_json) != 0) {
        /* Keep data+meta either both-present-and-consistent or both-absent. */
        std::remove(data_path.c_str());
        g_active = false;
        g_doc = nlohmann::json{};
        return;
    }

    fprintf(stdout,
        "Yuril export written: %d host(s), %d CVE(s) -> %s\n",
        g_host_count, g_cve_count, data_path.c_str());

    /* Release memory. */
    g_doc = nlohmann::json{};
    g_dir.clear();
    g_kmap_version.clear();
    g_active = false;
}
