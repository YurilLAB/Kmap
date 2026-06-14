/*
 * test_sha256.cc -- proves the self-contained SHA-256 in yuril_export.cc is
 * correct against the FIPS 180-4 / NIST known-answer vectors.
 *
 * yuril_export.cc hashes the export bundle to produce the integrity metadata
 * (kmap-yuril-export.meta.json) that downstream consumers (ypanel, the website
 * intel feed) use to verify the data wasn't tampered with in transit. A wrong
 * hash silently breaks that verification, so the implementation must match a
 * reference bit-for-bit -- not just "look right".
 *
 * The four functions below are copied VERBATIM from yuril_export.cc (keep in
 * sync). The test checks the canonical NIST vectors plus every message length
 * around the 55/56/63/64/65-byte padding boundaries (where length-padding bugs
 * hide) by cross-checking the streaming update path against a single-shot hash.
 *
 * Build (MinGW / any g++):
 *   g++ -O2 -g -std=gnu++17 -Wall fuzz/test_sha256.cc -o fuzz/test_sha256.exe \
 *       && fuzz/test_sha256.exe
 */

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>

/* ===== VERBATIM from yuril_export.cc ===== */
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
/* ===== end verbatim ===== */

static int g_fail = 0;
static void check(const std::string &in, const char *expect, const char *label) {
    std::string got = sha256_hex(in);
    if (got != expect) {
        printf("  FAIL %-14s len=%zu\n    got    %s\n    expect %s\n",
               label, in.size(), got.c_str(), expect);
        g_fail++;
    }
}

/* Hash via single-shot vs byte-at-a-time streaming -- must agree. This proves
   the buffering/padding logic is length-independent (the usual SHA bug site). */
static bool streaming_matches(const std::string &in) {
    std::string one = sha256_hex(in);
    Sha256Ctx c; uint8_t d[32]; sha256_init(&c);
    for (size_t i = 0; i < in.size(); i++) {
        uint8_t b = (uint8_t)in[i];
        sha256_update(&c, &b, 1);
    }
    sha256_final(&c, d);
    static const char hx[] = "0123456789abcdef";
    std::string two; two.resize(64);
    for (int i = 0; i < 32; i++) { two[i*2]=hx[(d[i]>>4)&0xF]; two[i*2+1]=hx[d[i]&0xF]; }
    return one == two;
}

int main(void) {
    printf("SHA-256 (yuril_export.cc) known-answer test\n");
    printf("===========================================\n");

    /* NIST / FIPS 180-4 canonical vectors. */
    check("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "empty");
    check("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "abc");
    check("hello", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "hello");
    /* 448-bit, 56-byte message: one of the two classic FIPS examples. With the
       0x80 + 64-bit length this overflows into a SECOND block, exercising the
       `buflen > 56` two-block padding path -- the trickiest part of final(). */
    check("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "fips-2block");

    int kat_fail = g_fail;
    printf("known-answer vectors: %d/%d failed\n", kat_fail, 4);

    /* Streaming vs single-shot across every padding boundary. */
    int stream_fail = 0;
    for (size_t n = 0; n <= 200; n++) {
        std::string s(n, (char)('A' + (int)(n % 26)));
        if (!streaming_matches(s)) {
            if (stream_fail < 5) printf("  FAIL streaming len=%zu\n", n);
            stream_fail++;
        }
    }
    printf("streaming==single-shot for len 0..200: %s (%d mismatches)\n",
           stream_fail ? "FAIL" : "OK", stream_fail);

    int total = kat_fail + stream_fail;
    printf("\n%s\n", total == 0 ? "sha256 test: ALL PASS" : "sha256 test: FAILURES");
    return total == 0 ? 0 : 1;
}
