/*
 * md5.h -- Self-contained MD5 (RFC 1321), header-only.
 *
 * MD5 is cryptographically broken for collision resistance and MUST NOT be
 * used for any security decision.  It lives here for one reason only: the
 * HASSH SSH-fingerprint standard (Salesforce) is *defined* as the MD5 of a
 * specific algorithm-list string, exactly as Shodan's `ssh.hassh` and Censys
 * publish it.  To produce a value that pivots against those datasets we must
 * compute the same MD5 they do -- the hash choice is fixed by the spec, not by
 * us.  No other Kmap code path may use this for integrity/authentication.
 *
 * Header-only (every function `static inline`) means each TU gets its own
 * internal-linkage copy -- no new .cc, no Makefile/vcxproj parity edit -- the
 * same pattern sha256.h uses.  Bytes are decoded/encoded little-endian
 * explicitly (MD5 is little-endian) so the result is identical on big-endian
 * targets and never trips an unaligned-access trap.
 *
 * Validated against the RFC 1321 known-answer suite by fuzz/test_hassh.cc,
 * which keeps a byte-identical standalone copy as a regression pin.  If you
 * ever change the math here, update that copy too.
 */

#ifndef KMAP_MD5_H
#define KMAP_MD5_H

#include <cstdint>
#include <cstring>
#include <string>

struct Md5Ctx {
    uint32_t state[4];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
};

/* T[i] = floor(2^32 * abs(sin(i+1))), i = 0..63 (RFC 1321). */
static const uint32_t KMAP_MD5_T[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

/* Per-round left-rotate amounts. */
static const int KMAP_MD5_S[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

static inline uint32_t kmap_md5_rotl(uint32_t x, int c) {
    return (x << c) | (x >> (32 - c));
}

static inline void kmap_md5_transform(Md5Ctx *ctx, const uint8_t *blk) {
    uint32_t m[16];
    for (int i = 0; i < 16; i++) {
        m[i] = (uint32_t)blk[i*4+0]        | ((uint32_t)blk[i*4+1] << 8) |
               ((uint32_t)blk[i*4+2] << 16) | ((uint32_t)blk[i*4+3] << 24);
    }
    uint32_t a = ctx->state[0], b = ctx->state[1],
             c = ctx->state[2], d = ctx->state[3];
    for (int i = 0; i < 64; i++) {
        uint32_t f;
        int g;
        if (i < 16)      { f = (b & c) | (~b & d);        g = i; }
        else if (i < 32) { f = (d & b) | (~d & c);        g = (5*i + 1) & 15; }
        else if (i < 48) { f = b ^ c ^ d;                 g = (3*i + 5) & 15; }
        else             { f = c ^ (b | ~d);              g = (7*i)     & 15; }
        f = f + a + KMAP_MD5_T[i] + m[g];
        a = d; d = c; c = b;
        b = b + kmap_md5_rotl(f, KMAP_MD5_S[i]);
    }
    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d;
}

static inline void md5_init(Md5Ctx *ctx) {
    ctx->state[0] = 0x67452301; ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe; ctx->state[3] = 0x10325476;
    ctx->bitlen = 0;
    ctx->buflen = 0;
}

static inline void md5_update(Md5Ctx *ctx, const uint8_t *data, size_t len) {
    ctx->bitlen += (uint64_t)len * 8;
    while (len > 0) {
        size_t space = 64 - ctx->buflen;
        size_t take  = (len < space) ? len : space;
        memcpy(ctx->buf + ctx->buflen, data, take);
        ctx->buflen += take;
        data        += take;
        len         -= take;
        if (ctx->buflen == 64) {
            kmap_md5_transform(ctx, ctx->buf);
            ctx->buflen = 0;
        }
    }
}

static inline void md5_final(Md5Ctx *ctx, uint8_t out[16]) {
    uint64_t bitlen = ctx->bitlen;
    ctx->buf[ctx->buflen++] = 0x80;
    if (ctx->buflen > 56) {
        while (ctx->buflen < 64) ctx->buf[ctx->buflen++] = 0;
        kmap_md5_transform(ctx, ctx->buf);
        ctx->buflen = 0;
    }
    while (ctx->buflen < 56) ctx->buf[ctx->buflen++] = 0;
    /* length appended little-endian (MD5), low byte first. */
    for (int i = 0; i < 8; i++) ctx->buf[ctx->buflen++] = (uint8_t)(bitlen >> (i*8));
    kmap_md5_transform(ctx, ctx->buf);
    for (int i = 0; i < 4; i++) {
        out[i*4+0] = (uint8_t)(ctx->state[i]);
        out[i*4+1] = (uint8_t)(ctx->state[i] >> 8);
        out[i*4+2] = (uint8_t)(ctx->state[i] >> 16);
        out[i*4+3] = (uint8_t)(ctx->state[i] >> 24);
    }
}

static inline std::string md5_hex(const std::string &data) {
    Md5Ctx ctx;
    uint8_t digest[16];
    md5_init(&ctx);
    md5_update(&ctx, reinterpret_cast<const uint8_t *>(data.data()), data.size());
    md5_final(&ctx, digest);
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.resize(32);
    for (int i = 0; i < 16; i++) {
        out[i*2+0] = hex[(digest[i] >> 4) & 0xF];
        out[i*2+1] = hex[digest[i] & 0xF];
    }
    return out;
}

#endif /* KMAP_MD5_H */
