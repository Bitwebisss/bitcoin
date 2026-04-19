// Copyright (c) 2021-2026 The Bitweb Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <crypto/argon2d/argon2.h>
#include <tinyformat.h>
#include <uint256.h>

#include <array>
#include <cassert>
#include <cstdint>

/* Consensus-critical parameters — must match block.cpp exactly */
static constexpr uint32_t ARGON2ID_T       = 3;
static constexpr uint32_t ARGON2ID_M       = 1024;
static constexpr uint32_t ARGON2ID_P       = 1;
static constexpr size_t   ARGON2ID_HASHLEN = 32;
static constexpr size_t   HEADER_LEN       = 80;

/*
 * Per-ISA fill_segment implementations — forward declarations.
 * fill_segment_sse2  : opt.cpp      (x86 baseline, SSE2/__m128i)
 * fill_segment_avx2  : opt_avx2.cpp
 * fill_segment_avx512: opt_avx512.cpp
 * All are non-static, so extern linkage works.
 */
#if !defined(DISABLE_OPTIMIZED_ARGON2) && \
    (defined(__x86_64__) || defined(__amd64__) || defined(__i386__))

/* argon2_fill_segment — the global function pointer defined in opt.cpp */
extern void (*argon2_fill_segment)(const argon2_instance_t *, argon2_position_t);

extern void fill_segment_sse2(const argon2_instance_t *, argon2_position_t);

#if defined(ENABLE_ARGON2_AVX2)
extern void fill_segment_avx2(const argon2_instance_t *, argon2_position_t);
#endif

#if defined(ENABLE_ARGON2_AVX512)
extern void fill_segment_avx512(const argon2_instance_t *, argon2_position_t);
#endif

#endif /* !DISABLE_OPTIMIZED_ARGON2 && x86 */

/* -----------------------------------------------------------------------
 * Run one Argon2id PoW hash of a synthetic 80-byte block header.
 * The unit is "hash" rather than "byte" — unlike SHA256, Argon2 is
 * memory-hard, so throughput in bytes/s is not a meaningful metric.
 * ----------------------------------------------------------------------- */
static void RunArgon2idHash(benchmark::Bench& bench)
{
    std::array<uint8_t, HEADER_LEN> hdr{};
    hdr[0] = 0x04; /* non-zero version field */

    bench.unit("hash").batch(1).run([&] {
        uint256 out;
        const int rc = argon2id_hash_raw(
            ARGON2ID_T, ARGON2ID_M, ARGON2ID_P,
            hdr.data(), hdr.size(),
            hdr.data(), hdr.size(),
            out.begin(), ARGON2ID_HASHLEN
        );
        assert(rc == ARGON2_OK);
    });
}

/* -----------------------------------------------------------------------
 * One benchmark variant per available ISA, mirroring the pattern used for
 * SHA256_STANDARD / SHA256_SSE4 / SHA256_AVX2 in crypto_hash.cpp:
 *   1. Set the desired implementation (or restore autodetect)
 *   2. Run the measurement
 *   3. Restore the autodetected implementation
 * ----------------------------------------------------------------------- */

static void Argon2id_AutoDetect(benchmark::Bench& bench)
{
    bench.name(strprintf("%s using the '%s' Argon2id implementation",
                         __func__, Argon2AutoDetect()));
    RunArgon2idHash(bench);
    Argon2AutoDetect(); /* restore */
}

#if !defined(DISABLE_OPTIMIZED_ARGON2) && \
    (defined(__x86_64__) || defined(__amd64__) || defined(__i386__))

static void Argon2id_SSE2(benchmark::Bench& bench)
{
    bench.name(strprintf("%s using the 'sse2' Argon2id implementation", __func__));
    argon2_fill_segment = fill_segment_sse2;
    RunArgon2idHash(bench);
    Argon2AutoDetect();
}

#if defined(ENABLE_ARGON2_AVX2)
static void Argon2id_AVX2(benchmark::Bench& bench)
{
    bench.name(strprintf("%s using the 'avx2' Argon2id implementation", __func__));
    argon2_fill_segment = fill_segment_avx2;
    RunArgon2idHash(bench);
    Argon2AutoDetect();
}
#endif

#if defined(ENABLE_ARGON2_AVX512)
static void Argon2id_AVX512(benchmark::Bench& bench)
{
    bench.name(strprintf("%s using the 'avx512' Argon2id implementation", __func__));
    argon2_fill_segment = fill_segment_avx512;
    RunArgon2idHash(bench);
    Argon2AutoDetect();
}
#endif

#endif /* !DISABLE_OPTIMIZED_ARGON2 && x86 */

BENCHMARK(Argon2id_AutoDetect, benchmark::PriorityLevel::HIGH);

#if !defined(DISABLE_OPTIMIZED_ARGON2) && \
    (defined(__x86_64__) || defined(__amd64__) || defined(__i386__))
BENCHMARK(Argon2id_SSE2, benchmark::PriorityLevel::HIGH);
#if defined(ENABLE_ARGON2_AVX2)
BENCHMARK(Argon2id_AVX2, benchmark::PriorityLevel::HIGH);
#endif
#if defined(ENABLE_ARGON2_AVX512)
BENCHMARK(Argon2id_AVX512, benchmark::PriorityLevel::HIGH);
#endif
#endif
