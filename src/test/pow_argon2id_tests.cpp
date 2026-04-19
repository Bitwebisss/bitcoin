// Copyright (c) 2026-present The Bitweb Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <crypto/argon2d/argon2.h>
#include <primitives/block.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>

BOOST_AUTO_TEST_SUITE(pow_argon2id_tests)

// ---------------------------------------------------------------------------
// Regtest genesis block header (80 bytes, little-endian serialization).
// Used as a shared fixture across all test cases.
// ---------------------------------------------------------------------------
static CBlockHeader GenesisHeader()
{
    // Canonical 80-byte serialization of the regtest genesis block header.
    // Produced by: CDataStream ss; ss << genesis_block.GetBlockHeader();
    static const std::string HEX_HEADER =
        "010000000000000000000000000000000000000000000000000000000000000000000000"
        "f6080cb097396d71619536977a791fe52fcb8b6cbd72c4b593187c2eb4e9de1"
        "4784a0469ffff7f201b17993b";

    CBlockHeader hdr;
    DataStream ss{ParseHex(HEX_HEADER)};
    ss >> hdr;
    return hdr;
}

// ---------------------------------------------------------------------------
// Test 1 — Known-vector: the genesis header must hash to the expected digest.
//
// Expected value verified against a live bitweb node:
//   LogInfo("genesis hash (argon2id): %s", genesis.GetArgon2idPoWHash().ToString());
//
// NOTE: uint256::ToString() displays bytes in reversed order (big-endian
// convention used throughout Bitcoin for block/tx hashes).  The value below
// is what the node logs; it is NOT the raw byte sequence returned by
// argon2id_hash_raw().
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(argon2id_genesis_known_vector)
{
    const CBlockHeader hdr = GenesisHeader();

    const uint256 pow_hash = hdr.GetArgon2idPoWHash();

    BOOST_CHECK_EQUAL(
        pow_hash.ToString(),
        "33127ec18ae35313ad6f966ea03fcc03b220da7c9c5bfa5fab210cd04743868d");
}

// ---------------------------------------------------------------------------
// Test 2 — Cross-ISA consistency: SSE2 / AVX2 / AVX512 must all produce the
// same digest for the same input.  A divergence here is a consensus split.
//
// On non-x86 or when an ISA is unavailable, Argon2AutoDetectImpl() ignores
// the flag and returns "reference", so all three variants hash identically
// via the portable path — the test still passes without any #ifdef.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(argon2id_cross_isa_consistency)
{
    const CBlockHeader hdr = GenesisHeader();

    // Baseline: SSE2 on x86, reference on non-x86.
    Argon2AutoDetect(argon2_implementation::STANDARD);
    const uint256 hash_std = hdr.GetArgon2idPoWHash();

    // AVX2 path (silently falls back to SSE2 if unavailable).
    Argon2AutoDetect(argon2_implementation::USE_AVX2);
    const uint256 hash_avx2 = hdr.GetArgon2idPoWHash();
    BOOST_CHECK_EQUAL(hash_std, hash_avx2);

    // AVX-512 path (silently falls back to SSE2 if unavailable).
    Argon2AutoDetect(argon2_implementation::USE_AVX512);
    const uint256 hash_avx512 = hdr.GetArgon2idPoWHash();
    BOOST_CHECK_EQUAL(hash_std, hash_avx512);

    // Restore the best available implementation for subsequent tests.
    Argon2AutoDetect();
}

// ---------------------------------------------------------------------------
// Test 3 — Determinism: identical header serializations must always produce
// the same digest within the same process (no hidden mutable state leakage).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(argon2id_determinism)
{
    const CBlockHeader hdr = GenesisHeader();

    const uint256 h1 = hdr.GetArgon2idPoWHash();
    const uint256 h2 = hdr.GetArgon2idPoWHash();
    const uint256 h3 = hdr.GetArgon2idPoWHash();

    BOOST_CHECK_EQUAL(h1, h2);
    BOOST_CHECK_EQUAL(h1, h3);
}

// ---------------------------------------------------------------------------
// Test 4 — Sensitivity: a single-bit change in the header must change the
// digest (Argon2id is a cryptographic hash — avalanche property).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(argon2id_input_sensitivity)
{
    CBlockHeader hdr = GenesisHeader();
    const uint256 hash_orig = hdr.GetArgon2idPoWHash();

    // Flip one bit in nNonce.
    hdr.nNonce ^= 1;
    const uint256 hash_mod = hdr.GetArgon2idPoWHash();

    BOOST_CHECK(hash_orig != hash_mod);
}

BOOST_AUTO_TEST_SUITE_END()
