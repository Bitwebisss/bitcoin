// Copyright (c) 2026-present The Bitweb Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(permitted_difficulty_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// PermittedDifficultyTransition - bootstrap boundary checks
//
// No argon2id PoW, no chain building. Runtime: microseconds.
//
// Logic under test (pow.cpp):
//   if (height <= L)  →  return new_nbits == powLimit.GetCompact()
//   else              →  return true
//
// Where L = lwmaAveragingWindow + 59424.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(bootstrap_main)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const Consensus::Params& p = chainParams->GetConsensus();

    const int64_t  N            = p.lwmaAveragingWindow;           // 576
    const int64_t  L            = N + 59424;                        // 60000
    const uint32_t genesis_bits = UintToArith256(p.powLimit).GetCompact();

    // Bootstrap interior: only genesis_bits accepted
    BOOST_CHECK( PermittedDifficultyTransition(p,   1, 0, genesis_bits));
    BOOST_CHECK( PermittedDifficultyTransition(p, 100, 0, genesis_bits));
    BOOST_CHECK( PermittedDifficultyTransition(p,   L, 0, genesis_bits));  // last bootstrap block

    // Bootstrap interior: any other nBits rejected
    BOOST_CHECK(!PermittedDifficultyTransition(p,   1, 0, genesis_bits - 1));
    BOOST_CHECK(!PermittedDifficultyTransition(p,   1, 0, genesis_bits + 1));
    BOOST_CHECK(!PermittedDifficultyTransition(p,   L, 0, 0x1d00ffffU));
    BOOST_CHECK(!PermittedDifficultyTransition(p,   L, 0, 0x00000000U));

    // Boundary: L+1 is first block above bootstrap - any nBits passes
    BOOST_CHECK( PermittedDifficultyTransition(p, L + 1, 0, genesis_bits));
    BOOST_CHECK( PermittedDifficultyTransition(p, L + 1, 0, genesis_bits - 1));
    BOOST_CHECK( PermittedDifficultyTransition(p, L + 1, 0, 0xdeadbeefU));
    BOOST_CHECK( PermittedDifficultyTransition(p, L + 1, 0, 0x00000000U));

    // Well above bootstrap
    BOOST_CHECK( PermittedDifficultyTransition(p, 100000, 0, 0x1a2b3c4dU));
    BOOST_CHECK( PermittedDifficultyTransition(p, 100000, 0, 0x00000000U));
}

BOOST_AUTO_TEST_CASE(bootstrap_testnet4)
{
    // TESTNET4 uses N=288, so L=59712 - different from MAIN's L=60000
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::TESTNET4);
    const Consensus::Params& p = chainParams->GetConsensus();

    const int64_t  N            = p.lwmaAveragingWindow;           // 288
    const int64_t  L            = N + 59424;                        // 59712
    const uint32_t genesis_bits = UintToArith256(p.powLimit).GetCompact();

    // Confirm L differs from MAIN to catch copy-paste errors
    const int64_t L_main = CreateChainParams(*m_node.args, ChainType::MAIN)
                               ->GetConsensus().lwmaAveragingWindow + 59424;
    BOOST_CHECK(L != L_main);

    BOOST_CHECK( PermittedDifficultyTransition(p,     1, 0, genesis_bits));
    BOOST_CHECK( PermittedDifficultyTransition(p,     L, 0, genesis_bits));
    BOOST_CHECK(!PermittedDifficultyTransition(p,     L, 0, genesis_bits - 1));
    BOOST_CHECK( PermittedDifficultyTransition(p, L + 1, 0, genesis_bits - 1));
}

BOOST_AUTO_TEST_CASE(bootstrap_signet_different_powlimit)
{
    // SIGNET shares N=576 (L=60000) with MAIN but has a different powLimit.
    // This verifies that the two networks reject each other's genesis_bits
    // inside the bootstrap zone.
    const auto signetParams = CreateChainParams(*m_node.args, ChainType::SIGNET);
    const auto mainParams   = CreateChainParams(*m_node.args, ChainType::MAIN);

    const Consensus::Params& ps = signetParams->GetConsensus();
    const int64_t  L            = ps.lwmaAveragingWindow + 59424;   // 60000

    const uint32_t signet_bits = UintToArith256(ps.powLimit).GetCompact();
    const uint32_t main_bits   = UintToArith256(mainParams->GetConsensus().powLimit).GetCompact();

    BOOST_CHECK(signet_bits != main_bits);

    // Signet bootstrap: signet bits accepted, main bits rejected
    BOOST_CHECK( PermittedDifficultyTransition(ps,     1, 0, signet_bits));
    BOOST_CHECK(!PermittedDifficultyTransition(ps,     1, 0, main_bits));

    // Above bootstrap: both accepted
    BOOST_CHECK( PermittedDifficultyTransition(ps, L + 1, 0, signet_bits));
    BOOST_CHECK( PermittedDifficultyTransition(ps, L + 1, 0, main_bits));
}

BOOST_AUTO_TEST_CASE(bootstrap_regtest)
{
    // REGTEST: fPowNoRetargeting=true, N=144, L=59568.
    // nBits never changes - always powLimit.GetCompact().
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::REGTEST);
    const Consensus::Params& p = chainParams->GetConsensus();

    BOOST_CHECK(p.fPowNoRetargeting);

    const int64_t  N            = p.lwmaAveragingWindow;           // 144
    const int64_t  L            = N + 59424;                        // 59568
    const uint32_t genesis_bits = UintToArith256(p.powLimit).GetCompact();

    BOOST_CHECK( PermittedDifficultyTransition(p,     1, 0, genesis_bits));
    BOOST_CHECK(!PermittedDifficultyTransition(p,     1, 0, genesis_bits - 1));
    BOOST_CHECK( PermittedDifficultyTransition(p, L + 1, 0, genesis_bits - 1));
}

BOOST_AUTO_TEST_SUITE_END()
