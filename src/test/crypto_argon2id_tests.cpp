// Copyright (c) 2026-present The Bitweb Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <crypto/argon2d/argon2.h>
#include <test/data/argon2id_vectors.json.h>
#include <test/util/json.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <iostream>
#include <vector>

BOOST_AUTO_TEST_SUITE(crypto_argon2id_tests)

BOOST_AUTO_TEST_CASE(argon2id_json_vectors_all_isa)
{
    UniValue tests = read_json(json_tests::argon2id_vectors);
    BOOST_REQUIRE(!tests.isNull());
    BOOST_REQUIRE(tests.isArray());
    BOOST_REQUIRE_GT(tests.size(), 0);

    constexpr uint32_t t_cost = 3;
    constexpr uint32_t m_cost = 1024;
    constexpr uint32_t parallelism = 1;
    constexpr size_t   hash_len = 32;

    size_t failed_count = 0;

    for (size_t idx = 0; idx < tests.size(); ++idx) {
        const UniValue& vec = tests[idx];
        std::string data_hex = vec["data"].get_str();
        std::string salt_hex = vec["salt"].get_str();
        std::string expected_hex = vec["expected_hash"].get_str();

        std::vector<uint8_t> data = ParseHex(data_hex);
        std::vector<uint8_t> salt = ParseHex(salt_hex);
        std::vector<uint8_t> expected = ParseHex(expected_hex);
        BOOST_REQUIRE(!data.empty());
        BOOST_REQUIRE(!salt.empty());
        BOOST_REQUIRE(expected.size() == hash_len);

        auto check_isa = [&](argon2_implementation::UseImplementation impl, const std::string& name) {
            Argon2AutoDetect(impl);
            uint256 hash;
            int rc = argon2id_hash_raw(t_cost, m_cost, parallelism,
                                       data.data(), data.size(),
                                       salt.data(), salt.size(),
                                       hash.begin(), hash_len);
            BOOST_REQUIRE_MESSAGE(rc == ARGON2_OK, name << " failed at vector " << idx);
            std::vector<uint8_t> actual(hash.begin(), hash.end());
            if (!std::equal(actual.begin(), actual.end(), expected.begin())) {
                ++failed_count;
                std::cerr << "Vector " << idx << " " << name << " mismatch:\n"
                          << "  data: " << data_hex << "\n"
                          << "  salt: " << salt_hex << "\n"
                          << "  expected: " << expected_hex << "\n"
                          << "  actual:   " << HexStr(actual) << "\n";
            }
        };

        check_isa(argon2_implementation::STANDARD, "STANDARD");
        check_isa(argon2_implementation::USE_SSE2,   "SSE2");
        check_isa(argon2_implementation::USE_SSSE3,  "SSSE3");
        check_isa(argon2_implementation::USE_AVX2,   "AVX2");
        check_isa(argon2_implementation::USE_AVX512, "AVX512");
    }

    Argon2AutoDetect();

    BOOST_REQUIRE_EQUAL(failed_count, 0);
}

BOOST_AUTO_TEST_SUITE_END()
