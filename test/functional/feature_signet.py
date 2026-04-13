#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test basic signet functionality"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

SIGNET_DEFAULT_CHALLENGE = '512103206dbfb2c1e729d2ff82126b37e3f965ff580969ee3b681cb6fff152a2c58aa551ae'

signet_blocks = [
    '00000020761478bb83bc9d332b9c9a441bef9a1322dea9def22bbf669dcd74e62e790dce534c76b9c6e85049cbe489a49ec13ba94b1da86a02c48300740678dd993754ab43cadc69e07a371f2e03000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025100feffffff0200f2052a010000001600140a8ce1dbeecdeb95a30277ce07139e0fd923d3fb0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402207dbade3d0e05f56eb44ef79c5d914f863aa6ce1d22585f6192a2a949c80960c802207a183fe2e3379f2c5d7404646007117aaadba29ae264cb4f8899b1b1c6d692b001000120000000000000000000000000000000000000000000000000000000000000000000000000',
    '00000020e0534d9fe7bed49c0c37caf9f235eea657d4758735e41ef152fdf095e2788b37e53caec777a743d32a8cdfd2dcca7c7016533351fe74bc2cb34007660a0028fe8ecadc69e07a371fa800000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025200feffffff0200f2052a010000001600140a8ce1dbeecdeb95a30277ce07139e0fd923d3fb0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402207b9de84b1d6fe82bd171cd700902829df33c4dee53d124faa00f4d9748876c4b02203d8f796e77a4c6d1eb6278188c48d909a68604c089f880795604d5647f092d6a01000120000000000000000000000000000000000000000000000000000000000000000001000000',
    '00000020bd7b6b7caaf202094ee2f681873af0c7eb3efaa18326fee83be7f60bfd22f107e6563bd966b59e492392ada8719f0be2e001ba315902d5c67b87741e2b8bbc48d9cadc69e07a371fc501000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025300feffffff0200f2052a010000001600140a8ce1dbeecdeb95a30277ce07139e0fd923d3fb0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa249004730440220660ffa81ab2785d8da68599d67152313a693bde1407e7c78168c66d96e5df0440220165a6e7a3e35e1b27e51b1c0291b68e3b09ce385a2a2182e227508243f34d98d01000120000000000000000000000000000000000000000000000000000000000000000002000000',
    '00000020c97393404faa5056daef168dfe00d27fcc2aa57992d0d1965ec70986f31bd59f72e5d3c6005686e56380fe40b968b2900dab47fd3a629b7abc4b2a899b49009924cbdc69e07a371f640a000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025400feffffff0200f2052a010000001600140a8ce1dbeecdeb95a30277ce07139e0fd923d3fb0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa24900473044022028be2156bbcfa28cbfc782e725ad028c21bdaae36cc62791819183bc1bf6c84002205052e5fde86ab4a49b586f8937bada29a13d44b1818ae30d03ddc301d3e4c3e901000120000000000000000000000000000000000000000000000000000000000000000003000000',
    '000000206ac68a0842c54f09364839c8bd43cb771e26b2cd817d766a2e6049b57c4e567ddd4f381d9a6eb4a09cc8e56d0c5d645940dcb43965c42d93745bec7ec59df7d36fcbdc69e07a371fd902000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025500feffffff0200f2052a010000001600140a8ce1dbeecdeb95a30277ce07139e0fd923d3fb0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402205f1fbef23369a9af18033ca9131fe326b8e2f28902bd0465a8223c93ca39d9e902200682b7c618df200fc4b3f9c0921addafc76d2a7a7ffa8eaf3379403c66b1624901000120000000000000000000000000000000000000000000000000000000000000000004000000',
    '0000002031e86086edac87d87e02a74c6dd591823dc38286364ff22d0e8b01b7fc5ba56f755b1626164a68c5b7f32ffaf135ffac47c6de68676aada5b3cd66292400f9c6bacbdc69e07a371fdd03000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025600feffffff0200f2052a010000001600140a8ce1dbeecdeb95a30277ce07139e0fd923d3fb0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa24900473044022019e964b6dd96a7c752649194349df77bc19f01a30ed55125470eb594e9caa3ea0220254a3db8aa91a7f2e37c3ec2cf6225017f00064da4694058e2e52b286f452bf101000120000000000000000000000000000000000000000000000000000000000000000005000000',
    '00000020d151d11f625e2f2511a95923e5fce574097d2c7454f82a66db9af89da7fea34e52dea07dac286f4dddb4df3f915438ad33e65cb4271f4995617d22949299242f05ccdc69e07a371fb203000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025700feffffff0200f2052a010000001600140a8ce1dbeecdeb95a30277ce07139e0fd923d3fb0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402207b672381e719e36420d30dc04af682b3f4f8b62f32c98267fe1612a048a95cf0022026117b78284c077e9c7ebd14a2a7091e2574744f372f81c5d41fef2542019ae401000120000000000000000000000000000000000000000000000000000000000000000006000000',
    '00000020f58d636a1ff66e165fbd9bde1cf224f234ad8f5315690c3aefb2c666186296549ab9bae000292f81000d032fc795951876554ac1b2d0e9a512c50d506fb8d2f350ccdc69e07a371fab01000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025800feffffff0200f2052a010000001600140a8ce1dbeecdeb95a30277ce07139e0fd923d3fb0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402203f949ef80b1f620c931864356059509b3d56066920cb627f7d00669344573163022076f17b3013624e265f28f90ed26aeea526e10ff406c5b293533a8decf498251b01000120000000000000000000000000000000000000000000000000000000000000000007000000',
    '00000020da385daba1a40cdaa4746940151825b00f6ce9befc61ef0e3bf27449ccab0dbbc23b36c1b552f4ab60e937a317c2dfc1429f765772bbc58e8f45fe069f29baaa9bccdc69e07a371fd201000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025900feffffff0200f2052a010000001600140a8ce1dbeecdeb95a30277ce07139e0fd923d3fb0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402201486744317f6840fb71f8d27f5e1396dc44e3f3e4991788976c480aaddbb2e0902200d41caebdcf4e3fd9ea594bad1e774674dd66aadd9f319358f045a3a391bf4b301000120000000000000000000000000000000000000000000000000000000000000000008000000',
    '00000020615163348ead4d599ba6ad1c8c37cb4ac2f2cdcfff4f4f350bba5c009a7cbb45e42aab2dcb96517617fca7f1734339e42bebb8e667669da3b3a598ecb8f67740e6ccdc69e07a371f6f00000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025a00feffffff0200f2052a010000001600140a8ce1dbeecdeb95a30277ce07139e0fd923d3fb0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402201e7b1614d457f541c80fedef17d1e8e25d606bccba7865c27f284b24538c9de90220742a2d620dcfcf2594d266280f28c05b06cbd892a6510c3d8de5d66ada2a52bc01000120000000000000000000000000000000000000000000000000000000000000000009000000',
]

class SignetParams:
    def __init__(self, challenge=None):
        # Prune to prevent disk space warning on CI systems with limited space,
        # when using networks other than regtest.
        if challenge is None:
            self.challenge = SIGNET_DEFAULT_CHALLENGE
            self.shared_args = ["-prune=550"]
        else:
            self.challenge = challenge
            self.shared_args = ["-prune=550", f"-signetchallenge={challenge}"]

class SignetBasicTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "signet"
        self.num_nodes = 6
        self.setup_clean_chain = True
        self.signets = [
            SignetParams(challenge='51'), # OP_TRUE
            SignetParams(), # default challenge
            # default challenge as a 2-of-2, which means it should fail
            SignetParams(challenge='522103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae')
        ]

        self.extra_args = [
            self.signets[0].shared_args, self.signets[0].shared_args,
            self.signets[1].shared_args, self.signets[1].shared_args,
            self.signets[2].shared_args, self.signets[2].shared_args,
        ]

    def setup_network(self):
        self.setup_nodes()

        # Setup the three signets, which are incompatible with each other
        self.connect_nodes(0, 1)
        self.connect_nodes(2, 3)
        self.connect_nodes(4, 5)

    def run_test(self):
        self.log.info("basic tests using OP_TRUE challenge")

        self.log.info('getblockchaininfo')
        def check_getblockchaininfo(node_idx, signet_idx):
            blockchain_info = self.nodes[node_idx].getblockchaininfo()
            assert_equal(blockchain_info['chain'], 'signet')
            assert_equal(blockchain_info['signet_challenge'], self.signets[signet_idx].challenge)
        check_getblockchaininfo(node_idx=1, signet_idx=0)
        check_getblockchaininfo(node_idx=2, signet_idx=1)
        check_getblockchaininfo(node_idx=5, signet_idx=2)

        self.log.info('getmininginfo')
        def check_getmininginfo(node_idx, signet_idx):
            mining_info = self.nodes[node_idx].getmininginfo()
            assert_equal(mining_info['blocks'], 0)
            assert_equal(mining_info['chain'], 'signet')
            assert 'currentblocktx' not in mining_info
            assert 'currentblockweight' not in mining_info
            assert_equal(mining_info['networkhashps'], Decimal('0'))
            assert_equal(mining_info['pooledtx'], 0)
            assert_equal(mining_info['signet_challenge'], self.signets[signet_idx].challenge)
        check_getmininginfo(node_idx=0, signet_idx=0)
        check_getmininginfo(node_idx=3, signet_idx=1)
        check_getmininginfo(node_idx=4, signet_idx=2)

        self.generate(self.nodes[0], 1, sync_fun=self.no_op)

        self.log.info("pregenerated signet blocks check")

        height = 0
        for block in signet_blocks:
            assert_equal(self.nodes[2].submitblock(block), None)
            height += 1
            assert_equal(self.nodes[2].getblockcount(), height)

        self.log.info("pregenerated signet blocks check (incompatible solution)")

        assert_equal(self.nodes[4].submitblock(signet_blocks[0]), 'bad-signet-blksig')

        self.log.info("test that signet logs the network magic on node start")
        with self.nodes[0].assert_debug_log(["Signet derived magic (message start)"]):
            self.restart_node(0)
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(extra_args=["-signetchallenge=abc"], expected_msg="Error: -signetchallenge must be hex, not 'abc'.")
        self.nodes[0].assert_start_raises_init_error(extra_args=["-signetchallenge=abc"] * 2, expected_msg="Error: -signetchallenge cannot be multiple values.")


if __name__ == '__main__':
    SignetBasicTest(__file__).main()
