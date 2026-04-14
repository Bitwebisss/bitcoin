#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that we reject low difficulty headers to prevent our block tree from filling up with useless bloat.

GENERATOR MODE
--------------
Run with --mine to mine the test blocks and write JSON to stdout:

    python3 p2p_dos_header_tree.py --mine > data/testnet3_headers.json

The generator starts the testnet3 node, mines 546 main-chain blocks and
2 fork blocks (branching from genesis) using Argon2id PoW, then prints
the resulting JSON.

After mining:
  1. Save the printed JSON to test/functional/data/testnet3_headers.json
  2. Update CHECKPOINT_HASH and FORK_TIP_HASH constants below
  3. Add the checkpoint to chainparams.cpp CTestNetParams::checkpointData
"""

# ---------------------------------------------------------------------------
# UPDATE THESE two constants after running --mine once and updating chainparams
# ---------------------------------------------------------------------------
CHECKPOINT_HEIGHT = 546
CHECKPOINT_HASH   = 'REPLACE_ME_AFTER_MINE'   # main[-1]['hash'] from JSON
FORK_TIP_HASH     = 'REPLACE_ME_AFTER_MINE'   # fork[-1]['hash'] from JSON
# ---------------------------------------------------------------------------

import json
import os
import sys
import time as _time


def _progress(msg):
    """Write directly to /dev/tty, bypassing all test framework output capture."""
    try:
        with open('/dev/tty', 'w') as tty:
            tty.write(msg + '\n')
            tty.flush()
    except OSError:
        os.write(2, (msg + '\n').encode())

from test_framework.messages import (
    CBlock,
    CBlockHeader,
    SEQUENCE_FINAL,
    uint256_from_compact,
)
from test_framework.p2p import (
    P2PInterface,
    msg_headers,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.blocktools import (
    NORMAL_GBT_REQUEST_PARAMS,
    create_coinbase,
)
from test_framework.util import assert_equal


# ---------------------------------------------------------------------------
# Helpers shared between generator and test
# ---------------------------------------------------------------------------

def _header_from_record(rec):
    """Reconstruct a CBlockHeader from a JSON record."""
    hdr = CBlockHeader()
    hdr.nVersion      = rec['version']
    hdr.hashPrevBlock = int(rec['prev_hash'], 16)
    hdr.hashMerkleRoot = int(rec['merkle_root'], 16)
    hdr.nTime         = rec['time']
    hdr.nBits         = rec['bits']
    hdr.nNonce        = rec['nonce']
    return hdr


def _meets_target(hdr):
    """Return True if hdr.argon2id satisfies hdr.nBits.

    argon2id property returns uint256_from_str(digest) which uses
    little-endian byte order, matching UintToArith256 in C++.
    uint256_from_compact returns the target in the same LE convention.
    """
    return hdr.argon2id <= uint256_from_compact(hdr.nBits)


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

def _run_generator(node, log, datafile_path):
    """Mine 546 main-chain headers + 2 fork headers, write JSON to stdout."""

    assert_equal(node.getblockcount(), 0)
    genesis_hash = node.getbestblockhash()
    genesis_hash_int = int(genesis_hash, 16)

    COINBASE_SCRIPT_PUBKEY = bytes.fromhex(
        "76a914eadbac7f36c37e39361168b7aaee3cb24a25312d88ac"
    )

    records_main = []
    records_fork = []  # initialised here so the incremental write inside the main loop can reference it

    _progress("")
    _progress("=" * 64)
    _progress(f"  GENERATOR MODE — mining {CHECKPOINT_HEIGHT} testnet3 blocks")
    _progress(f"  genesis = {genesis_hash}")
    _progress("=" * 64)

    t_start = _time.monotonic()

    for height in range(1, CHECKPOINT_HEIGHT + 1):
        t_block = _time.monotonic()

        # getblocktemplate gives us the correct nBits (LWMA-adjusted) and curtime
        tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)

        block = CBlock()
        block.nVersion      = 0x20000000
        block.hashPrevBlock = int(tmpl['previousblockhash'], 16)
        block.nTime         = tmpl['curtime']
        block.nBits         = int(tmpl['bits'], 16)

        cb = create_coinbase(
            height=height,
            script_pubkey=COINBASE_SCRIPT_PUBKEY,
            halving_period=420000,
        )
        cb.nLockTime = 0
        cb.vin[0].nSequence = SEQUENCE_FINAL
        block.vtx = [cb]
        block.hashMerkleRoot = block.calc_merkle_root()

        # Brute-force nonce until Argon2id PoW is satisfied
        found = False
        for nonce in range(0x1_0000_0000):
            block.nNonce = nonce
            if _meets_target(block):
                found = True
                break
        assert found, f"Exhausted nonce space at height {height}"

        block_hex = block.serialize(with_witness=False).hex()
        result = node.submitblock(block_hex)
        assert result is None, f"submitblock failed at height {height}: {result}"

        elapsed_block = _time.monotonic() - t_block
        elapsed_total = _time.monotonic() - t_start
        avg_per_block = elapsed_total / height
        remaining     = avg_per_block * (CHECKPOINT_HEIGHT - height)
        eta_min, eta_sec = divmod(int(remaining), 60)

        _progress(
            f"  [{height:>3}/{CHECKPOINT_HEIGHT}]  "
            f"nonce={nonce:<8}  bits={block.nBits:#010x}  "
            f"hash={block.hash_hex[:16]}...  "
            f"{elapsed_block:4.1f}s/block  ETA {eta_min}m{eta_sec:02d}s"
        )

        records_main.append({
            'height':      height,
            'version':     block.nVersion,
            'prev_hash':   f'{block.hashPrevBlock:064x}',
            'merkle_root': f'{block.hashMerkleRoot:064x}',
            'time':        block.nTime,
            'bits':        block.nBits,
            'nonce':       block.nNonce,
            'hash':        block.hash_hex,
        })

        # Write after every block so progress survives a crash
        with open(datafile_path, 'w', encoding='utf-8') as f:
            json.dump({'main': records_main, 'fork': records_fork}, f, indent=2)

    # Mine 2 fork blocks branching from genesis.
    # Genesis nBits is used (no retargeting at depth 1-2).
    genesis_block_info = node.getblock(genesis_hash)
    fork_nbits = int(genesis_block_info['bits'], 16)

    _progress("")
    _progress(f"  Mining 2 fork headers at genesis nBits={fork_nbits:#010x}")

    records_fork = []
    prev_fork_int = genesis_hash_int

    for height in range(1, 3):
        t_block = _time.monotonic()

        # Use a timestamp offset that differs from main chain to ensure a
        # different hash, while staying within the 2-hour future-time window.
        base_time = records_main[height - 1]['time']
        fork_time = base_time + 3600  # +1 h offset guarantees distinct hash

        block = CBlock()
        block.nVersion      = 0x20000000
        block.hashPrevBlock = prev_fork_int
        block.nTime         = fork_time
        block.nBits         = fork_nbits

        cb = create_coinbase(
            height=height,
            script_pubkey=COINBASE_SCRIPT_PUBKEY,
            halving_period=420000,
        )
        cb.nLockTime = 0
        cb.vin[0].nSequence = SEQUENCE_FINAL
        block.vtx = [cb]
        block.hashMerkleRoot = block.calc_merkle_root()

        found = False
        for nonce in range(0x1_0000_0000):
            block.nNonce = nonce
            if _meets_target(block):
                found = True
                break
        assert found, f"Exhausted nonce space for fork block at height {height}"

        elapsed_block = _time.monotonic() - t_block
        _progress(
            f"  fork [{height}/2]  nonce={nonce:<8}  "
            f"hash={block.hash_hex[:16]}...  {elapsed_block:.1f}s"
        )

        records_fork.append({
            'height':      height,
            'version':     block.nVersion,
            'prev_hash':   f'{block.hashPrevBlock:064x}',
            'merkle_root': f'{block.hashMerkleRoot:064x}',
            'time':        block.nTime,
            'bits':        block.nBits,
            'nonce':       block.nNonce,
            'hash':        block.hash_hex,
        })
        prev_fork_int = block.hash_int

        # Write after every block so progress survives a crash
        with open(datafile_path, 'w', encoding='utf-8') as f:
            json.dump({'main': records_main, 'fork': records_fork}, f, indent=2)

    total_min, total_sec = divmod(int(_time.monotonic() - t_start), 60)
    checkpoint_hash = records_main[-1]['hash']
    fork_tip_hash   = records_fork[-1]['hash']

    _progress("")
    _progress("=" * 64)
    _progress(f"  DONE in {total_min}m{total_sec:02d}s")
    _progress("")
    _progress("  1. JSON is on stdout — redirect it:")
    _progress("     python3 p2p_dos_header_tree.py --mine > data/testnet3_headers.json")
    _progress("")
    _progress("  2. Update constants in p2p_dos_header_tree.py:")
    _progress(f"     CHECKPOINT_HASH = '{checkpoint_hash}'")
    _progress(f"     FORK_TIP_HASH   = '{fork_tip_hash}'")
    _progress("")
    _progress("  3. Add to chainparams.cpp CTestNetParams::checkpointData:")
    _progress(f"     {{{CHECKPOINT_HEIGHT}, uint256{{\"{checkpoint_hash}\"}}}},")
    _progress("=" * 64)


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

class RejectLowDifficultyHeadersTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.chain = 'testnet3'
        self.num_nodes = 2
        self.extra_args = [["-minimumchainwork=0x0", '-prune=550']] * self.num_nodes

    def add_options(self, parser):
        parser.add_argument(
            '--mine',
            action='store_true',
            default=False,
            help='Generator mode: mine test blocks and write data/testnet3_headers.json, then exit',
        )

    def run_test(self):
        datafile_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'data', 'testnet3_headers.json',
        )

        # ----------------------------------------------------------------
        # Generator mode
        # ----------------------------------------------------------------
        if self.options.mine:
            _run_generator(self.nodes[0], self.log, datafile_path)
            return

        # ----------------------------------------------------------------
        # Normal test mode
        # ----------------------------------------------------------------
        self.log.info("Load header data from JSON")
        with open(datafile_path, encoding='utf-8') as f:
            data = json.load(f)

        headers      = [_header_from_record(r) for r in data['main']]
        headers_fork = [_header_from_record(r) for r in data['fork']]

        self.log.info("Feed all non-fork headers, including and up to the first checkpoint")
        peer_checkpoint = self.nodes[0].add_p2p_connection(P2PInterface())
        peer_checkpoint.send_and_ping(msg_headers(headers))
        assert {
            'height':    CHECKPOINT_HEIGHT,
            'hash':      CHECKPOINT_HASH,
            'branchlen': CHECKPOINT_HEIGHT,
            'status':    'headers-only',
        } in self.nodes[0].getchaintips()

        self.log.info("Feed all fork headers (fails due to checkpoint)")
        with self.nodes[0].assert_debug_log(['bad-fork-prior-to-checkpoint']):
            peer_checkpoint.send_without_ping(msg_headers(headers_fork))
            peer_checkpoint.wait_for_disconnect()

        self.log.info("Feed all fork headers (succeeds without checkpoint)")
        self.restart_node(0, extra_args=['-nocheckpoints', "-minimumchainwork=0x0", '-prune=550'])
        peer_no_checkpoint = self.nodes[0].add_p2p_connection(P2PInterface())
        peer_no_checkpoint.send_and_ping(msg_headers(headers_fork))
        assert {
            'height':    len(headers_fork),
            'hash':      FORK_TIP_HASH,
            'branchlen': len(headers_fork),
            'status':    'headers-only',
        } in self.nodes[0].getchaintips()

        peer_before_checkpoint = self.nodes[1].add_p2p_connection(P2PInterface())
        peer_before_checkpoint.send_and_ping(msg_headers(headers_fork))
        assert {
            'height':    len(headers_fork),
            'hash':      FORK_TIP_HASH,
            'branchlen': len(headers_fork),
            'status':    'headers-only',
        } in self.nodes[1].getchaintips()


if __name__ == '__main__':
    RejectLowDifficultyHeadersTest(__file__).main()
