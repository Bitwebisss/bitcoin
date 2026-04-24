#!/usr/bin/env python3
# Copyright (c) 2018-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test migratewallet RPC using a pre-built legacy wallet dataset (v0.24).

The wallet file 'data/legacy_wallet_v24.dat' must be present before running
this test.  It was created on a v0.24 node with:

    bitcoin-cli createwallet "test_legacy" false false "" false false
    bitcoin-cli -rpcwallet=test_legacy getnewaddress

The file is committed to the repository as a static fixture so that the full
backwards-compatibility test suite (which requires live old-version binaries)
is not needed to exercise the migratewallet RPC path.
"""

import os
import shutil

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

# Directory that contains this test file.
# Mirrors the convention used in rpc_getblockstats.py and other data-driven
# tests: fixture files live in   test/functional/data/
TESTSDIR = os.path.dirname(os.path.realpath(__file__))


class WalletMigration024Test(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        # No default wallet — we manage wallets manually.
        self.wallet_names = []

    def skip_test_if_missing_module(self):
        # migratewallet reads the legacy BDB file via the BERKELEY_RO driver
        # and writes the result as SQLite, so both must be compiled in.
        self.skip_if_no_sqlite()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def data_file(self, filename):
        """Return the absolute path to a fixture file inside data/."""
        return os.path.join(TESTSDIR, "data", filename)

    def install_wallet(self, wallet_name, src_filename):
        """
        Copy a wallet.dat fixture into the node's wallets directory.

        Bitcoin Core expects the layout:
            <wallets_path>/<wallet_name>/wallet.dat
        """
        dst_dir = self.nodes[0].wallets_path / wallet_name
        dst_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(self.data_file(src_filename), dst_dir / "wallet.dat")

    # ------------------------------------------------------------------
    # Individual test cases
    # ------------------------------------------------------------------

    def test_basic_migration(self):
        """
        Happy path: migrate a plain (unencrypted) v0.24 legacy wallet.

        Expected behaviour
        ------------------
        * migratewallet succeeds and returns the standard result object.
        * A backup file is created on disk.
        * The resulting wallet is descriptor-based.
        * The wallet is functional (getnewaddress works).
        """
        self.log.info("Test basic migration of an unencrypted v0.24 legacy wallet")

        node = self.nodes[0]
        wallet_name = "legacy_v24_basic"

        self.install_wallet(wallet_name, "legacy_wallet_v24.dat")

        result = node.migratewallet(wallet_name)

        # --- result structure ---
        assert_equal(result["wallet_name"], wallet_name)
        assert "backup_path" in result, "migratewallet must return backup_path"
        assert os.path.exists(result["backup_path"]), (
            f"Backup file not found: {result['backup_path']}"
        )
        self.log.info(f"  backup created: {result['backup_path']}")

        # watchonly / solvables wallets are only created when the legacy wallet
        # contains scripts that need them; a plain wallet should not produce them.
        assert "watchonly_name" not in result, (
            "Plain legacy wallet should not produce a watchonly wallet"
        )
        assert "solvables_name" not in result, (
            "Plain legacy wallet should not produce a solvables wallet"
        )

        # --- migrated wallet is descriptor-based ---
        wallet_rpc = node.get_wallet_rpc(wallet_name)
        info = wallet_rpc.getwalletinfo()
        assert info["descriptors"], "Migrated wallet must use descriptors"

        # --- migrated wallet is functional ---
        addr = wallet_rpc.getnewaddress()
        assert addr, "getnewaddress must return a non-empty address"
        self.log.info(f"  new address from migrated wallet: {addr}")

        wallet_rpc.unloadwallet()

    def test_double_migration_fails(self):
        """
        Migrating a wallet that is already a descriptor wallet must fail
        with a clear error message, not silently succeed or crash.
        """
        self.log.info("Test that migrating a descriptor wallet raises an error")

        node = self.nodes[0]
        wallet_name = "descriptor_wallet"

        # createwallet produces a descriptor wallet by default on current nodes.
        node.createwallet(wallet_name=wallet_name)

        assert_raises_rpc_error(
            -4,
            "Error: This wallet is already a descriptor wallet",
            node.migratewallet,
            wallet_name,
        )

        node.unloadwallet(wallet_name)

    def test_migrate_nonexistent_wallet_fails(self):
        """
        Trying to migrate a wallet that does not exist on disk must return
        a proper RPC error, not an unhandled exception.
        """
        self.log.info("Test that migrating a non-existent wallet raises an error")

        assert_raises_rpc_error(
            -18,
            "Wallet not found",
            self.nodes[0].migratewallet,
            "wallet_that_does_not_exist_xyz",
        )

    def test_migration_result_fields(self):
        """
        Verify every documented field of the migratewallet result object:
            wallet_name   (always present)
            backup_path   (always present)
            watchonly_name  (optional)
            solvables_name  (optional)
        """
        self.log.info("Test migratewallet result object field coverage")

        node = self.nodes[0]
        wallet_name = "legacy_v24_fields"

        self.install_wallet(wallet_name, "legacy_wallet_v24.dat")

        result = node.migratewallet(wallet_name)

        # These two fields must always be present.
        assert "wallet_name" in result
        assert "backup_path" in result

        # wallet_name must match the argument we passed.
        assert_equal(result["wallet_name"], wallet_name)

        node.get_wallet_rpc(wallet_name).unloadwallet()

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run_test(self):
        self.test_basic_migration()
        self.test_double_migration_fails()
        self.test_migrate_nonexistent_wallet_fails()
        self.test_migration_result_fields()


if __name__ == "__main__":
    WalletMigration024Test(__file__).main()
