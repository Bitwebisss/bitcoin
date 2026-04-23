#!/usr/bin/env bash
#
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export CONTAINER_NAME="ci_mac_native_bench"
export PIP_PACKAGES="--break-system-packages zmq argon2-cffi"
export GOAL="all"
export CMAKE_GENERATOR="Ninja"
export BITCOIN_CONFIG="-DBUILD_GUI=OFF -DWITH_ZMQ=ON -DREDUCE_EXPORTS=ON"
export CI_OS_NAME="macos"
export NO_DEPENDS=1
export OSX_SDK=""
export RUN_UNIT_TESTS=false
export RUN_FUNCTIONAL_TESTS=false
export RUN_BENCHMARK=true
