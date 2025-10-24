#!/usr/bin/env bash
# SPDX-License-Identifier: MIT-0
set -euo pipefail
anvil --silent --chain-id 31337 --block-time 1 > /tmp/anvil.out 2>&1 &
echo $! > /tmp/anvil.pid
echo "anvil started (pid $(cat /tmp/anvil.pid))"
sleep 1
