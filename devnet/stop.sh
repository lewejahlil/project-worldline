#!/usr/bin/env bash
# SPDX-License-Identifier: MIT-0
set -euo pipefail
if [ -f /tmp/anvil.pid ]; then
  kill $(cat /tmp/anvil.pid) || true
  rm -f /tmp/anvil.pid
  echo "anvil stopped"
fi
