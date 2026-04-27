#!/usr/bin/env bash
set -euo pipefail

for ns in ${NS_LAN10:-xdp-lan10} ${NS_LAN20:-xdp-lan20} ${NS_RTR:-xdp-rtr} ${NS_SW:-xdp-sw} ${NS_INET:-xdp-inet}; do
  ip netns del "$ns" 2>/dev/null || true
done
for dev in v10a v10b v20a v20b vwana vwanb vina vinb __vetha __vethb; do
  ip link del "$dev" 2>/dev/null || true
done
