#!/usr/bin/env bash
set -euo pipefail
set -x

NS_LAN10=${NS_LAN10:-xdp-lan10}
NS_LAN20=${NS_LAN20:-xdp-lan20}
NS_RTR=${NS_RTR:-xdp-rtr}
NS_SW=${NS_SW:-xdp-sw}
NS_INET=${NS_INET:-xdp-inet}

cleanup() {
  for ns in "$NS_LAN10" "$NS_LAN20" "$NS_RTR" "$NS_SW" "$NS_INET"; do
    ip netns del "$ns" 2>/dev/null || true
  done
  for dev in v10a v10b v20a v20b vwana vwanb vina vinb __vetha __vethb; do
    ip link del "$dev" 2>/dev/null || true
  done
}

disable_basic_offloads() {
  local ns=$1 dev=$2
  ip netns exec "$ns" ethtool -K "$dev" gro off 2>/dev/null || true
  ip netns exec "$ns" ethtool -K "$dev" gso off 2>/dev/null || true
  ip netns exec "$ns" ethtool -K "$dev" tso off 2>/dev/null || true
  ip netns exec "$ns" ethtool -K "$dev" sg off  2>/dev/null || true
}

if [[ ${EUID} -ne 0 ]]; then
  echo "must run as root" >&2
  exit 1
fi

cleanup
if ! ip link add __vetha type veth peer name __vethb 2>/dev/null; then
  modprobe veth 2>/dev/null || true
  ip link add __vetha type veth peer name __vethb
fi
ip link del __vetha
modprobe ip_gre 2>/dev/null || true

ip netns add "$NS_LAN10"
ip netns add "$NS_LAN20"
ip netns add "$NS_RTR"
ip netns add "$NS_SW"
ip netns add "$NS_INET"

ip link add v10a type veth peer name v10b
ip link add v20a type veth peer name v20b
ip link add vwana type veth peer name vwanb
ip link add vina type veth peer name vinb

ip link set v10a netns "$NS_LAN10"
ip link set v10b netns "$NS_RTR"
ip link set v20a netns "$NS_LAN20"
ip link set v20b netns "$NS_RTR"
ip link set vwana netns "$NS_RTR"
ip link set vwanb netns "$NS_SW"
ip link set vina netns "$NS_SW"
ip link set vinb netns "$NS_INET"

ip -n "$NS_LAN10" link set v10a name lan0
ip -n "$NS_RTR"   link set v10b name lan10
ip -n "$NS_LAN20" link set v20a name lan0
ip -n "$NS_RTR"   link set v20b name lan20
ip -n "$NS_RTR"   link set vwana name wan0
ip -n "$NS_SW"    link set vwanb name wan0
ip -n "$NS_SW"    link set vina name lan0
ip -n "$NS_INET"  link set vinb name lan0

for ns in "$NS_LAN10" "$NS_LAN20" "$NS_RTR" "$NS_SW" "$NS_INET"; do
  ip -n "$ns" link set lo up
  ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.send_redirects=0
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.default.send_redirects=0
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.accept_redirects=0
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.default.accept_redirects=0
done

ip -n "$NS_LAN10" link set lan0  address 02:00:00:00:10:02
ip -n "$NS_RTR"   link set lan10 address 02:00:00:00:10:01
ip -n "$NS_LAN20" link set lan0  address 02:00:00:00:20:02
ip -n "$NS_RTR"   link set lan20 address 02:00:00:00:20:01
ip -n "$NS_RTR"   link set wan0  address 02:00:00:00:a0:0a
ip -n "$NS_SW"    link set wan0  address 02:00:00:00:a0:01
ip -n "$NS_SW"    link set lan0  address 02:00:00:00:30:01
ip -n "$NS_INET"  link set lan0  address 02:00:00:00:30:02

ip -n "$NS_LAN10" addr add 10.10.0.2/24 dev lan0
ip -n "$NS_RTR"   addr add 10.10.0.1/24 dev lan10
ip -n "$NS_LAN20" addr add 10.20.0.2/24 dev lan0
ip -n "$NS_RTR"   addr add 10.20.0.1/24 dev lan20
ip -n "$NS_RTR"   addr add 192.0.2.10/24 dev wan0
ip -n "$NS_SW"    addr add 192.0.2.1/24 dev wan0
ip -n "$NS_SW"    addr add 203.0.113.1/24 dev lan0
ip -n "$NS_INET"  addr add 203.0.113.2/24 dev lan0

for item in \
  "$NS_LAN10 lan0 1476" \
  "$NS_RTR lan10 1476" \
  "$NS_LAN20 lan0 1476" \
  "$NS_RTR lan20 1476" \
  "$NS_RTR wan0 1500" \
  "$NS_SW wan0 1500" \
  "$NS_SW lan0 1476" \
  "$NS_INET lan0 1476"
do
  set -- $item
  ip -n "$1" link set "$2" mtu "$3" up
  disable_basic_offloads "$1" "$2"
done

# Kernel GRE is used on xdp-sw to simulate the GRE-capable switch.
# xdp-rtr also gets gre1 as a slow/fallback path. Run xdp-rtr with -decap=true
# to test the XDP return path; bring xdp-rtr:gre1 down to prove it is not used.
ip -n "$NS_RTR" tunnel add gre1 mode gre local 192.0.2.10 remote 192.0.2.1 ttl 64
ip -n "$NS_SW"  tunnel add gre1 mode gre local 192.0.2.1  remote 192.0.2.10 ttl 64
ip -n "$NS_RTR" addr add 172.16.0.1/30 dev gre1
ip -n "$NS_SW"  addr add 172.16.0.2/30 dev gre1
ip -n "$NS_RTR" link set gre1 mtu 1476 up
ip -n "$NS_SW"  link set gre1 mtu 1476 up

for ns in "$NS_RTR" "$NS_SW"; do
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.gre1.rp_filter=0
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.wan0.rp_filter=0
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0
done

ip -n "$NS_LAN10" route add default via 10.10.0.1
ip -n "$NS_LAN20" route add default via 10.20.0.1
ip -n "$NS_INET"  route add default via 203.0.113.1

# Slow/fallback path routes.
# Forward slow path on xdp-rtr and all return traffic on xdp-sw use kernel GRE.
ip -n "$NS_RTR" route add 203.0.113.0/24 dev gre1
ip -n "$NS_SW"  route add 10.10.0.0/24 dev gre1
ip -n "$NS_SW"  route add 10.20.0.0/24 dev gre1

# Warm up directly connected and tunnel neighbors/routes.
ip netns exec "$NS_RTR" ping -c 1 -W 1 192.0.2.1 >/dev/null 2>&1 || true
ip netns exec "$NS_SW"  ping -c 1 -W 1 192.0.2.10 >/dev/null 2>&1 || true
ip netns exec "$NS_RTR" ping -c 1 -W 1 10.10.0.2 >/dev/null 2>&1 || true
ip netns exec "$NS_RTR" ping -c 1 -W 1 10.20.0.2 >/dev/null 2>&1 || true
ip netns exec "$NS_SW"  ping -c 1 -W 1 203.0.113.2 >/dev/null 2>&1 || true
ip netns exec "$NS_RTR" ping -c 1 -W 1 172.16.0.2 >/dev/null 2>&1 || true

cat <<EOM
Created multi-LAN lab with kernel GRE on xdp-sw.

Left gateway namespace $NS_RTR:
  lan10 10.10.0.1/24
  lan20 10.20.0.1/24
  wan0  192.0.2.10/24
  gre1  172.16.0.1/30  slow/fallback path

Right GRE peer namespace $NS_SW:
  wan0  192.0.2.1/24
  gre1  172.16.0.2/30  kernel GRE endpoint
  lan0  203.0.113.1/24

Run only the left XDP gateway:
  sudo ip netns exec $NS_RTR ./xdp-gre-gw \\
    -lan lan10 -lan lan20 \\
    -wan wan0 \\
    -local 192.0.2.10 \\
    -remote 192.0.2.1 \\
    -inner-mtu 1476 \\
    -mode generic \\
    -decap=true

The xdp-sw side uses kernel GRE. Do not run xdp-gre-gw inside $NS_SW for this lab.

Test:
  sudo ip netns exec $NS_INET iperf3 -s
  sudo ip netns exec $NS_LAN10 iperf3 -c 203.0.113.2
  sudo ip netns exec $NS_LAN20 iperf3 -c 203.0.113.2

Observe kernel GRE on xdp-sw:
  sudo ip netns exec $NS_SW tcpdump -ni wan0 'proto 47'
  sudo ip netns exec $NS_SW tcpdump -ni gre1 'icmp or ip'

Optional: prove xdp-rtr return path is XDP decap, not router-side kernel GRE:
  sudo ip netns exec $NS_RTR ip link set gre1 down
  sudo ip netns exec $NS_LAN10 ping -c 3 203.0.113.2

Destroy:
  sudo ./scripts/destroy-multilan-netns.sh
EOM
