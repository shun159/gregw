agre (An experimental GRE gateway)
---

An experimental XDP/eBPF IPv4-over-GRE gateway.  
This project implements a minimal RFC 2784 IPv4-over-GRE datapath using XDP.


In a local single-host validation environment, `agre` reached more than 100 Gbit/s aggregate TCP throughput using XDP.
```
- - - - - - - - - - - - - - - - - - - - - - - - -
[SUM]   0.00-10.00  sec   155 GBytes   133 Gbits/sec  828             sender
[SUM]   0.00-10.00  sec   155 GBytes   133 Gbits/sec                  receiver
```

## Architecture

```text
LAN host(s)
  |
  | lan10 / lan20 / ...
  |
+----------------+
| agre           |
|                |
| LAN ingress    |  IPv4 -> IPv4/GRE
| WAN ingress    |  IPv4/GRE -> IPv4
+----------------+
  |
  | wan0
  |
GRE underlay
  |
Remote GRE peer
```


### LAN ingress

- Parses Ethernet + IPv4
- Bypasses ARP, non-IPv4, local gateway traffic, and local LAN-to-LAN traffic
- Checks MTU before encapsulation
- Uses kernel FIB to resolve the outer next hop
- Prepends outer IPv4 + GRE headers

### WAN ingress

- Parses outer IPv4/GRE
- Validates the GRE peer and GRE header
- Decapsulates inner IPv4
- Uses kernel FIB to resolve the LAN-side output interface and MAC address


## Configuration example

```yaml
wan: wan0
lans:
- name: lan10
  gateway: 10.10.0.1
  inner_mtu: 8000
- name: lan20
  gateway: 10.20.0.1
  inner_mtu: 8000
tunnel:
  local: 192.0.2.10
  remote: 192.0.2.1
  fib_lookup: true
xdp:
  mode: generic
  decap: true
defaults:
  inner_mtu: 9000
```

## Build and run

```bash
make
sudo ./bin/agre -config example/config.yaml
```




