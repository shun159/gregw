agre (An experimental GRE gateway)
---


This will allow traffic to be routed through the remote GRE endpoint as shown below.

```bash
02:06:26.887513 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto GRE (47), length 1500)
    192.0.2.10 > 192.0.2.1: GREv0, Flags [none], length 1480
	IP (tos 0x0, ttl 63, id 14272, offset 0, flags [DF], proto TCP (6), length 1476)
    10.20.0.2.60406 > 203.0.113.2.5201: Flags [.], cksum 0x4bcf (incorrect -> 0x9817), seq 1435217014:1435218438, ack 1, win 64, options [nop,nop,TS val 30967492 ecr 3060651575], length 1424
```

I want a powerful machine to run this.
