#!/bin/bash

#setup IFB interface
modprobe ifb
sudo ip link set dev ifb0 up
sudo tc qdisc add dev eth1 ingress handle ffff:
sudo tc filter add dev eth1 parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0
sudo tc qdisc add dev ifb0 root netem delay 10ms
#purge logs
sudo rm /var/log/kern.log
sudo rm /var/log/syslog
#set read and write buffer to higher values
sudo sysctl -w net.core.rmem_default=2097152
sudo sysctl -w net.core.rmem_max=2097152
sudo sysctl -w net.core.wmem_default=2097152
sudo sysctl -w net.core.wmem_max=2097152


