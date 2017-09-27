#!/bin/bash

#setup IFB interface
modprobe ifb
sudo ip link set dev ifb0 up
sudo tc qdisc add dev eth1 ingress handle ffff:
sudo tc filter add dev eth1 parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0
#purge logs
sudo rm /var/log/kern.log
sudo rm /var/log/syslog
#set read and write buffer to higher values
sudo sysctl -w net.core.rmem_default=2097152
sudo sysctl -w net.core.rmem_max=2097152
sudo sysctl -w net.core.wmem_default=2097152
sudo sysctl -w net.core.wmem_max=2097152
#add bandwidth limiting - Test 3 and 4
sudo tc qdisc add dev ifb0 handle 1: root htb default 11
sudo tc class add dev ifb0 parent 1: classid 1:1 htb rate 4Mbit
sudo tc class add dev ifb0 parent 1:1 classid 1:11 htb rate 4Mbit
sudo tc qdisc add dev ifb0 parent 1:11 handle 10: netem delay 10ms
