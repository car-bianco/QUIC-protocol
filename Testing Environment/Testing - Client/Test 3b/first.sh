#!/bin/bash

sudo rm /var/log/kern.log
sudo rm /var/log/syslog
sudo sysctl -w net.core.wmem_default=2097152
sudo sysctl -w net.core.wmem_max=2097152
sudo sysctl -w net.core.rmem_default=2097152
sudo sysctl -w net.core.rmem_max=2097152
#sudo tc qdisc add dev eth0 root netem delay 10ms

