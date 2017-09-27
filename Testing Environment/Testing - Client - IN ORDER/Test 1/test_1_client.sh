#!/bin/bash
./first.sh
for i in 10 30 50 100
do
	for j in 0 0.1 1 3 5 10
	do
		echo "Delay = $i ms, packet loss rate = $j %"
		echo "QUIC test starting"
		./QUIC_script.sh
		sudo rm /var/log/kern.log
		sudo rm /var/log/syslog
		sudo rm /var/log/kern.log.1
		sudo rm /var/log/syslog.1
		echo "TCP test starting"
		./TCP_script.sh
		sudo rm /var/log/kern.log
		sudo rm /var/log/syslog
		sudo rm /var/log/kern.log.1
		sudo rm /var/log/syslog.1
	done	
done

