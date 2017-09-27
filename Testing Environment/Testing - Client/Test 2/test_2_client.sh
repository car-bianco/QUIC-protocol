#!/bin/bash
./first.sh
#CHANNEL INTERFERENCE HAS TO BE MANUALLY SET IN THE ROUTER SETTINGS!
for i in 10 50
do
	for j in 0
	do
		echo "Delay = $i ms, Packet loss rate = $j %"
		echo "QUIC test starting"
		./quic_script.sh
		sudo rm /var/log/kern.log
		sudo rm /var/log/syslog
		sudo rm /var/log/kern.log.1
		sudo rm /var/log/syslog.1
		sleep 15
		echo "TCP test starting"
		./TCP_script.sh
		sudo rm /var/log/kern.log
		sudo rm /var/log/syslog
		sudo rm /var/log/kern.log.1
		sudo rm /var/log/syslog.1
	done	
done



