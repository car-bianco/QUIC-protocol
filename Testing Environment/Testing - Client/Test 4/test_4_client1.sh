#!/bin/bash
./first.sh
#CHANNEL INTERFERENCE MUST BE SET MANUALLY IN THE ROUTER SETTINGS
for BAND in 05
do
	for PROT in TCP 
	do
		for i in 10 30 50 100
		do
			for j in 0 0.1 1 3
			do
				echo "Delay = $i ms, packet loss rate = $j %, bandwidth = $BAND MBps, concurrent protocol = $PROT"
				./quic_sync_script.sh
				sudo rm /var/log/kern.log
				sudo rm /var/log/syslog
				sudo rm /var/log/kern.log.1
				sudo rm /var/log/syslog.1
			done	
		done
	done
done


