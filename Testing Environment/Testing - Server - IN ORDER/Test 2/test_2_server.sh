#!/bin/bash
./first_test_1_2.sh
#AGAIN: CHANNEL INTERFERENCE MUST BE SET MANUALLY IN THE ROUTER SETTINGS
CHANNEL=52
for i in 10 50
do
	for j in 0
	do
	    echo "QUIC test starting"
		echo "Delay = $i ms, packet loss rate = $j %"
		sudo tc qdisc change dev ifb0 root netem delay "$i"ms
		rm std.txt 			#if there has been an error
		./quic_script.sh		#call inner script
		sudo rm /var/log/kern.log	#purge logs
		sudo rm /var/log/syslog
		sudo rm /var/log/kern.log.1
		sudo rm /var/log/syslog.1
		cat std.txt | sed '/^$/d' | sed 's/,/./g' | tr "\n" "," | sed 's/,$/\n/g' >> ~/Documents/Testing/Test\ 2\ results/test_"$CHANNEL".csv
		mv std.txt ~/Documents/Testing/Test\ 2\ results/quic_"$i"_"$CHANNEL".txt	
		rm test1.pcapng
		echo "TCP test starting"
		./TCP_script.sh			#call inner script
		sudo rm /var/log/kern.log	#purge logs
		sudo rm /var/log/syslog
		sudo rm /var/log/kern.log.1
		sudo rm /var/log/syslog.1
		cat std.txt | sed '/^$/d' | sed 's/,/./g' | tr "\n" "," | sed 's/,$/\n/g' >> ~/Documents/Testing/Test\ 2\ results/test_"$CHANNEL".csv
		mv std.txt ~/Documents/Testing/Test\ 2\ results/TCP_"$i"_"$CHANNEL".txt	
	done	
done
sudo tc qdisc del dev ifb0 root netem
