#!/bin/bash
./first_test_1_2.sh
for i in 10 30 50 100
do
	for j in 0 0.1 1 3 5 10
	do
		echo "Delay = $i ms, packet loss rate = $j %"
		sudo tc qdisc change dev ifb0 root netem delay "$i"ms loss "$j"%
		rm std.txt 			#if there has been an error
		echo "QUIC test starting"
		./quic_script.sh		#call inner script
		sudo rm /var/log/kern.log	#purge logs
		sudo rm /var/log/syslog
		sudo rm /var/log/kern.log.1
		sudo rm /var/log/syslog.1
		cat std.txt | sed '/^$/d' | sed 's/,/./g' | tr "\n" "," | sed 's/,$/\n/g' >> ~/Documents/Testing/Test\ 1\ results/quic_"$i".csv
		mv std.txt ~/Documents/Testing/Test\ 1\ results/quic_"$i"_"$j".txt
		rm test1.pcapng
		echo "TCP test starting"
		./TCP_script.sh		#call inner script
		sudo rm /var/log/kern.log	#purge logs
		sudo rm /var/log/syslog
		sudo rm /var/log/kern.log.1
		sudo rm /var/log/syslog.1
		cat std.txt | sed '/^$/d' | sed 's/,/./g' | tr "\n" "," | sed 's/,$/\n/g' >> ~/Documents/Testing/Test\ 1\ results/TCP_"$i".csv
		mv std.txt ~/Documents/Testing/Test\ 1\ results/TCP_"$i"_"$j".txt
		rm test1.pcapng
	done	
done
sudo tc qdisc del dev ifb0 root netem
