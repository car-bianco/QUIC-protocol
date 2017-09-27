#!/bin/bash
./first_test_3_4.sh
for BAND in 2 0.5
do
	for PROT in quic TCP
	do
		for i in 10 50
		do
			for j in 0 0.1 1
			do
				echo "Delay = $i ms, packet loss rate = $j %, concurrent protocol = $PROT, bandwidth cap = $BAND MBps"
				sudo tc qdisc change dev ifb0 parent 1:11 handle 10: netem delay "$i"ms loss "$j"%
				rm std.txt 			#if there has been an error
				echo "QUIC test starting"
				./quic_script.sh		#call inner script
				sudo rm /var/log/kern.log	#purge logs
				sudo rm /var/log/syslog
				sudo rm /var/log/kern.log.1
				sudo rm /var/log/syslog.1
				cat std.txt | sed '/^$/d' | sed 's/,/./g' | tr "\n" "," | sed 's/,$/\n/g' >> ~/Documents/Testing/Test\ 3\ results/"$PROT"_"$BAND"_stream1.csv
				mv std.txt ~/Documents/Testing/Test\ 3\ results/quic_"$i"_"$j"_"$PROT"_"$BAND"_stream1.txt
				rm test1.pcapng
			done	
		done
	done
sudo tc class change dev ifb0 parent 1: classid 1:1 htb rate 4Mbit
sudo tc class change dev ifb0 parent 1:1 classid 1:11 htb rate 4Mbit
done
