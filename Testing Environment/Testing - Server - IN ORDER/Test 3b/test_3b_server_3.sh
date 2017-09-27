#!/bin/bash

for BAND in 0.5
do
	for PROT in TCP 
	do
		for i in 10 50
		do
			for j in 0 0.1 1
			do
				rm std3.txt 			#if there has been an error
				echo "TCP test (stream 2) starting"
				./"$PROT"_script_3.sh		#call inner script
				sudo rm /var/log/kern.log	#purge logs
				sudo rm /var/log/syslog
				sudo rm /var/log/kern.log.1
				sudo rm /var/log/syslog.1
				cat std3.txt | sed '/^$/d' | sed 's/,/./g' | tr "\n" "," | sed 's/,$/\n/g' >> ~/Documents/Testing/Test\ 3b\ results/"$PROT"_"$BAND"_stream3.csv
				mv std2.txt ~/Documents/Testing/Test\ 3b\ results/"$PROT"_"$i"_"$j"_"$PROT"_"$BAND"_stream3.txt
				rm test3.pcapng
				sleep 15
			done	
		done
	done
done
