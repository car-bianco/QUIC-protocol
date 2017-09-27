#!/bin/bash
for BAND in 0.5
do
	for PROT in TCP 
	do
		for i in 10 50
		do
			for j in 0 0.1 1
			do
				rm std2.txt 			#if there has been an error
				echo "TCP test (stream 1) starting"
				./"$PROT"_script_2.sh		#call inner script
				sudo rm /var/log/kern.log	#purge logs
				sudo rm /var/log/syslog
				sudo rm /var/log/kern.log.1
				sudo rm /var/log/syslog.1
				cat std2.txt | sed '/^$/d' | sed 's/,/./g' | tr "\n" "," | sed 's/,$/\n/g' >> ~/Documents/Testing/Test\ 3b\ results/"$PROT"_"$BAND"_stream2.csv
				mv std2.txt ~/Documents/Testing/Test\ 3b\ results/"$PROT"_"$i"_"$j"_"$PROT"_"$BAND"_stream2.txt
				rm test2.pcapng
				sleep 15
			done	
		done
	done
done
