#!/bin/bash
for BAND in 0.5
do
	for PROT in TCP 
	do
		for i in 10 30 50 100
		do
			for j in 0 0.1 1 3
			do
				rm std2.txt 			#if there has been an error
				./"$PROT"_script_2.sh		#call inner script
				sudo rm /var/log/kern.log	#purge logs
				sudo rm /var/log/syslog
				sudo rm /var/log/kern.log.1
				sudo rm /var/log/syslog.1
				cat std2.txt | sed '/^$/d' | sed 's/,/./g' | tr "\n" "," | sed 's/,$/\n/g' >> ~/Documents/Testing/Test\ 4\ results/"$PROT"_"$BAND"_stream2.csv
				mv std2.txt ~/Documents/Testing/Test\ 4\ results/"$PROT"_"$i"_"$j"_"$PROT"_"$BAND"_stream2.txt
				rm test2.pcapng
				sleep 15
			done	
		done
	done
done
