#!/bin/bash
i=0
while [ $i -lt 20 ]
do
	let i=i+1
	sleep 15
	echo "Test number $i"
	./TCPClient	
done
sleep 15

