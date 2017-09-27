#!/bin/bash
i=0
while [ $i -lt 20 ]
do
	let i=i+1
	echo "Test number $i"
	sleep 15
	./quicClient	
done
sleep 15
