all : arp_spoof

arp_spoof: main.o
	g++ -g -o arp_spoof main.o -lpcap -pthread

main.o:
	g++ -g -c -o main.o main.cpp -pthread

clean:
	rm -f arp_spoof
	rm -f *.o

