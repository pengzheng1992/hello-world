all: pcap_offline.o
	g++ -o pcap_offline pcap_offline.o -lpcap -Wall -std=c++11

pcap_offline.o: pcap_offline.cpp pcap_offline.h
	g++ -c pcap_offline.cpp -lpcap -Wall -std=c++11

clean:
	rm *.o
	rm pcap_offline
