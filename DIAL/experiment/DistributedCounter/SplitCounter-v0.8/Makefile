all: pcap_offline.o
	g++ -o pcap_offline pcap_offline.o -lpcap -Wall -std=c++11 -O3

pcap_offline.o: pcap_offline.cc
	g++ -c pcap_offline.cc -lpcap -Wall -std=c++11 -O3

clean:
	rm *.o
	rm pcap_offline

run:
	./pcap_offline -f ~/pcap/equinix-chicago.dirA.20160121-125911.UTC.anon.pcap
