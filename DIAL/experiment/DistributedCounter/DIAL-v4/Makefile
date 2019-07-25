CC = g++
#CXXFLAGS = -std=c++11 -Wall -g -O3
CXXFLAGS = -std=c++11 -Wall -g -O3

LDLIBS = -lpcap
OBJS = dial.o parse_args.o packet.o topo.o place.o statistics.o
#

all: $(OBJS)
	$(CC) -o dial $(OBJS) $(CXXFLAGS) $(LDLIBS)

dial.o: dial.cpp common.h flow.h switch.h parse_args.h packet.h topo.h place.h statistics.h
	$(CC) -c dial.cpp $(CXXFLAGS) $(LDLIBS)
topo.o: topo.cpp topo.h
	$(CC) -c topo.cpp $(CXXFLAGS)
packet.o: packet.cpp packet.h common.h
	$(CC) -c packet.cpp $(CXXFLAGS)
parse_args.o: parse_args.cpp parse_args.h common.h
	$(CC) -c parse_args.cpp $(CXXFLAGS)
place.o: place.cpp place.h flow.h common.h
	$(CC) -c place.cpp $(CXXFLAGS)
statistics.o: statistics.cpp statistics.h
	$(CC) -c statistics.cpp $(CXXFLAGS)
#run:
#	./split_counter -p ~/pcap/equinix-chicago.dirA.20160121-125911.UTC.anon.pcap -t ~/topo/cernet.txt

.PHONY: run clean

clean:
	rm $(OBJS) dial
	
APP = ./dial
#PCAP = ~/pcap/equinix-chicago.dirA.20160121-125911.UTC.anon.pcap
PCAP = ~/pcap/equinix-chicago.dirA.20160218-130000.UTC.anon.pcap
#PCAP = ~/Desktop/Pcap/equinix-chicago.dirA.20160317-130100.UTC.anon.pcap
#TOPO = ~/topo/fattree.txt
#TOPO = ~/topo/cernet.txt
TOPO = ~/topo/chinanet.txt
#TOPO = ~/topo/test.txt

DEV_ARGS = -p $(PCAP) -t $(TOPO)

run:
	$(APP) $(DEV_ARGS)