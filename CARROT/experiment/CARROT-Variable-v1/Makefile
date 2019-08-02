CC = g++
#CXXFLAGS = -std=c++11 -Wall -g -O3
CXXFLAGS = -std=c++11 -Wall -g -O3

LDLIBS = -lpcap
OBJS = main.o parse_args.o packet.o topo.o place.o statistics.o
APP = carrot.out
APP_PATH = ./$(APP)

all: $(OBJS)
	$(CC) -o $(APP) $(OBJS) $(CXXFLAGS) $(LDLIBS)

main.o: main.cpp common.h flow.h switch.h parse_args.h packet.h topo.h place.h statistics.h
	$(CC) -c main.cpp $(CXXFLAGS) $(LDLIBS)
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
	rm $(OBJS) $(APP)
	
PCAP1 = ~/pcap/equinix-chicago.dirA.20160121-125911.UTC.anon.pcap
PCAP2 = ~/pcap/equinix-chicago.dirA.20160218-130000.UTC.anon.pcap
PCAP3 = ~/pcap/equinix-chicago.dirA.20160317-130100.UTC.anon.pcap
TOPO1 = ~/topo/fattree.txt
TOPO2 = ~/topo/cernet.txt
TOPO3 = ~/topo/chinanet.txt
#TOPO = ~/topo/test.txt

DEV_ARGS = -p $(PCAP1) -t $(TOPO3)

run:
	$(APP_PATH) $(DEV_ARGS)

