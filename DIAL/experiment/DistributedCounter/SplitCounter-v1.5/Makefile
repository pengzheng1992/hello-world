CC = g++
CXXFLAGS = -std=c++17 -Wall -g -O3
LDLIBS = -lpcap
OBJS = split_counter.o topo.o packet.o parse_args.o statistics.o

all: $(OBJS)
	$(CC) -o split_counter $(OBJS) $(CXXFLAGS) $(LDLIBS)

split_counter.o: split_counter.cc common.h packet.h topo.h
	$(CC) -c split_counter.cc $(CXXFLAGS) $(LDLIBS)
topo.o: topo.cc topo.h
	$(CC) -c topo.cc $(CXXFLAGS)
packet.o: packet.cc packet.h common.h
	$(CC) -c packet.cc $(CXXFLAGS)
parse_args.o: parse_args.cc parse_args.h common.h
	$(CC) -c parse_args.cc $(CXXFLAGS)
statistics.o: statistics.cc statistics.h
	$(CC) -c statistics.cc $(CXXFLAGS)
#run:
#	./split_counter -p ~/pcap/equinix-chicago.dirA.20160121-125911.UTC.anon.pcap -t ~/topo/cernet.txt

.PHONY: run clean

clean:
	rm split_counter $(OBJS)
	
APP = ./split_counter
PCAP = ~/pcap/equinix-chicago.dirA.20160121-125911.UTC.anon.pcap
TOPO = ~/topo/chinanet.txt

DEV_ARGS = -p $(PCAP) -t $(TOPO)

run:
	$(APP) $(DEV_ARGS)