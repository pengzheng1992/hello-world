CC = g++
FLAGS = -Wall -g -O3

#LDLIBS = -lpcap
LDLIBS = 
OBJS = dflow.o flow1.o pcap.o 
APP = dflow
APP_PATH = ./$(APP)

all: $(OBJS)
	$(CC) -o $(APP) $(OBJS) $(FLAGS) $(LDLIBS)

dflow.o: dflow.cpp flow1.h pcap.h
	$(CC) -c dflow.cpp $(FLAGS) $(LDLIBS)
flow1.o: flow1.cpp flow1.h
	$(CC) -c flow1.cpp $(FLAGS)
pcap.o: pcap.cpp pcap.h 
	$(CC) -c pcap.cpp $(FLAGS)

.PHONY: run clean

clean:
	rm $(OBJS) $(APP)

#run:
#	./split_counter -p ~/pcap/equinix-chicago.dirA.20160121-125911.UTC.anon.pcap -t ~/topo/cernet.txt

PCAP1 = ~/pcap/equinix-chicago.dirA.20160121-125911.UTC.anon.pcap
PCAP2 = ~/pcap/equinix-chicago.dirA.20160218-130000.UTC.anon.pcap
PCAP3 = ~/pcap/equinix-chicago.dirA.20160317-130100.UTC.anon.pcap
TOPO1 = ~/topo/fattree.txt
TOPO2 = ~/topo/cernet.txt
TOPO3 = ~/topo/chinanet.txt
#TOPO = ~/topo/test.txt

#DEV_ARGS = -p $(PCAP1) -t $(TOPO1)
DEV_ARGS = 

run:
	$(APP_PATH) $(DEV_ARGS)

