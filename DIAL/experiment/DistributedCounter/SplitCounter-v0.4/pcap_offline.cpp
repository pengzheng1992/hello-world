/* Author: PZ
 * Raw IP ONLY!
 */
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <map>
#include <cmath>
#include <stdint.h>
#include <cassert>
#include <climits>

#define IN
#define OUT

#define NUM_SWITCHES 16 // how many splitcounters
#define WIDTH_SPLIT_COUNTER 16 // must <= 16bits
#define WIDTH_FULL_COUNTER 28 // must <= 64bits
#define NUM_COUNTER_THRESHOLD (910000/NUM_SWITCHES+1) // how many counters can a splitcounter hold
//#define NUM_COUNTER_THRESHOLD INT_MAX

using namespace std;

static map<struct Tuple5, uint64_t> FullCounter;

static map<struct Tuple5, uint16_t> SplitCounter[NUM_SWITCHES];

static map<struct Tuple5, uint64_t> Controller;

static long countPacketIn = 0;

struct Tuple5 {
	uint16_t sport;
	uint16_t dport;
	uint32_t saddr;
	uint32_t daddr;
	uint8_t ip_proto;

	bool operator == (Tuple5 const &o) const {
		return saddr == o.saddr && daddr == o.daddr && sport == o.sport && dport == o.dport && ip_proto == o.ip_proto;
	}
	
	//这个函数指定排序策略
	bool operator < (Tuple5 const &o) const {
		if (saddr < o.saddr) return true;
		if (saddr > o.saddr) return false;
		if (daddr < o.daddr) return true;
		if (daddr > o.daddr) return false;
		if (sport < o.sport) return true;
		if (sport > o.sport) return false;
		if (dport < o.dport) return true;
		if (dport > o.dport) return false;
		if (ip_proto < o.ip_proto) return true;
		if (ip_proto > o.ip_proto) return false;
		assert(*this == o);
		return false;
	}
};

struct Packet {
	uint16_t length;
	//uint16_t eth_proto;
	struct Tuple5 tuple5;
	bool ip;
};


void printUsage() {
    fprintf(stderr, "Usage: ./test -f filename\n");
}

int parse_args(IN int argc, IN char **argv, OUT const char **file) {
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (!strcmp(arg, "-f") && i + 1 < argc)	{
            *file = argv[++i];
        } else {
            fprintf(stderr, "Unknown option '%s'.\n", arg);
            printUsage();
            return 1;
        }
    }
    return 0;
}

void init_zero(OUT struct Packet *ppacket) {
    ppacket->ip = false;
    (ppacket->tuple5).sport = 0;
    (ppacket->tuple5).dport = 0;
    (ppacket->tuple5).saddr = 0;
    (ppacket->tuple5).daddr = 0;
}

// get some basic info from the ip packet.
void get_ip_info(IN const u_char **ppcap_content, OUT struct Packet *ppacket) {
	//cout << "sizeof(struct ethhdr): " << sizeof(struct ethhdr) << endl;
	struct iphdr *ipv4_hdr_ptr = (struct iphdr *)(*ppcap_content);
	(ppacket->tuple5).saddr = ipv4_hdr_ptr->saddr; // only ip address is stored in big end, i.e. without ntoh();
	(ppacket->tuple5).daddr = ipv4_hdr_ptr->daddr;
	(ppacket->tuple5).ip_proto = ipv4_hdr_ptr->protocol;
}

// get some basic info from the tcp packet.
void get_tcp_info(IN const u_char **ppcap_content, OUT struct Packet *ppacket) {
	struct tcphdr *tcp_hdr_ptr = (struct tcphdr *)(*ppcap_content + sizeof(struct iphdr));
	(ppacket->tuple5).sport = ntohs(tcp_hdr_ptr->source);
	(ppacket->tuple5).dport = ntohs(tcp_hdr_ptr->dest);
}

// get some basic info from the udp packet.
void get_udp_info(IN const u_char **ppcap_content, OUT struct Packet *ppacket) {
	struct udphdr *udp_hdr_ptr = (struct udphdr *)(*ppcap_content + sizeof(struct iphdr));
	(ppacket->tuple5).sport = ntohs(udp_hdr_ptr->source);
	(ppacket->tuple5).dport = ntohs(udp_hdr_ptr->dest);
}

// pre-process the packet.
void init_packet(IN const struct pcap_pkthdr *packet_header, IN const u_char **ppcap_content, OUT struct Packet *ppacket) {
    init_zero(OUT ppacket);
    ppacket->length = packet_header->len;
	//cout << "ip" << endl;
	ppacket->ip = true;
	get_ip_info(IN ppcap_content, OUT ppacket);
	switch (ppacket->tuple5.ip_proto) {
		case IPPROTO_TCP: {
			//cout << "tcp" << endl;
			get_tcp_info(IN ppcap_content, OUT ppacket);
			break;
		}
		case IPPROTO_UDP: {
			//cout << "udp" << endl;
			get_udp_info(IN ppcap_content, OUT ppacket);
			break;
		}
		case IPPROTO_ICMP: {
			//cout << "icmp" << endl;
			break;
		}
		default: {
			break;
		}
	}
}

template <typename T>
void count_flow(IN struct Packet *ppacket, OUT map<struct Tuple5, T> &o) {
    assert(ppacket->ip == true);
    o[ppacket->tuple5] += ppacket->length;
}

void count_flow_full(IN struct Packet *ppacket) {
    if (ppacket->ip == true) {
        count_flow(IN ppacket, OUT FullCounter);
    }
}
/*
void upload(IN int i, IN Tuple5 o) {
    Controller[o] += SplitCounter[i][o];
    SplitCounter[i][o] = 0;
    SplitCounter[i].erase(o);
}
*/
void packetIn(IN struct Packet *ppacket) {
    if (ppacket->ip == true) {
		countPacketIn++;
        count_flow(IN ppacket, OUT Controller);
    }
}

void count_flow_split(IN struct Packet *ppacket, IN int i) {
    if (ppacket->ip == true) {
		if ((SplitCounter[i].size() >= NUM_COUNTER_THRESHOLD && 0 == SplitCounter[i].count(ppacket->tuple5))
			|| (SplitCounter[i][ppacket->tuple5] + ppacket->length >= pow(2, WIDTH_SPLIT_COUNTER))) {
            //upload(IN i, IN ppacket->tuple5);
            //takeover();
            if (i == NUM_SWITCHES - 1) {
				packetIn(IN ppacket);
            } else {
           		count_flow_split(IN ppacket, IN i + 1);
			}
        } else {
            count_flow(IN ppacket, OUT SplitCounter[i]);
        }
    }
}

// 数据包callback函数
void callback(u_char *args, const struct pcap_pkthdr *pcap_header, const u_char *pcap_content) {
    struct Packet packet;
    Packet *ppacket = &packet;
    init_packet(IN pcap_header, IN &pcap_content, OUT ppacket);
    count_flow_full(IN ppacket);
    count_flow_split(IN ppacket, IN 0);
    //printf("caplen: %d, sip: %d, dip: %d, sport: %d, dport: %d\n", ppacket->length, 
           //(ppacket->tuple5).saddr, (ppacket->tuple5).daddr, (ppacket->tuple5).sport, (ppacket->tuple5).dport);

}


template <typename T>
int show_result(IN map<struct Tuple5, T> &o, IN int typelen) {
	/*
	for (auto it = o.begin(); it != o.end(); it++) {
        if (it->second > pow(2, WIDTH_FULL_COUNTER)) {
            printf("proto: %u, sip: %u, dip: %u, sport: %u, dport: %u\n", it->first.ip_proto, 
                it->first.saddr, it->first.daddr, it->first.sport, it->first.dport);
            cout << "volume: " << it->second << endl;
        }
    }
	*/
	int count = o.size();
	int memory = count * typelen;
	int mB = memory / 8;
	int mKB = mB / 1024;
	int mMB = mKB / 1024;
    cout << "Size count: " << count << ", typelen: " << typelen << ", MEMORY: " << memory << "b = " 
		<< mB << "B = " << mKB << "KB = " << mMB << "MB" << endl;
	return memory;
}

void showAllResult() {
	cout << "FullCounter: ";
	int fullMemory = show_result(IN FullCounter, WIDTH_FULL_COUNTER);
	int splitMemory = 0;
	for (int i = 0; i < NUM_SWITCHES; i++) {
		cout << "SplitCounter[" << i << "]: "; 
       	splitMemory += show_result(IN SplitCounter[i], WIDTH_SPLIT_COUNTER);
    }
	cout << "Controller: ";
	int controllerMemory = show_result(IN Controller, WIDTH_FULL_COUNTER);
	cout << "FullMemory: " << fullMemory << "b, "<< "SplitMemory: " << splitMemory << "b, "<< "ControllerMemory: " << controllerMemory
		<< "b, Ratio: " << (double)(splitMemory) / fullMemory * 100 << "%" << endl;
	cout << "countPacketIn: " << countPacketIn << endl;
}


int main(IN int argc, IN char *argv[]) {
    pcap_t *handler;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* file = "test.pcap";
    if (parse_args(IN argc, IN argv, OUT &file)) {
        fprintf(stderr, "Couldn't parse args.\n");
        return 1;
    }

    // 打开文件
    if ((handler = pcap_open_offline(file, errbuf)) == NULL) {
        fprintf(stderr, "Couldn't open file: %s\n%s\n", file, errbuf);
        printUsage();
        return 1;
    } else {
		cout << "Open file: " << file << endl;
	}

	// 捕获数据包
	pcap_loop(handler, -1, callback, NULL);

	showAllResult();

    /* And close the session */
    pcap_close(handler);

    return 0;
}
