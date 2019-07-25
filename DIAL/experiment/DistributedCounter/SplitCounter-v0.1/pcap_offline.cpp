#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include "pcap_offline.h"
#include <iostream>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <map>
#include <cmath>
#include <stdint.h>


using namespace std;

#define NUM_SWITCHES 8
#define WIDTH_SPLIT_COUNTER 16 // 16 bits


static map<struct Tuple5, uint64_t> FullCounter;

static map<struct Tuple5, uint16_t> SplitCounter[NUM_SWITCHES];

static map<struct Tuple5, uint64_t> Controller;




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

void init_zero(IN struct Packet *ppacket) {
    //ppacket->syn = false;
    //ppacket->icmp = false;
    //ppacket->fin = false;
    //ppacket->other = false;
    ppacket->ip = false;
    (ppacket->tuple5).sport = 0;
    (ppacket->tuple5).dport = 0;
    (ppacket->tuple5).saddr = 0;
    (ppacket->tuple5).daddr = 0;
}

// get some basic info from the ip packet.
void get_ip_info(IN const u_char **ppcap_content, OUT struct Packet *ppacket) {
	struct iphdr *ipv4_hdr_ptr = (struct iphdr *)(*ppcap_content + sizeof(struct ethhdr));
	(ppacket->tuple5).saddr = ipv4_hdr_ptr->saddr; // only ip address is stored in big end, i.e. without ntoh();
	(ppacket->tuple5).daddr = ipv4_hdr_ptr->daddr;
	(ppacket->tuple5).ip_proto = ipv4_hdr_ptr->protocol;
}

// get some basic info from the tcp packet.
void get_tcp_info(IN const u_char **ppcap_content, OUT struct Packet *ppacket) {
	struct tcphdr *tcp_hdr_ptr = (struct tcphdr *)(*ppcap_content + sizeof(struct ethhdr) + sizeof(struct iphdr));
	//ppacket->syn = tcp_hdr_ptr->syn;
	//ppacket->fin = tcp_hdr_ptr->fin;
	(ppacket->tuple5).sport = ntohs(tcp_hdr_ptr->source);
	(ppacket->tuple5).dport = ntohs(tcp_hdr_ptr->dest);
}

// get some basic info from the udp packet.
void get_udp_info(IN const u_char **ppcap_content, OUT struct Packet *ppacket) {
	struct udphdr *udp_hdr_ptr = (struct udphdr *)(*ppcap_content + sizeof(struct ethhdr) + sizeof(struct iphdr));
	(ppacket->tuple5).sport = ntohs(udp_hdr_ptr->source);
	(ppacket->tuple5).dport = ntohs(udp_hdr_ptr->dest);
}

// pre-process the packet.
void init_packet(IN const struct pcap_pkthdr *packet_header, IN const u_char **ppcap_content, OUT struct Packet *ppacket) {
    init_zero(ppacket);
    ppacket->length = packet_header->caplen;
    struct ethhdr *eth_hdr_ptr = (struct ethhdr *)(*ppcap_content);
    if (!eth_hdr_ptr) return;
	ppacket->eth_proto = ntohs(eth_hdr_ptr->h_proto); // IP or ARP or OTHER
    switch (ppacket->eth_proto) {
		case ETH_P_IP: {
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
					//ppacket->icmp = true;
					break;
				}
				default: {
					break;
				}
			}
			break;
		}
		/*case ETH_P_ARP: {
			//cout << "ARP" << endl;
			//get_arp_info(IN idesc, OUT ppacket);
			break;
		}*/
		default: {
			//cout << "OTHER" << endl;
			//ppacket->other = true;
			break;
		}
	}
}

/*
template <typename T> inline void count_flow(IN struct Packet *ppacket, OUT map<struct Tuple5, T> &o) {
    assert (ppacket->ip == true);
    o[ppacket->tuple5] += ppacket->length;
}*/

void count_flow_full(IN struct Packet *ppacket) {
    if (ppacket->ip == true) {
        count_flow(IN ppacket, OUT FullCounter);
    }
}

void upload(IN size_t i, IN Tuple5 o) {
    Controller[o] += SplitCounter[i][o];
    SplitCounter[i][o] = 0;
    SplitCounter[i].erase(o);
}

void count_flow_split(IN struct Packet *ppacket, IN size_t i) {
    if (ppacket->ip == true) {
        if (SplitCounter[i][ppacket->tuple5] + ppacket->length < pow(2, WIDTH_SPLIT_COUNTER)) {
            count_flow(IN ppacket, OUT SplitCounter[i]);
        } else {
            upload(IN i, IN ppacket->tuple5);
           // takeover();
            if (++i == NUM_SWITCHES) {
                i = 0;
            }
            count_flow_split(IN ppacket, IN i);
        }
    }
}

template <typename T>
void show_result(IN map<struct Tuple5, T> &o) {
    //static int cnt = 0;
	for (auto it = o.begin(); it != o.end(); it++) {
        if (it->second > 1000000) {
           // printf("proto: %u, sip: %u, dip: %u, sport: %u, dport: %u\n", it->first.ip_proto, 
           //     it->first.saddr, it->first.daddr, it->first.sport, it->first.dport);
          //  cout << "volume: " << it->second << endl;
        }
    }
    //cout << "test: " << pow(2, WIDTH_SPLIT_COUNTER) << endl;
    cout << "Size count: " << o.size() << ", sizeof(T): " << sizeof(T) << ", MEMORY: " << o.size() * sizeof(T)  << endl;
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
    }

    // 捕获数据包
    pcap_loop(handler, -1, callback, NULL);
    
    show_result(FullCounter);
    for (size_t i = 0; i < NUM_SWITCHES; i++) {
        show_result(SplitCounter[i]);
    }
   // show_result(SplitCounter[0]);
    show_result(Controller);


    /* And close the session */
    pcap_close(handler);

    return 0;
}
