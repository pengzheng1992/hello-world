// Author: PZ
// Raw IP
// Rewrite

#include <stdio.h>
#include <string.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <stdint.h>
#include <assert.h>
#include <climits>
#include <cmath>
#include <iostream>
#include <unordered_map>
// #include <map>
#include <pcap.h>

#define IN
#define OUT

using namespace std;


struct Tuple5 {
	int sport; // source port number
	int dport; // destination port number
	int saddr; // source IP address
	int daddr; // destination IP address
	int ip_proto; // protocol

	/*bool operator == (const Tuple5& o) const {
		return saddr == o.saddr && daddr == o.daddr
			&& sport == o.sport && dport == o.dport
			&& ip_proto == o.ip_proto;
	}*/

	// for sort
	/*bool operator < (const Tuple5& o) const {
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
		return false;
	}*/
};

struct Tuple5Hash {
	std::size_t operator () (const Tuple5 &o) const {
		return hash<int>()(o.daddr) ^ hash<int>()(o.saddr)
			^ hash<int>()(o.dport) ^ hash<int>()(o.sport) ^ hash<int>()(o.ip_proto);
	}
};

struct EqualKey {
	bool operator () (const Tuple5 &o1, const Tuple5 &o2) const {
		return o2.saddr == o1.saddr && o2.daddr == o1.daddr
			&& o2.sport == o1.sport && o2.dport == o1.dport
			&& o2.ip_proto == o1.ip_proto;
	}
};

struct Packet {
	int length;
	struct Tuple5 tuple5;
};

const int kSwitches = 20; // how many switches we have for this flow
const int kSplitCounterWidth = 16; // must <= 16bits
const int kFullCounterWidth = 28; // must <= 64bits
const int kMaxCountersInSwitch = (910000 / kSwitches + 1); // how many counters can a split_counters hold
//#define MAX_COUNTERS_PER_SWITCH INT_MAX

typedef unordered_map<struct Tuple5, int, Tuple5Hash, EqualKey> MeterTable;
// typedef map<struct Tuple5, int> MeterTable;

static MeterTable fullsize_counters, split_counters[kSwitches], controller_counters;

static long packets_in_controller = 0;

void print_usage() {
    fprintf(stderr, "Usage: ./pcap_offline -f filename\n");
}

int parse_args(IN int argc, IN char **argv, OUT const char **file) {
    for (int i = 1; i < argc; ++i) {
        char *arg = argv[i];
        if (!strcmp(arg, "-f") && i + 1 < argc)	{
            *file = argv[++i];
        } else {
            fprintf(stderr, "Unknown option '%s'.\n", arg);
            print_usage();
            return 1;
        }
    }
    return 0;
}

// get some basic info from the ip packet.
void ip_info_from_pcap(IN const u_char **p_pcap_content, OUT struct Packet *p_packet) {
	struct iphdr *p_ipv4_header = (struct iphdr*)(*p_pcap_content);
	// only ip address is stored in big end, i.e. without ntoh();
	(p_packet->tuple5).saddr = p_ipv4_header->saddr; 
	(p_packet->tuple5).daddr = p_ipv4_header->daddr;
	(p_packet->tuple5).ip_proto = p_ipv4_header->protocol;
}

// get some basic info from the tcp packet.
void tcp_info_from_pcap(IN const u_char **p_pcap_content, OUT struct Packet *p_packet) {
	struct tcphdr *tcp_hdr_ptr = (struct tcphdr *)(*p_pcap_content + sizeof(struct iphdr));
	(p_packet->tuple5).sport = ntohs(tcp_hdr_ptr->source);
	(p_packet->tuple5).dport = ntohs(tcp_hdr_ptr->dest);
}

// get some basic info from the udp packet.
void udp_info_from_pcap(IN const u_char **p_pcap_content, OUT struct Packet *p_packet) {
	struct udphdr *udp_hdr_ptr = (struct udphdr *)(*p_pcap_content + sizeof(struct iphdr));
	(p_packet->tuple5).sport = ntohs(udp_hdr_ptr->source);
	(p_packet->tuple5).dport = ntohs(udp_hdr_ptr->dest);
}

// pre-process the packet.
void init_packet(IN const struct pcap_pkthdr *packet_header, IN const u_char **p_pcap_content, OUT struct Packet *p_packet) {
    p_packet->length = packet_header->len;
	ip_info_from_pcap(IN p_pcap_content, OUT p_packet);
	switch (p_packet->tuple5.ip_proto) {
		case IPPROTO_TCP: {
			//cout << "tcp" << endl;
			tcp_info_from_pcap(IN p_pcap_content, OUT p_packet);
			break;
		}
		case IPPROTO_UDP: {
			//cout << "udp" << endl;
			udp_info_from_pcap(IN p_pcap_content, OUT p_packet);
			break;
		}
		default: {
			//assert(false);
		}
	}
}

void count_flow(IN struct Packet *p_packet, OUT MeterTable &o) {
	o[p_packet->tuple5] += p_packet->length;
}

void packet_in_controller(IN struct Packet *p_packet) {
	++packets_in_controller;
	count_flow(IN p_packet, OUT controller_counters);
}

void count_split_flow(IN struct Packet *p_packet, IN int i) {
	auto it = split_counters[i].find(p_packet->tuple5);
	// new flow
	if (it == split_counters[i].end()) {
		// switch full
		if (split_counters[i].size() >= kMaxCountersInSwitch) {
			if (i == kSwitches - 1) {
				packet_in_controller(IN p_packet); // last switch goto the controller
			} else {
				count_split_flow(IN p_packet, IN i + 1); // goto next counter
			}
		} else {
			// packet too large
			if (p_packet->length >= pow(2, kSplitCounterWidth)) {
				if (i == kSwitches - 1) {
					packet_in_controller(IN p_packet); // last switch goto the controller
				} else {
					count_split_flow(IN p_packet, IN i + 1); // goto next counter
				}
			} else {
				count_flow(IN p_packet, OUT split_counters[i]);
			}
		}
	} else {
		// counter full
		if (it->second + p_packet->length >= pow(2, kSplitCounterWidth)) {
			if (i == kSwitches - 1) {
				packet_in_controller(IN p_packet); // last switch goto the controller
			} else {
				count_split_flow(IN p_packet, IN i + 1); // goto next counter
			}
		} else {
			count_flow(IN p_packet, OUT split_counters[i]);
		}
	}
}

int show_result(IN MeterTable &o, IN int typelen) {
	/*
	for (auto it = o.begin(); it != o.end(); it++) {
        if (it->second > pow(2, FULLSIZE_COUNTER_WIDTH)) {
            printf("proto: %u, sip: %u, dip: %u, sport: %u, dport: %u\n", it->first.ip_proto, 
                it->first.saddr, it->first.daddr, it->first.sport, it->first.dport);
            cout << "volume: " << it->second << endl;
        }
    }
	*/
	int count = o.size();
	int memory = count * typelen;
	int mb = memory / 8;
	int mkb = mb / 1024;
	int mmb = mkb / 1024;
    cout << "Size Count: " << count << ", Typelen: " << typelen << ", Memory: " << memory << "b = "
		 << mb << "B = " << mkb << "KB = " << mmb << "MB" << endl;
	return memory;
}

void show_all_result() {
	cout << "Fullsize Counters: ";
	int fullsize_conters_memory = show_result(IN fullsize_counters, kFullCounterWidth);
	int split_counters_memory = 0;
	for (int i = 0; i < kSwitches; i++) {
		cout << "SplitCounters[" << i << "]: "; 
       	split_counters_memory += show_result(IN split_counters[i], kSplitCounterWidth);
    }
	cout << "Controller Counters: ";
	int controller_counters_memory = show_result(IN controller_counters, kFullCounterWidth);
	cout << "Fullsize Counters Memory: " << fullsize_conters_memory << "b, "
		 << "SplitCounters Memory: " << split_counters_memory
		 << "b, Controller Counters Memory: " << controller_counters_memory
		 << "b, Ratio: " << (double)(split_counters_memory) / fullsize_conters_memory * 100 << "%" << endl
		 << "Packets in Controller: " << packets_in_controller << endl;
}

void callback(u_char *args, const struct pcap_pkthdr *pcap_header, const u_char *pcap_content) {
    struct Packet packet;
    Packet *p_packet = &packet;
    init_packet(IN pcap_header, IN &pcap_content, OUT p_packet);
	count_flow(IN p_packet, OUT fullsize_counters);
    count_split_flow(IN p_packet, IN 0);
}

int main(IN int argc, IN char *argv[]) {
    pcap_t *handler;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* file = "";

    if (parse_args(IN argc, IN argv, OUT &file)) {
        fprintf(stderr, "Couldn't parse args.\n");
        return 1;
    }

    // open the file
    if ((handler = pcap_open_offline(file, errbuf)) == NULL) {
        fprintf(stderr, "Couldn't open file: %s\n%s\n", file, errbuf);
        print_usage();
        return 1;
    } else {
		cout << "Open file: " << file << endl;
	}

	// capture the packets
	pcap_loop(handler, -1, callback, NULL);

	show_all_result();

    // close the session
    pcap_close(handler);

    return 0;
}
