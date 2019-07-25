// Author: PZ
// Customize Topology Simulation
// 

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <climits>
#include <cmath>
#include <cassert>
#include <iostream>
#include <unordered_map>
#include <bitset>
#include <pcap.h>

#define IN
#define OUT

using namespace std;

struct Tuple5 {
	unsigned short sport; // source port number
	unsigned short dport; // destination port number
	uint32_t saddr; // source IP address
	uint32_t daddr; // destination IP address
	unsigned char ip_proto; // protocol

	bool operator == (const Tuple5 &o) const {
		return saddr == o.saddr && daddr == o.daddr &&
			sport == o.sport && dport == o.dport &&
			ip_proto == o.ip_proto;
	}
};

struct Tuple5Hash {
	size_t operator () (const Tuple5 &o) const {
		return hash<uint32_t>()(o.daddr) ^ hash<uint32_t>()(o.saddr) ^
			hash<unsigned short>()(o.dport) ^ hash<unsigned short>()(o.sport) ^
			hash<unsigned char>()(o.ip_proto);
	}
};

struct Packet {
	int length;
	struct Tuple5 tuple5;
	int s_net_segment; // source_network_segment;
	int d_net_segment; // destination_network_segment;
	bool flow;
};

const int kSwitches = 12; // how many switches we have for this flow
const int kFullCounterWidth = 28; // must <= 64bits
const int kSplitCounterWidth = 16; // must <= 16bits
// const int kMaxCountersInSwitch = 90000; // how many counters can a split_counters hold
const int kMaxCountersInSwitch = INT_MAX;

typedef unordered_map<struct Tuple5, int, Tuple5Hash> MeterTable;

static MeterTable split_counters[kSwitches], controller_counters;

static long packets_in_controller = 0;

const int topology[12][8] = {
	{ -1, 8, 8, 8, 8, 8, 8, 8 },
	{ 8, -1, 8, 8, 8, 8, 8, 8 },
	{ 9, 9, -1, 9, 9, 9, 9, 9 },
	{ 9, 9, 9, -1, 9, 9, 9, 9 },
	{ 10, 10, 10, 10, -1, 10, 10, 10 },
	{ 10, 10, 10, 10, 10, -1, 10, 10 },
	{ 11, 11, 11, 11, 11, 11, -1, 11 },
	{ 11, 11, 11, 11, 11, 11, 11, -1 },
	{ 0, 1, 9, 9, 10, 10, 11, 11 },
	{ 8, 8, 2, 3, 10, 10, 11, 11 },
	{ 8, 8, 9, 9, 4, 5, 11, 11 },
	{ 8, 8, 9, 9, 10, 10, 6, 7 },
};

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

void show_settings() {
	cout << "The Number of Switches: " << kSwitches << endl
		<< "The Fullsize Counter Width: " << kFullCounterWidth << endl
		<< "The SplitCounter Width: " << kSplitCounterWidth << endl
		<< "How Many Flows Can One Switch Maintain: " << kMaxCountersInSwitch << endl;
}

// get some basic info from the ip packet.
void ip_info_from_pcap(IN const u_char **p_pcap_content, OUT struct Packet *p_packet) {
	struct iphdr *p_ipv4_header = (struct iphdr*)(*p_pcap_content);
	// FIXED: IP address is stored in host byte sequence.
	(p_packet->tuple5).saddr = ntohl(p_ipv4_header->saddr);
	(p_packet->tuple5).daddr = ntohl(p_ipv4_header->daddr);
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

void network_segment(IN OUT struct Packet *p_packet) {
// 	cout << p_packet->tuple5.saddr << endl
// 		<< (p_packet->tuple5.saddr & 7) << endl;
// 	exit(0);
	p_packet->s_net_segment = p_packet->tuple5.saddr >> 29;
	p_packet->d_net_segment = p_packet->tuple5.daddr >> 29;
//  	p_packet->s_net_segment = p_packet->tuple5.saddr & 7;
//  	p_packet->d_net_segment = p_packet->tuple5.daddr & 7;
}

// pre-process the packet.
void init_packet(IN const struct pcap_pkthdr *packet_header, IN const u_char **p_pcap_content, OUT struct Packet *p_packet) {
    p_packet->length = packet_header->len;
	ip_info_from_pcap(IN p_pcap_content, OUT p_packet);
	network_segment(IN OUT p_packet);
	// 	in_addr in = { p_packet->tuple5.saddr };
	// 	cout << bitset<sizeof(uint32_t) * 8>(ntohl(p_packet->tuple5.saddr)) << endl;
	// 	cout << inet_ntoa(in) << endl;
	// 	cout << (int)(p_packet->tuple5).ip_proto << endl;
	//cout << (p_packet->tuple5.saddr >> 29);
//  	exit(0);
	switch (p_packet->tuple5.ip_proto) {
		case IPPROTO_TCP: {
			//cout << "tcp" << endl;
			p_packet->flow = true;
			tcp_info_from_pcap(IN p_pcap_content, OUT p_packet);
			break;
		}
		case IPPROTO_UDP: {
			//cout << "udp" << endl;
			p_packet->flow = true;
			udp_info_from_pcap(IN p_pcap_content, OUT p_packet);
			break;
		}
		default: {
			p_packet->flow = false;
			//cout << (int)p_packet->tuple5.ip_proto << endl;
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

void upload(IN int i, IN Tuple5 o) {
	++packets_in_controller;
	controller_counters[o] += split_counters[i][o];
	split_counters[i][o] = 0;
	split_counters[i].erase(o);
}

int next_switch(IN int current_switch, IN int des_net_segment) {
	return topology[current_switch][des_net_segment];
}

void count_split_flow(IN struct Packet *p_packet, IN int i) {
	if (i == -1) {
		packet_in_controller(IN p_packet); // last switch goto the controller
		return;
	}
	auto it = split_counters[i].find(p_packet->tuple5);
	// new flow
	if (it == split_counters[i].end()) {
		// switch full
		if (split_counters[i].size() >= kMaxCountersInSwitch) {
			count_split_flow(IN p_packet, IN next_switch(IN i, IN p_packet->d_net_segment));
			//if (i == kSwitches - 1) {
			//	packet_in_controller(IN p_packet); // last switch goto the controller
			//} else {
			//	count_split_flow(IN p_packet, IN i + 1); // goto next counter
			//}
		} else {
			// packet too large
			if (p_packet->length >= pow(2, kSplitCounterWidth)) {
				packet_in_controller(IN p_packet); // directly goto the controller
			} else {
				count_flow(IN p_packet, OUT split_counters[i]);
			}
		}
	} else {
		// counter full
		if (it->second + p_packet->length >= pow(2, kSplitCounterWidth)) {
			count_split_flow(IN p_packet, IN next_switch(IN i, IN p_packet->d_net_segment));
			//if (i == kSwitches - 1) {
			//	packet_in_controller(IN p_packet); // last switch goto the controller
			//} else {
			//	count_split_flow(IN p_packet, IN i + 1); // goto next counter
			//}
			upload(IN i, IN p_packet->tuple5);
		} else {
			count_flow(IN p_packet, OUT split_counters[i]);
		}
	}
}

void show_results() {
	int split_counters_memory = 0;
	for (int i = 0; i < kSwitches; i++) {
		int n = split_counters[i].size();
		int m = n * kSplitCounterWidth;
		cout << "SplitCounters[" << i << "]   "
			<< "Flows: " << n << "   "
			<< "Memory: " << m << "b" << endl;
       	split_counters_memory += m;
    }
	cout << "SplitCounters, Total Memory: " << split_counters_memory << "b" << endl;
	int n = controller_counters.size();
	int controller_counters_memory = n * kFullCounterWidth;
	cout << "ControllerCounters,   "
		<< "Flows: " << n << "   "
		<< "Memory: " << controller_counters_memory << "b" << endl;
	cout << "Packets in Controller: " << packets_in_controller << endl;
}

void callback(u_char *args, const struct pcap_pkthdr *pcap_header, const u_char *pcap_content) {
    struct Packet packet;
    Packet *p_packet = &packet;
    init_packet(IN pcap_header, IN &pcap_content, OUT p_packet);
	if (packet.flow) {
		count_split_flow(IN p_packet, IN p_packet->s_net_segment);
	}
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

	show_settings();

	// capture the packets
	pcap_loop(handler, -1, callback, NULL);

	show_results();

    // close the session
    pcap_close(handler);

    return 0;
}
