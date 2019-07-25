// Author: PZ
// Simulation Topology: Cernet
// I give up..

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

const int kSwitches = 20; // how many switches we have for this flow
const int kFullCounterWidth = 28; // must <= 64bits
const int kSplitCounterWidth = 13; // must <= 16bits
const int kMaxCountersInSwitch = INT_MAX; // how many counters can a split_counters hold
//const int kMaxCountersInSwitch = INT_MAX;

typedef unordered_map<struct Tuple5, int, Tuple5Hash> MeterTable;

static MeterTable split_counters[kSwitches], controller_counters;

static long packets_in_controller = 0;

const bool multi_path[20][8] = {
	{ 0, 1, 1, 1, 1, 1, 1, 1 }, // 0
	{ 1, 0, 1, 1, 1, 1, 1, 1 }, // 1
	{ 1, 1, 0, 1, 1, 1, 1, 1 }, // 2
	{ 1, 1, 1, 0, 1, 1, 1, 1 }, // 3
	{ 1, 1, 1, 1, 0, 1, 1, 1 }, // 4
	{ 1, 1, 1, 1, 1, 0, 1, 1 }, // 5
	{ 1, 1, 1, 1, 1, 1, 0, 1 }, // 6
	{ 1, 1, 1, 1, 1, 1, 1, 0 }, // 7
	{ 0, 0, 1, 1, 1, 1, 1, 1 }, // 8
	{ 0, 0, 1, 1, 1, 1, 1, 1 }, // 9
	{ 1, 1, 0, 0, 1, 1, 1, 1 }, // 10
	{ 1, 1, 0, 0, 1, 1, 1, 1 }, // 11
	{ 1, 1, 1, 1, 0, 0, 1, 1 }, // 12
	{ 1, 1, 1, 1, 0, 0, 1, 1 }, // 13
	{ 1, 1, 1, 1, 1, 1, 0, 0 }, // 14
	{ 1, 1, 1, 1, 1, 1, 0, 0 }, // 15
	{ 0, 0, 0, 0, 0, 0, 0, 0 }, // 16
	{ 0, 0, 0, 0, 0, 0, 0, 0 }, // 17
	{ 0, 0, 0, 0, 0, 0, 0, 0 }, // 18
	{ 0, 0, 0, 0, 0, 0, 0, 0 }, // 19
};

/* Edge Switch: 0-7, Aggr Switch: 8-15, Core Switch: 16-19 */
const int topology[36][36] = {
	{ -1, }, // 0 ����
	{6,-1,6,6,6,5,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6}, // 1 ��³ľ��
	{9,9,-1,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9}, // 2 ����
	{4,4,4,-1,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4}, // 3 ����
	{6,6,6,3,-1,5,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6}, // 4 ����
	{6,1,6,6,6,-1,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6}, // 5 ����
	{  }, // 6 ����
	{9,9,9,9,9,9,9,-1,8,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9}, // 7 ���ͺ���
	{9,9,9,9,9,9,9,7,-1,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9}, // 8 ̫ԭ
	{  }, // 9 ����
	{  }, // 10 ����
	{10,10,10,10,10,10,10,10,10,10,10,-1,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10}, // 11 ����
	{10,10,10,10,10,10,10,10,10,10,10,10,-1,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10}, // 12 ������
	{10,10,10,10,10,10,10,10,10,10,10,10,10,-1,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10}, // 13 ����
	{  }, // 14 ���
	{  }, // 15 ʯ��ׯ
	{  }, // 16 �ൺ
	{  }, // 17 ֣��
	{  }, // 18 �人
	{  }, // 19 �Ϸ�
	{  }, // 20 �Ͼ�
	{  }, // 21 �Ϻ�
	{21,21,21,21,21,21,21,21,21,21,21,21,21,21,21,21,21,21,21,21,21,21,-1,21,21,21,21,21,21,21,21,21,21,21,21,21}, // 22 ����
	{  }, // 23 �ϲ�
	{  }, // 24 ��ɳ
	{  }, // 25 ����
	{35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,-1,27,35,35,35,35,35,35,35,35}, // 26 ����
	{35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,26,-1,35,35,35,35,35,35,35,35}, // 27 ����
	{  }, // 28 ����
	{  }, // 29 ����
	{  }, // 30 ��ɽ
	{  }, // 31 ����
	{31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,-1,33,31,31}, // 32 ����
	{31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,32,-1,31,31}, // 33 ����
	{  }, // 34 ����
	{  }, // 35 ����
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
	p_packet->s_net_segment = (p_packet->tuple5.saddr >> 26) * 14/9;
	p_packet->d_net_segment = (p_packet->tuple5.daddr >> 26) * 14/9;
	if (p_packet->d_net_segment > 35 || p_packet->s_net_segment > 35) {
		cout << p_packet->d_net_segment << "," << p_packet->s_net_segment << endl;
		p_packet->flow = false;
	}
}

// pre-process the packet.
void init_packet(IN const struct pcap_pkthdr *packet_header, IN const u_char **p_pcap_content, OUT struct Packet *p_packet) {
    p_packet->length = packet_header->len;
	ip_info_from_pcap(IN p_pcap_content, OUT p_packet);
	// 	in_addr in = { htonl(p_packet->tuple5.saddr) };
	// 	cout << bitset<sizeof(uint32_t) * 8>(p_packet->tuple5.saddr) << endl;
	// 	cout << inet_ntoa(in) << endl;
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
		}
	}
	network_segment(IN OUT p_packet);
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
	int next = topology[current_switch][des_net_segment];
	if (multi_path[current_switch][des_net_segment]) {
		next = next + rand() % 2;
	}
	return next;
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
			upload(IN i, IN p_packet->tuple5);
		} else {
			count_flow(IN p_packet, OUT split_counters[i]);
		}
	}
}

double standard_deviation(const int data[], int n, double average) {
	double sd = 0.0;
	for (int i = 0; i < n; ++i) {
		sd += pow(data[i] - average, 2);
	}
	sd /= n;
	sd = sqrt(sd);
	return sd;
}

void show_results() {
	int split_counters_memory = 0;
	int memories[kSwitches];
	for (int i = 0; i < kSwitches; i++) {
		int n = split_counters[i].size();
		int m = n * kSplitCounterWidth;
		memories[i] = m;
		cout << "SplitCounters[" << i << "]   "
			<< "Flows: " << n << "   "
			<< "Memory: " << m << "b" << endl;
       	split_counters_memory += m;
    }
	double average = static_cast<double>(split_counters_memory) / kSwitches;
	cout << "average: " << average << "b" << endl;
	double sd = standard_deviation(memories, kSwitches, average);
	cout << "standard_deviation: " << sd << "b" << endl;
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
