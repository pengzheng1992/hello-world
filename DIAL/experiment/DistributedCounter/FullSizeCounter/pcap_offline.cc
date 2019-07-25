// Author: PZ
// Only test fullsize counters
//

#include <stdio.h>
#include <string.h>
#include <cmath>
#include <iostream>
#include <unordered_map>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
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
	bool flow;
};

const int kFullCounterWidth = 29; // must <= 64bits

typedef unordered_map<struct Tuple5, int, Tuple5Hash> MeterTable;

static MeterTable fullsize_counters;

void print_usage() {
    fprintf(stderr, "Usage: ./pcap_offline -p filename\n");
}

int parse_args(IN int argc, IN char **argv, OUT const char **file) {
    for (int i = 1; i < argc; ++i) {
        char *arg = argv[i];
        if (!strcmp(arg, "-p") && i + 1 < argc)	{
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

// pre-process the packet.
void init_packet(IN const struct pcap_pkthdr *packet_header, IN const u_char **p_pcap_content, OUT struct Packet *p_packet) {
    p_packet->length = packet_header->len;
	ip_info_from_pcap(IN p_pcap_content, OUT p_packet);
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
}

void count_flow(IN struct Packet *p_packet, OUT MeterTable &o) {
	o[p_packet->tuple5] += p_packet->length;
}

int bit_width(unsigned int n) {
	unsigned int i = 0;
	do {
		++i;
	} while ((n >> i));
	return i;
}

int show_result(IN MeterTable &o, IN int typelen) {
	int max_width = 0;
	int optimal_memory = 0;
	for (auto it = o.begin(); it != o.end(); ++it) {
		/*if (it->second > pow(2, kFullCounterWidth - 1)) {
			printf("proto: %u, sip: %u, dip: %u, sport: %u, dport: %u\n", it->first.ip_proto,
				it->first.saddr, it->first.daddr, it->first.sport, it->first.dport);
			cout << "volume: " << it->second << endl;
		}*/
		int volume_width = bit_width(it->second);
		if (max_width < volume_width) {
			max_width = volume_width;
		}
		optimal_memory += volume_width;
    }
	cout << "Max width: " << max_width << ", optimal memory: " << optimal_memory << endl;
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
	cout << "Fullsize Counters Memory: " << fullsize_conters_memory << "b" << endl;
}

void callback(u_char *args, const struct pcap_pkthdr *pcap_header, const u_char *pcap_content) {
    struct Packet packet;
    Packet *p_packet = &packet;
    init_packet(IN pcap_header, IN &pcap_content, OUT p_packet);
	if (packet.flow) {
		count_flow(IN p_packet, OUT fullsize_counters);
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

	// capture the packets
	pcap_loop(handler, -1, callback, NULL);

	show_all_result();

	// close the session
	pcap_close(handler);

	return 0;
}
