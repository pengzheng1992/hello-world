#ifndef SPLIT_COUTNER_PACKET_H_
#define SPLIT_COUTNER_PACKET_H_

#include "common.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string>

//using namespace std;

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
		return std::hash<uint32_t>()(o.daddr) ^ std::hash<uint32_t>()(o.saddr) ^
			std::hash<unsigned short>()(o.dport) ^ std::hash<unsigned short>()(o.sport) ^
			std::hash<unsigned char>()(o.ip_proto);
	}
};

struct Packet {
	int length;
	struct Tuple5 tuple5;
	unsigned int s_net_segment; // source_network_segment;
	unsigned int d_net_segment; // destination_network_segment;
	bool flow;
};

void ip_info_from_pcap(IN const u_char **p_pcap_content, OUT struct Packet *p_packet);
void tcp_info_from_pcap(IN const u_char **p_pcap_content, OUT struct Packet *p_packet);
void udp_info_from_pcap(IN const u_char **p_pcap_content, OUT struct Packet *p_packet);

#endif // SPLIT_COUTNER_PACKET_H_