#ifndef DIAL_PACKET_H_
#define DIAL_PACKET_H_

#include "common.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string>
#include <set>
#include <cassert>

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
	unsigned int srcSwitch; // source_network_segment;
	unsigned int destSwitch; // destination_network_segment;
	bool flow;
	bool counted;
};

void ip_info_from_pcap(IN const u_char **p_pcap_content, OUT struct Packet *p_packet);
void tcp_info_from_pcap(IN const u_char **p_pcap_content, OUT struct Packet *p_packet);
void udp_info_from_pcap(IN const u_char **p_pcap_content, OUT struct Packet *p_packet);

#endif // !DIAL_PACKET_H_