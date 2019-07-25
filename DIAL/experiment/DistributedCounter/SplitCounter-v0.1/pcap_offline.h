#ifndef PCAP_OFFLINES_H_
#define PCAP_OFFLINES_H_

#include <stdint.h>
#include <cassert>
#include <map>

#define IN
#define OUT

using namespace std;

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
	uint16_t eth_proto;
	struct Tuple5 tuple5;
	bool ip;
};

template <typename T> inline void count_flow(IN struct Packet *ppacket, OUT map<struct Tuple5, T> &o) {
    assert(ppacket->ip == true);
    o[ppacket->tuple5] += ppacket->length;
}

#endif
