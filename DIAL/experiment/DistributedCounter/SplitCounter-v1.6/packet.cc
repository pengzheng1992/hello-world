#include "packet.h"

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