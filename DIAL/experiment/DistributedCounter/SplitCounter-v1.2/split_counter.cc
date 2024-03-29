// Author: PZ
// Simulation Topology: Cernet
//

#include <stdio.h>
#include <string.h>
#include <climits>
#include <cmath>
#include <cassert>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <bitset>
#include <pcap.h>
#include "topo.h"
#include "packet.h"
#include "common.h"

using namespace std;

const int kSwitches = 36; // how many switches we have for this flow
const int kFullCounterWidth = 28; // must <= 64bits
const int kSplitCounterWidth = 13; // must <= 16bits
const int kMaxCountersInSwitch = 30000; // how many counters can a split_counters hold
//const int kMaxCountersInSwitch = INT_MAX;

vector<vector<int>> path(36, vector<int>(36));

typedef unordered_map<struct Tuple5, int, Tuple5Hash> MeterTable;

static MeterTable split_counters[kSwitches], controller_counters;

static long packets_in_controller = 0;

void print_usage() {
    fprintf(stderr, "Usage: ./pcap_offline -p pcap_filename -t topo_filename\ntopofile format: node_number, edge_number then source destination pair for each edge\n");
}

int parse_args(IN int argc, IN char **argv, OUT const char **pcap_file, OUT const char **topo_file) {
    for (int i = 1; i < argc; ++i) {
        char *arg = argv[i];
        if (!strcmp(arg, "-p") && i + 1 < argc)	{
            *pcap_file = argv[++i];
        }
		else if (!strcmp(arg, "-t") && i + 1 < argc) {
			*topo_file = argv[++i];
        }
		else {
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

void network_segment(IN OUT struct Packet *p_packet) {
	
	p_packet->s_net_segment = (p_packet->tuple5.saddr >> 27) * 9/7;
	p_packet->d_net_segment = (p_packet->tuple5.daddr >> 27) * 9/7;
	if (p_packet->d_net_segment > 35 || p_packet->s_net_segment > 35) {
// 		cout << p_packet->s_net_segment << "," << p_packet->d_net_segment << endl;
		p_packet->flow = false;
		//cout << p_packet->tuple5.saddr << "," << p_packet->tuple5.daddr << endl;
		//cout << p_packet->tuple5.sport << "," << p_packet->tuple5.dport << endl;
// 		exit(0);
	}
	if (p_packet->d_net_segment == 8 || p_packet->s_net_segment == 8 ||
		p_packet->d_net_segment == 13 || p_packet->s_net_segment == 13 || 
		p_packet->d_net_segment == 17 || p_packet->s_net_segment == 17 || 
		p_packet->d_net_segment == 22 || p_packet->s_net_segment == 22 || 
		p_packet->d_net_segment == 26 || p_packet->s_net_segment == 26) {
		cout << p_packet->s_net_segment << "," << p_packet->d_net_segment << endl;
		//p_packet->flow = false;
		//cout << p_packet->tuple5.saddr << "," << p_packet->tuple5.daddr << endl;
		//cout << p_packet->tuple5.sport << "," << p_packet->tuple5.dport << endl;
		// 		exit(0);
	}
}

// pre-process the packet.
void init_packet(IN const struct pcap_pkthdr *packet_header, IN const u_char **p_pcap_content, OUT struct Packet *p_packet) {
    p_packet->length = packet_header->len;
	ip_info_from_pcap(IN p_pcap_content, OUT p_packet);
	//in_addr in = { htonl(p_packet->tuple5.saddr) };
	//cout << bitset<sizeof(uint32_t) * 8>(p_packet->tuple5.saddr) << endl;
	//cout << inet_ntoa(in) << endl;
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
	if (current_switch==des_net_segment) {
		return -1;
	}
	int next = path[current_switch][des_net_segment];
	//cout << current_switch << " " << des_net_segment << " " << next << ",";
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
    const char* pcap_file = "";
	const char* topo_file = "";

    if (parse_args(IN argc, IN argv, OUT &pcap_file, OUT &topo_file)) {
        fprintf(stderr, "Couldn't parse args.\n");
        return 1;
    }
	//int n_num = nodes_number(topo_file);
	//vector<vector<int>> path(n_num, vector<int>(n_num));
	cout << "Open topology file: " << topo_file << endl;
	topo(IN topo_file, OUT path);
    // open the pcap file
    if ((handler = pcap_open_offline(pcap_file, errbuf)) == NULL) {
        fprintf(stderr, "Couldn't open file: %s\n%s\n", pcap_file, errbuf);
        print_usage();
        return 1;
    } else {
		cout << "Open pcap file: " << pcap_file << endl;
	}

	show_settings();

	// capture the packets
	pcap_loop(handler, -1, callback, NULL);

	show_results();

    // close the session
    pcap_close(handler);

    return 0;
}