// Author: PZ
// update: controller counting result
// 

#include <climits>
#include <cmath>
#include <cassert>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <map>
#include <unordered_set>
#include <bitset>
#include <utility>      // std::pair
#include <pcap.h>
#include "topo.h"
#include "packet.h"
#include "common.h"
#include "parse_args.h"
#include "place.h"
#include "switch.h"
#include "flow.h"
#include "statistics.h"

using namespace std;

// NEED SETTING!!!
const int kSwitches = 38; // how many switches we have in the topology file.
//const int kFullCounterWidth = 28; // maybe <= 64bits. Related to traffic file
const int kSplitCounterWidth = 13; // maybe <= 16bits
//const int MEMINSWITCH = INT_MAX;
////const int kMaxCountersInSwitch = 30000; // how many counters can a split_counters hold
//const int kMaxCountersInSwitch = INT_MAX / kSplitCounterWidth;
const int kMaxCountersInSwitch = 30000;
const int MEM = kMaxCountersInSwitch * kSplitCounterWidth;
const int RULES = kMaxCountersInSwitch;

//static vector<Switch> Switches;

static unordered_set<Flow, flow_hash> flows;

vector<vector<int>> nextHop(kSwitches, vector<int>(kSwitches));

//typedef unordered_map<struct Tuple5, int, Tuple5Hash> MeterTable;
//typedef multimap<struct Tuple5, int> MeterTable;

// static MeterTable split_counters[kSwitches], controller_counters;
//static MeterTable split_counters[kSwitches];
vector<Switch*> g_switches;

//static unordered_map<struct Tuple5, int, Tuple5Hash> controller_counters;
std::unordered_map<Flow, int, flow_hash> g_controller_counters;


long packets_in_controller = 0;

//void show_settings() {
//	cout << "The Number of Switches: " << kSwitches << endl
//		//<< "The Fullsize Counter Width: " << kFullCounterWidth << endl
//		<< "The SplitCounter Width: " << kSplitCounterWidth << endl
//		<< "How Many Flows Can One Switch Maintain: " << kMaxCountersInSwitch << endl;
//}

unsigned int ip2ns(uint32_t ip) {
	assert(kSwitches > 1);
	int exp;
	double a = frexp(kSwitches, &exp);
	//cout << a << " " << exp << endl;
	unsigned int ns = static_cast<uint32_t>(ip / 7 * a) >> (29 - exp);
	return ns;
}

void find_src_dest_switch(IN OUT struct Packet *p_packet) {
	p_packet->srcSwitch = ip2ns(p_packet->tuple5.saddr);
	p_packet->destSwitch = ip2ns(p_packet->tuple5.daddr);
	/*p_packet->srcSwitch = (p_packet->tuple5.saddr / 14 * 9) >> 26;
	p_packet->destSwitch = (p_packet->tuple5.daddr / 14 * 9) >> 26;*/
	if (p_packet->destSwitch >= kSwitches || p_packet->srcSwitch >= kSwitches) {
 		//cout << p_packet->srcSwitch << "," << p_packet->destSwitch << endl;
		p_packet->flow = false;
		//cout << p_packet->tuple5.saddr << "," << p_packet->tuple5.daddr << endl;
		//cout << p_packet->tuple5.sport << "," << p_packet->tuple5.dport << endl;
// 		exit(0);
	}
}

// pre-process the packet.
void init_packet(IN const struct pcap_pkthdr *packet_header, IN const u_char **p_pcap_content, OUT struct Packet *p_packet) {
    p_packet->length = packet_header->len;
	p_packet->counted = false;
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
			//cout << static_cast<int>(p_packet->tuple5.ip_proto) << " ";
			p_packet->flow = false;
		}
	}
	//find_src_dest_switch(IN OUT p_packet);
}

void show_results() {
	int split_counters_memory = 0;
	int memories[kSwitches];
	for (int i = 0; i < kSwitches; i++) {
		int n = g_switches[i]->counters.size();
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
	/*int n = controller_counters.size();
	int controller_counters_memory = n * kFullCounterWidth;
	cout << "ControllerCounters,   "
		<< "Flows: " << n << "   "
		<< "Memory: " << controller_counters_memory << "b" << endl;*/
	cout << "Packets in Controller: " << packets_in_controller << endl;
}

void show_switches() {
	cout << "size of g_switches:" << g_switches.size() << endl;
	for (auto o : g_switches) {
		cout << "SwitchID: " << o->identity << ", "
			<< "MEM_TOTAL: " << o->counterMemoryTotal << ", "
			<< "RULES_TOTAL: " << o->flowTableCountingRuleEntriesTotal << ", "
			<< "current counters' number: " << o->counters.size() << endl;
	}
}

int count_in_the_ith_switch(IN OUT Flow &ff, IN OUT struct Packet *p_packet, IN int i) {
	assert(1 == ff.switchesPath[i].second);
	int l = p_packet->length;
	//cout << ff.switchesPath[i].first << endl;
	//switch
	auto ps = g_switches[ff.switchesPath[i].first];
	int width = ps->counterWidth;
	//counter
	auto it = ps->counters.find(ff);
	// new flow to count in this switch
	if (it == ps->counters.end()) {
		// switch full
		if ((ps->counters.size() + 1) * width > ps->counterMemoryTotal ||
			(ps->counters.size() + 1) > ps->flowTableCountingRuleEntriesTotal) {
			//cout << "counters.size: " << ps->counters.size() << ", width: " << width
			//	<< ", RULE: " << ps->flowTableCountingRuleEntriesTotal
			//	<< ", MEMORY: " << ps->counterMemoryTotal << endl;
			assert(false);
			//todo
			return 2;
			/*place(ff);
			return 1;*/
		} else {
			// packet too large
			if (l >= pow(2, kSplitCounterWidth)) {
				assert(false);
				//packet_in_controller(IN p_packet); // directly goto the controller
			} else {
				//first packet of the flow counted in this switch
				ps->counters.insert(make_pair(ff, l));
				return 0;
			}
		}
	}
	// old flow in this switch
	else {
		// counter full
		if (it->second + l >= pow(2, width)) {
			return 1;
		} else {
			it->second += l;
			return 0;
		}
	}
}

void count_flow(IN OUT Flow &ff, IN OUT struct Packet *p_packet) {
	//the ith switch pair in switchesPath
	for (int i = 0; i < ff.nSwitches; i++)
	{
		if (p_packet->counted)
		{
			break;
		}
		int hasRule = ff.switchesPath[i].second;
		//if (hasRule != 0)
		//	cout <<hasRule;
		if (0 == hasRule) {
			continue;
		} else if (2 == hasRule) {
			continue;
		} else {
			assert(1 == hasRule);
			int overflow = count_in_the_ith_switch(IN OUT ff, IN OUT p_packet, IN i);
			if (!overflow) {
				assert(0 == overflow);
				p_packet->counted = true;
				break;
			}
			else if (1 == overflow)
			{
				assert(1 == overflow);
				overflow_report(IN OUT ff, IN i, IN 1);
			}
			else
			{
				assert(2 == overflow);
				//assert(false);
				overflow_report(IN OUT ff, IN i, IN 2);
			}
		}
	}
	assert(p_packet->counted = true);
}


void count_packet(IN OUT struct Packet *p_packet) {
	//p_packet_match_flow();
	Flow f(p_packet->tuple5);
	auto it = flows.find(f);
	if (it == flows.end()) {
		cout << "flow not found" << endl;
		assert(false);
		return;
	}
	Flow ff = *it;
	//cout << "s&d&n: " << ff.srcSwitch << " " << ff.destSwitch << " " << ff.nSwitches << endl;
	//int l = p_packet->length;
	count_flow(IN OUT ff, IN OUT p_packet);
}

void callback_countflows(u_char *args, const struct pcap_pkthdr *pcap_header, const u_char *pcap_content) {
	struct Packet packet;
	Packet *p_packet = &packet;
    init_packet(IN pcap_header, IN &pcap_content, OUT p_packet);
	find_src_dest_switch(IN OUT p_packet);

	if (packet.flow) {
		count_packet(IN p_packet);
	}
}

void find_routing_path(IN OUT Flow &f) {
	int dest = f.destSwitch;
	vector<pair<int, int>> switches;
	for (int currentSwitch = f.srcSwitch; currentSwitch != dest; currentSwitch = nextHop[currentSwitch][dest]) {
		switches.push_back(make_pair(currentSwitch, 0));
	}
	switches.push_back(make_pair(dest, 0));
	f.switchesPath = switches;
	f.nSwitches = switches.size();
}

void find_init_flows(IN struct Packet *p_packet) {
	Flow f(p_packet->tuple5, p_packet->srcSwitch, p_packet->destSwitch);
	if (flows.count(f)) {
		return;
	}
	find_routing_path(IN OUT f);
	flows.insert(f);
	//cout << f.nSwitches << endl;
	//cout << p_packet->srcSwitch << ", " << p_packet->destSwitch << endl;
}

void callback_findinitflows(u_char *args, const struct pcap_pkthdr *pcap_header, const u_char *pcap_content) {
	struct Packet packet;
	Packet *p_packet = &packet;
	init_packet(IN pcap_header, IN &pcap_content, OUT p_packet);
	find_src_dest_switch(IN OUT p_packet);
	
	if (packet.flow) {
		find_init_flows(IN p_packet);
	}
}

void create_switches() {
	for (size_t i = 0; i < kSwitches; i++)
	{
		Switch *ps = new Switch(i, MEM, RULES, kSplitCounterWidth);
		g_switches.push_back(ps);
	}
}

void collect_statistics() {
	//vector<Switch*> g_switches;
	//std::unordered_map<Flow, int, flow_hash> g_controller_counters;
	for (Switch* ps : g_switches) {
		for (auto c : ps->counters) {
			g_controller_counters[c.first] += c.second;
		}
	}
}

long long verification() {
	long long sum = 0;
	for (auto c : g_controller_counters) {
		sum += c.second;
	}
	return sum;
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

	// process topology file to get the nextHop routing path of each switch in the topology.
	cout << "Open topology file: " << topo_file << endl;
	topo(IN topo_file, OUT nextHop);

	// find init flows
	if ((handler = pcap_open_offline(pcap_file, errbuf)) == NULL) {
		fprintf(stderr, "Couldn't open file: %s\n%s\n", pcap_file, errbuf);
		print_usage();
		return 1;
	} else {
		cout << "Open pcap file: " << pcap_file << endl;
	}
	pcap_loop(handler, -1, callback_findinitflows, NULL);
	pcap_close(handler);
	cout << "There are " << flows.size() << " Flows in the network." << endl;

	create_switches();
	//show_switches();

	multi_place(IN OUT flows);
	//test multi_place
	//for (Flow f : flows) {
	//	//for (auto a : f.switchesPath)
	//	//cout << f.switchesPath[0].first << " " << f.switchesPath[0].second << endl;
	//}
	multi_place(IN OUT flows);
	// counting...
    // open the pcap file
    if ((handler = pcap_open_offline(pcap_file, errbuf)) == NULL) {
        fprintf(stderr, "Couldn't open file: %s\n%s\n", pcap_file, errbuf);
        print_usage();
        return 1;
    } else {
		cout << "Open pcap file: " << pcap_file << endl;
	}

	//show_settings();

	// counting...
	// capture the packets
	pcap_loop(handler, -1, callback_countflows, NULL);

	collect_statistics();
	cout << "Total sum: " << verification() << endl;

	//show_switches();
	show_results();

    // close the session
    pcap_close(handler);
    return 0;
}