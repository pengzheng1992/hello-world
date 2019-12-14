#include "place.h"
#include "flow.h"
#include <unordered_set>
#include <iterator>     // std::back_inserter
#include <vector>       // std::vector
#include <algorithm>    // std::copy, sort
#include <iostream>
#include <list>
#include <utility>
#include "common.h"
#include "switch.h"

using namespace std;

extern vector<Switch*> g_switches;

extern std::unordered_map<Flow, int, flow_hash> g_controller_counters;
extern long packets_in_controller;
extern const int kSplitCounterWidth;

// upload local counter to the controller and reset to zero in a carry way
void carrot_upload(Flow &f) {
	for (auto it = f.switchesPath.begin(); it != f.switchesPath.end(); ++it) {
		if (it->second == 1 || it->second == 2)
		{
		// TODO ... update g_controller_counters[f] ... in a carry way, it's complecated, so I'll do it later......
		// FIXME IMPORTANT!!! IT'S REAL TODO!!!
		//	g_controller_counters[f] += g_switches[it->first]->counters[f] << ((it - f.switchesPath.begin()) * kSplitCounterWidth);
			++packets_in_controller;
			g_switches[it->first]->counters[f] = 0;
			it->second = 1;
		}
	}
}

// place rule for counting a flow in a switch
int carrot_place(IN OUT Flow &f)
{
	// candidate switches
	vector<Switch*> ss;

	// find all switches that havn't installed the rule
//	for (auto o : f.switchesPath) {
//		if (0 == o.second) {
//			ss.push_back(g_switches[o.first]);
//		}
//	}
	
	// find the emptiest one, but CARROT doesn't need that
	//sort(ss.begin(), ss.end(), moreEmpty());

	// find the emptiest one in the downstream switches
	// TODO...

	// find all switches that havn't installed the rule in the downstream
	for (auto o : f.switchesPath) {
		if (0 == o.second)
		{
			ss.push_back(g_switches[o.first]);
		}
		if (1 == o.second)
		{
			ss.clear();
		}
		if (2 == o.second)
		{
			assert(false);
		}
	}
	
	// find the emptiest one, but CARROT (doesn't) needs that
	sort(ss.begin(), ss.end(), moreEmpty());


	// what if all switches has rules
	if (ss.size() == 0) {
		//assert(0);
		carrot_upload(f);
		return 1;
	}

	assert(ss.size() > 0);
	for (auto s : ss)
	{
		int sid = s->identity;
		for (auto it = f.switchesPath.begin(); it != f.switchesPath.end(); ++it)
		{
			if (sid == it->first)
			{
				// find that switch
				auto ps = g_switches[sid];
	
				// if the number of flow entries or counter memories in the switch is sadly full
				if ((ps->counters.size() + 1) > ps->flowTableCountingRuleEntriesTotal ||
					(ps->counters.size() + 1) * ps->counterWidth > ps->counterMemoryTotal)
				{
					break;
				}
	
				assert((ps->counters.size() + 1) <= ps->flowTableCountingRuleEntriesTotal &&
					(ps->counters.size() + 1) * ps->counterWidth <= ps->counterMemoryTotal);
	
				// let me in it
				ps->counters.insert(make_pair(f, 0));
				it->second = 1;
				// set the highest and second highest counter for the flow.
				f.highest2 = f.highest;
				f.highest = sid;
	
				return 0;
			}
		}
	}
//	int sid = ss[0]->identity; // in fact we try to choose the first switch of the routing path of the flow
//	for (auto it = f.switchesPath.begin(); it != f.switchesPath.end(); ++it)
//	{
//		if (sid == it->first)
//		{
//			// find that switch
//			auto ps = g_switches[sid];
//
//			// if the number of flow entries or counter memories in the switch is sadly full
//			if ((ps->counters.size() + 1) > ps->flowTableCountingRuleEntriesTotal ||
//				(ps->counters.size() + 1) * ps->counterWidth > ps->counterMemoryTotal)
//			{
//				// report a full counter 
//				assert(false);
//				carrot_upload(f);
//				return 2;
//			}
//
//			assert((ps->counters.size() + 1) <= ps->flowTableCountingRuleEntriesTotal &&
//				(ps->counters.size() + 1) * ps->counterWidth <= ps->counterMemoryTotal);
//
//			// let me in it
//			ps->counters.insert(make_pair(f, 0));
//			it->second = 1;
//			// set the highest and second highest counter for the flow.
//			f.highest2 = f.highest;
//			f.highest = sid;
//
//			return 0;
//		}
//	}
	carrot_upload(f);
	return 2;
}

// call carrot_place(f)...
void carrot_multi_place(IN OUT std::unordered_set<Flow, flow_hash> &fs)
{
	vector<Flow> v;
	copy(fs.begin(), fs.end(), back_inserter(v));
	sort(v.begin(), v.end(), lessSwitches());
	fs.clear();
	for (Flow f : v) {
		int ret = carrot_place(IN OUT f);
		//TODO switch ret case ...
		switch (ret)
		{
		case 0: // normally counted, then...
			break;
		case 1: // ... 
			break;
		case 2: // switch memory fulled, then...
			break;
		default:
			assert(false);
		}
		//cout << f.switchesPath[0].second << endl;
		fs.insert(f);
		//std::cout << f.nSwitches << " ";
	}
	//for (Flow f : fs) {
	//	cout << f.switchesPath[0].first << " " << f.switchesPath[0].second << endl;
	//}
}

void carrot_overflow_report(IN OUT Flow &f, IN int i, IN int type) {
	switch (type)
	{
	case 1:
		// a packet leads to an overflow
		// if the highest or the 2nd highest counter is full, then a new highest counter needs creating
		// the 2nd highest needs new counter is for buffering, is to pre-duplicate the counting rule.
		if (f.switchesPath[i].first == f.highest)
		{
			carrot_place(IN OUT f);
		}
		if (f.switchesPath[i].first == f.highest2)
		{
			assert(1 == f.switchesPath[i].second);
			assert(f.highest >= 0);
			carrot_place(IN OUT f);
		
		}
		break;
	case 2:
		assert(false);
		//assert(f.switchesPath[i].second == 1);

		////TODO
		//// a packet encounters a full switch
		//// if sadly full
		//// report a full counter 
		//auto ps = g_switches[f.switchesPath[i].first];
		//Flow fff = clean_some_memory(g_controller_counters, ps);
		//f.switchesPath[i].second = 1;
		//// and let me in it
		//ps->counters.insert(make_pair(f, 0));
		//// give that flow another place to count
		//place(fff);
		////assert(false);
		break;
	case 3:
		// highest counter start working, request new counter.
		assert(false);
		carrot_place(IN OUT f);
		break;
	default:
		break;
	}
}
