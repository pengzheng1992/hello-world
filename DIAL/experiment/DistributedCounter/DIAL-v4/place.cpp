#include "place.h"
#include "flow.h"
#include <time.h>       /* time */
#include <unordered_set>
#include <iterator>     // std::back_inserter
#include <vector>       // std::vector
#include <algorithm>    // std::copy, sort
#include <iostream>
#include <list>
#include <utility>
#include "common.h"
#include "switch.h"

//#define DEBUG_PLACE

using namespace std;

extern vector<Switch*> g_switches;

extern std::unordered_map<Flow, int, flow_hash> g_controller_counters;
extern long packets_in_controller;

//Flow clean_some_memory(std::unordered_map<Flow, int, flow_hash> &controller_counters, Switch *ps) {
//#ifdef DEBUG_PLACE
//	cout << "clean_some_memory, id: " << ps->identity << endl;
//#endif // DEBUG_PLACE
//	assert(ps->counters.size() > 0);
//	srand(unsigned(time(NULL)));
//	int iSecret = rand() % ps->counters.size();
//	int i = 0;
//	auto it = ps->counters.begin();
//	auto maxit(it);
//	for (; it != ps->counters.end(); ++it) {
//		if (i >= iSecret) {
//			maxit = it;
//			break;
//		}
//		++i;
//		/*if (it->first.nSwitches > maxit->first.nSwitches)
//		{
//			maxit = it;
//		}
//		else if (it->first.nSwitches == maxit->first.nSwitches) {
//			srand(unsigned(time(NULL)));
//			int iSecret = rand() % 2;
//			if (iSecret == 0)
//			{
//				maxit = it;
//			}
//		}*/
//	}
//
//	Flow f(maxit->first);
//	g_controller_counters[maxit->first] += maxit->second;
//#ifdef DEBUG_PLACE
//	cout << "ps->counters.size1:" << ps->counters.size() << endl;
//#endif // DEBUG_PLACE
//
//	ps->counters.erase(maxit);
//#ifdef DEBUG_PLACE
//	cout << "ps->counters.size2:" << ps->counters.size() << endl;
//#endif // DEBUG_PLACE
//	auto vit = f.switchesPath.begin();
//	for (;vit != f.switchesPath.end(); ++vit) {
//		if (vit->first == ps->identity) {
//			vit->second = 0;
//			break;
//		}
//	}
//	return f;
//	//cout << maxit->second << " ";
//}

void upload(Flow &f) {
	for (auto it = f.switchesPath.begin(); it != f.switchesPath.end(); ++it) {
		if (it->second == 1 || it->second == 2)
		{
			g_controller_counters[f] += g_switches[it->first]->counters[f];
			++packets_in_controller;
			g_switches[it->first]->counters[f] = 0;
			it->second = 1;
		}
	}
}

int place(IN OUT Flow &f)
{
	vector<Switch*> ss;
	for (auto o : f.switchesPath) {
		if (0 == o.second) {
			ss.push_back(g_switches[o.first]);
		}
	}
	sort(ss.begin(), ss.end(), moreEmpty());
	if (ss.size() == 0) {
		//what if all switches has rules
		upload(f);
		return 1;
	}
	assert(ss.size() > 0);
	int sid = ss[0]->identity;
	for (auto it = f.switchesPath.begin(); it != f.switchesPath.end(); ++it) {
		if (sid == it->first) {
			auto ps = g_switches[sid];
			//vector<Flow> vf;
			if ((ps->counters.size() + 1) > ps->flowTableCountingRuleEntriesTotal ||
				(ps->counters.size() + 1) * ps->counterWidth > ps->counterMemoryTotal) {
				// if sadly full
				// report a full counter 
				upload(f);
				return 2;
				//Flow f  = clean_some_memory(g_controller_counters, ps);
#ifdef DEBUG_PLACE
				cout << "f.tuple5.saddr: " << f.tuple5.saddr << endl;
#endif // DEBUG_PLACE
				//vf.push_back(f);
			}
			assert((ps->counters.size() + 1) <= ps->flowTableCountingRuleEntriesTotal &&
				(ps->counters.size() + 1) * ps->counterWidth <= ps->counterMemoryTotal);
			// and let me in it
			ps->counters.insert(make_pair(f, 0));
			it->second = 1;
			// give that flow another place to count
			/*for (auto it = vf.begin(); it != vf.end(); ++it)
			{
				place(*it);
			}*/
			return 0;
			//break;
		}
	}
	return 3;
}

void multi_place(IN OUT std::unordered_set<Flow, flow_hash> &fs)
{
	vector<Flow> v;
	copy(fs.begin(), fs.end(), back_inserter(v));
	sort(v.begin(), v.end(), lessSwitches());
	fs.clear();
	for (Flow f : v) {
		//int ret = place(IN OUT f);
		place(IN OUT f);
		//if (ret == 1) {

		//}
		////cout << f.switchesPath[0].second << endl;
		//assert(ret == 0);
		fs.insert(f);
		//std::cout << f.nSwitches << " ";
	}
	//for (Flow f : fs) {
	//	cout << f.switchesPath[0].first << " " << f.switchesPath[0].second << endl;
	//}
}

void overflow_report(IN OUT Flow &f, IN int i, IN int type) {
	if (1 == type)
	{
		// a packet leads to an overflow
		f.switchesPath[i].second = 2;
		place(IN OUT f);
	}
	else if (2 == type)
	{
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
	}
}
