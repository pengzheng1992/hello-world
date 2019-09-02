#ifndef DIAL_SWITCH_H_
#define DIAL_SWITCH_H_

#include <unordered_map>
#include "flow.h"

class Switch {
public:
	int identity;
	unsigned int counterMemoryTotal;
	//int counterMemoryLeft;
	unsigned int flowTableCountingRuleEntriesTotal;
	//int flowTableCountingRuleEntriesLeft;
	std::unordered_map<Flow, int, flow_hash> counters;
	int counterWidth;

public:
	Switch() {};
	~Switch() {};
	Switch(int id) : identity(id) {	};
	Switch(int id, int mem, int rules) :
		identity(id), counterMemoryTotal(mem), flowTableCountingRuleEntriesTotal(rules) {	};
	Switch(int id, int mem, int rules, int width) :
		identity(id), counterMemoryTotal(mem), flowTableCountingRuleEntriesTotal(rules), counterWidth(width) {	};
};

struct moreEmpty {
	bool operator () (const Switch* lhs, const Switch* rhs)  const {
		return lhs->counters.size() < rhs->counters.size();
	}
};
#endif // !DIAL_SWITCH_H_
