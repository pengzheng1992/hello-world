#ifndef DIAL_FLOW_H_
#define DIAL_FLOW_H_

#include "packet.h"
//#include "switch.h"
#include <vector>
#include <utility>      // std::pair

class Flow
{
public:
	Flow() {};

	~Flow() {};

	Flow(Tuple5 t5) : tuple5(t5) {	};

	Flow(Tuple5 t5, unsigned int s, unsigned int d) :
		tuple5(t5), srcSwitch(s), destSwitch(d) {	};

	bool operator == (const Flow &o) const {
		return tuple5 == o.tuple5;
	}

	bool operator < (Flow const & o) const {
		return tuple5 < o.tuple5;
	}

public:
	Tuple5 tuple5;
	unsigned int srcSwitch; // source_network_segment;
	unsigned int destSwitch; // destination_network_segment;
	/* The first int indicates the Switches sequence of the flow,
	   start with srcSwitch, end with destSwitch.
	   The second int indicates: 0, the switch doesn't contain the counting rule in it;
								 1, the switch contains the counting rule in it, and is working;
								 2, the switch contains the counting rule in it, but has been full.
	*/
	vector<pair<int, int>> switchesPath;
	int nSwitches; // sizeof switchesPath
};

struct lessSwitches {
	bool operator () (const Flow & lhs, const Flow & rhs)  const {
		return lhs.nSwitches < rhs.nSwitches;
	}
};

struct flow_hash {
	size_t operator () (const Flow &o) const {
		return Tuple5Hash()(o.tuple5);
	}
};

#endif // !DIAL_FLOW_H_
