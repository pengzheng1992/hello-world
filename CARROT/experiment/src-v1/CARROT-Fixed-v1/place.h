#ifndef DIAL_PLACE_H_
#define DIAL_PLACE_H_

#include "flow.h"
#include <unordered_set>
#include "common.h"

// first switch of a flow get the counting rule, for CARROT, carry counting
int carrot_place(IN OUT Flow &f);
void carrot_multi_place(IN OUT std::unordered_set<Flow, flow_hash> &fs);
void carrot_overflow_report(IN OUT Flow &f, IN int i, IN int type);

#endif // !DIAL_PLACE_H_
