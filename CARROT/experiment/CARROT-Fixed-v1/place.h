#ifndef DIAL_PLACE_H_
#define DIAL_PLACE_H_

#include "flow.h"
#include <unordered_set>
#include "common.h"

int place(IN OUT Flow &f);
void multi_place(IN OUT std::unordered_set<Flow, flow_hash> &fs);
void overflow_report(IN OUT Flow &f, IN int i, IN int type);

// just random
int random_place(IN OUT Flow &f);
void random_multi_place(IN OUT std::unordered_set<Flow, flow_hash> &fs);

// first switch of a flow get the counting rule, for CARROT, carry counting
int carrot_place(IN OUT Flow &f);
void carrot_multi_place(IN OUT std::unordered_set<Flow, flow_hash> &fs);

#endif // !DIAL_PLACE_H_
