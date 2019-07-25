#ifndef DIAL_PLACE_H_
#define DIAL_PLACE_H_

#include "flow.h"
#include <unordered_set>
#include "common.h"

int place(IN OUT Flow &f);
void multi_place(IN OUT std::unordered_set<Flow, flow_hash> &fs);
void overflow_report(IN OUT Flow &f, IN int i, IN int type);


#endif // !DIAL_PLACE_H_
