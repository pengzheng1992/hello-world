#ifndef DIAL_PLACE_H_
#define DIAL_PLACE_H_

#include "flow.h"
#include <unordered_set>
#include "common.h"

int place(IN OUT Flow &f);
void multi_place(IN OUT std::unordered_set<Flow, flow_hash> &fs);
void overflow_report(IN OUT Flow &f, IN int i, IN int type);

//for brick and fullsize
// more free more better
int more_free_place(IN OUT Flow &f);
void more_free_multi_place(IN OUT std::unordered_set<Flow, flow_hash> &fs);

// just random
int random_place(IN OUT Flow &f);
void random_multi_place(IN OUT std::unordered_set<Flow, flow_hash> &fs);


#endif // !DIAL_PLACE_H_
