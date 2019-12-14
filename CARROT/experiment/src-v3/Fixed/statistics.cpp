#include "statistics.h"
#include <cmath>

double standard_deviation(const int data[], int n, double average) {
	double sd = 0.0;
	for (int i = 0; i < n; ++i) {
		sd += pow(data[i] - average, 2);
	}
	sd /= n;
	sd = sqrt(sd);
	return sd;
}