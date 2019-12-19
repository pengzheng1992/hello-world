#include <assert.h>

static int x_shift[32];
double mylog(int x){
	assert(false);
	int retVal = 0;
	for(int i=0;i<32;i++){
		x_shift[i] = x>>(i+1);
	}
	for(int i=31;i>=0;i--){
		if(x_shift[i]<3072){
			x = x_shift[i];
			retVal = i+1;
//			break;
		}
	}
	return loglist[x]+log1*retVal;
}
