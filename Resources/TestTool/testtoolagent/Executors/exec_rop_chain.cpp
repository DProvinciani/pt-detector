#include "executors.h"

#define CHAIN_BUFFER_SIZE 128

int TestToolAgentExecutors::ExecROPChain(unsigned char* ropChain)
{
	int ret = 0;

	TestCommon::Xtrace(L"[TestToolAgent] Hello from ExecROPChain!");

	unsigned char ropChainOnStack[CHAIN_BUFFER_SIZE] = { 0 };

	// Copying the rop chain into the stack
	for (int i = 0; i < CHAIN_BUFFER_SIZE; i++)
		ropChainOnStack[i] = *(ropChain + i);

	int(*func)();
	func = (int(*)()) ((ropChainOnStack[0] | '\0') | 
		              ((ropChainOnStack[1] << 8) | '\0') | 
		              ((ropChainOnStack[2] << 16) | '\0') | 
		              ((ropChainOnStack[3] << 24) | '\0'));
	(int)(*func)();

	if (ropChainOnStack[0]) { //use local variables so compiler won't remove them
		return 0;
	}

	return ret;
}
