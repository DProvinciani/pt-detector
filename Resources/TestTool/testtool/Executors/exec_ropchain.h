#ifndef _EXECUTOR_ROP_CHAIN_H_
#define _EXECUTOR_ROP_CHAIN_H_

#include "../helpers.h"

#define MAX_PAYLOAD_SIZE 20000

class ExecutorROPChain : public Executor
{
public:
	bool Execute(TestCommon::TestData &data);

	ExecutorROPChain() : Executor(TestCommon::ExecutorModeToString(TestCommon::ExecutorsMode::TEST_ROP_CHAIN),
				         TestCommon::ExecutorsMode::TEST_ROP_CHAIN) 
	                     { }

private:

};

#endif