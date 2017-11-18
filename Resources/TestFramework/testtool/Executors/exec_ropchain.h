#ifndef _EXECUTOR_ROP_CHAIN_H_
#define _EXECUTOR_ROP_CHAIN_H_

#include "../helpers.h"

#define MAX_PAYLOAD_SIZE 20000

class ExecutorROPChain : public Executor
{
public:
	bool Execute(TestCommon::TestData &data);
	void initGadgetDB();

	ExecutorROPChain() :
		Executor(TestCommon::TestExecutorsToString(TestCommon::TestExecutorsMode::TEST_ROP_CHAIN),
				 TestCommon::TestExecutorsMode::TEST_ROP_CHAIN) 
	{
		initGadgetDB();
	}

private:
	std::map <std::string, std::string> gadget_db;

};

#endif