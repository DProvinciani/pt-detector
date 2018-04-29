#ifndef _TEST_FRAMEWORK_EXECUTORS_H_
#define _TEST_FRAMEWORK_EXECUTORS_H_

#include "../../common/common.h"

namespace TestToolAgentExecutors
{
	int ExecROPChain(unsigned char* data);
    int GetRemoteFunctionAddress(unsigned char* data);
}

#endif