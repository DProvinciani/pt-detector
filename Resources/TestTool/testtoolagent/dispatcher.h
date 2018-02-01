#ifndef _TEST_FRAMEWORK_DISPATCHER_H_
#define _TEST_FRAMEWORK_DISPATCHER_H_

#include "helpers.h"

namespace TestToolAgentCore
{
	DWORD WINAPI ServerThread(LPVOID lp);
	DWORD WINAPI RunTestToolAgent(LPVOID lpParameter);
}

#endif