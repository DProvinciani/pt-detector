#ifndef _TEST_FRAMEWORK_DISPATCHER_H_
#define _TEST_FRAMEWORK_DISPATCHER_H_

#include "helpers.h"

namespace TestFrameworkCore
{
	DWORD WINAPI ServerThread(LPVOID lp);
	DWORD WINAPI RunTestFramework(LPVOID lpParameter);
}

#endif