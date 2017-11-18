#include "helpers.h"
#include "dispatcher.h"

#pragma comment(lib, "Ws2_32.lib")

DWORD WINAPI TestFrameworkCore::RunTestFramework(LPVOID lpParameter)
{
	bool ret = false;
	HANDLE coreThread = INVALID_HANDLE_VALUE;
	WORD wVersionRequested = MAKEWORD(1, 0);
	WSADATA wsaData;
	WSAStartup(wVersionRequested, &wsaData);
	srand(GetTickCount());

	DWORD currentPID = GetCurrentProcessId();
	std::wstring serverName(TestCommon::PRE_CHANNEL_TOKEN + std::to_wstring(currentPID));

	dipc::server testFrameworkServer(serverName);
	testFrameworkServer.route(TestCommon::TestExecutorsMode::TEST_ROP_CHAIN, TestFrameworkExecutors::ExecROPChain);

	testFrameworkServer.run();

	return ret;
}