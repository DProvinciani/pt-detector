#include "helpers.h"
#include "dispatcher.h"

#pragma comment(lib, "Ws2_32.lib")

DWORD WINAPI TestToolAgentCore::RunTestToolAgent(LPVOID lpParameter)
{
	bool ret = false;
	HANDLE coreThread = INVALID_HANDLE_VALUE;
	WORD wVersionRequested = MAKEWORD(1, 0);
	WSADATA wsaData;
	WSAStartup(wVersionRequested, &wsaData);
	srand(GetTickCount());

	DWORD currentPID = GetCurrentProcessId();
	std::wstring serverName(TestCommon::PRE_CHANNEL_TOKEN + std::to_wstring(currentPID));

	dipc::server testToolAgentServer(serverName);
	testToolAgentServer.route(TestCommon::ExecutorsMode::TEST_ROP_CHAIN, TestToolAgentExecutors::ExecROPChain);
    testToolAgentServer.route(TestCommon::ExecutorsMode::GET_REMOTE_FUNCTION_ADDRESS, TestToolAgentExecutors::GetRemoteFunctionAddress);

	testToolAgentServer.run();

	return ret;
}