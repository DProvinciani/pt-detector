// dllmain.cpp : Defines the entry point for the DLL application.
#include "helpers.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	HANDLE threadHandle = INVALID_HANDLE_VALUE;
	DWORD currentPID = GetCurrentProcessId();
	BOOL ret = true;
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
			threadHandle = CreateThread(NULL, 0, TestToolAgentCore::RunTestToolAgent, NULL, 0, NULL);
			if (threadHandle != INVALID_HANDLE_VALUE)
			{
				TestCommon::Xtrace(L"[TestToolAgent] Core framework was launched at PID: %d", currentPID);
				ret = true;
			}
			else
			{
				TestCommon::Xtrace(L"[TestToolAgent] There was a problem creating core framework at  PID: %d", currentPID);
			}
			CloseHandle(threadHandle);
			break;
		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return ret;
}

