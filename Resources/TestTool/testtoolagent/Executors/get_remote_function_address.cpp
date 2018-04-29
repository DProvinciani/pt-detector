#include "executors.h"

#pragma warning(disable : 4996)
#pragma runtime_checks( "", off )

int TestToolAgentExecutors::GetRemoteFunctionAddress(unsigned char* ropChain)
{
    TestCommon::Xtrace(L"[TestToolAgent] Entering to GetRemoteFunctionAddress!");

    if (ropChain == nullptr)
        return 0;

    int ret = 0;
    DWORD* functionAddress = nullptr;

    std::string functionName((char*)ropChain);

    if (functionName == "WinExec") {
        functionAddress = (DWORD*)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), functionName.c_str());
    }

    if (functionAddress != NULL)
        memcpy(ropChain, &functionAddress, 4);
    else
        TestCommon::Xtrace(L"[TestToolAgent] Error getting function address");

    TestCommon::Xtrace(L"[TestToolAgent] Leaving GetRemoteFunctionAddress!");

    return sizeof(DWORD);
}
