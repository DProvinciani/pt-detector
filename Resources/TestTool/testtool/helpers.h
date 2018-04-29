#ifndef _HELPERS_H_
#define _HELPERS_H_

#include "../common/common.h"
#include "../common/ipcpp.h"
#include "cmdparser.h"
#include "executor.h"
#include "executorManager.h"
#include "Executors/exec_ropchain.h"

namespace TestToolHelpers
{
	int ToInteger(const std::wstring &st);
	bool IsValidFile(const std::wstring &fileName);
	bool GetFullPathToFile(const std::wstring &fileName, std::wstring &fullPathFile);
	bool IsNumber(const std::wstring& str);
	bool GetFileToInjectSize(const std::wstring& file, DWORD &size);
	bool ReadFileToInjectInBuffer(const std::wstring& file, const DWORD &fileSize, LPVOID lpBuffer, DWORD &bytesRead);
	bool IsTestDataValid(TestCommon::TestData &data);
    bool InjectIntoRemoteProcess(const std::wstring &dllToInject, const std::wstring &targetPIDToInject, HANDLE& hProcess);
    bool WriteRemoteProcessMemory(const HANDLE hProcess, const LPVOID &buffer, const DWORD &bufferSize, LPVOID &remoteBufferAddr);

	class IPCClient
	{
	public:
		TestCommon::ARRAYBYTE SendRequest(TestCommon::ExecutorsMode executorID, unsigned char *dataPayload, int dataSize);

		IPCClient()
		{
			m_client = new dipc::client();
		}

		IPCClient(const std::wstring &channelID) : m_currentChannelID(channelID) 
		{
			m_client = new dipc::client(channelID);
		}

	private:
		std::wstring m_currentChannelID;
		dipc::client* m_client;
	};
}

#endif