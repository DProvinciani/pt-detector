#include "helpers.h"

int TestToolHelpers::ToInteger(const std::wstring &str)
{
	return std::stoi(str);
}

bool TestToolHelpers::IsValidFile(const std::wstring &fileName)
{
	bool ret = false;
	HANDLE hFile = INVALID_HANDLE_VALUE;

	hFile = CreateFile(fileName.c_str(),       // file to open
		GENERIC_READ,          // open for reading
		FILE_SHARE_READ,       // share for reading
		NULL,                  // default security
		OPEN_EXISTING,         // existing file only
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, // normal file
		NULL);                 // no attr. template

	if (hFile != INVALID_HANDLE_VALUE)
	{
		ret = true;
		CloseHandle(hFile);
	}

	return ret;
}

bool TestToolHelpers::GetFullPathToFile(const std::wstring &fileName, std::wstring &fullPathFile)
{
	bool ret = true;
	wchar_t ptargetFile[MAX_PATH] = { 0 };

	if (GetFullPathName(fileName.c_str(), MAX_PATH, ptargetFile, NULL) == 0)
	{
		ret = false;
	}
	else
	{
		fullPathFile.assign(ptargetFile);
	}

	return ret;
}

bool TestToolHelpers::IsNumber(const std::wstring& str)
{
	bool ret = false;
	std::wstring::const_iterator it = str.begin();
	while (it != str.end() && iswdigit(*it)) ++it;
	if (!str.empty() && it == str.end())
	{
		ret = true;
	}
	return ret;
}


bool TestToolHelpers::GetFileToInjectSize(const std::wstring& file, DWORD &size)
{
	bool ret = false;

	HANDLE hFile = CreateFileW(file.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		size = GetFileSize(hFile, NULL);
		if (size > 0)
		{
			ret = true;
		}

		CloseHandle(hFile);
	}

	return ret;
}


bool TestToolHelpers::IsTestDataValid(TestCommon::TestData &data)
{
	bool ret = false;

	if (!data.channelID.empty() &&
		!data.fileToInject.empty() && TestToolHelpers::IsValidFile(data.fileToInject) &&
		!data.testcaseFile.empty() && TestToolHelpers::IsValidFile(data.testcaseFile) &&
		!data.pidToInject.empty() && TestToolHelpers::IsNumber(data.pidToInject))
	{
		ret = true;
	}

	return ret;
}

bool TestToolHelpers::ReadFileToInjectInBuffer(const std::wstring& file, const DWORD &fileSize, LPVOID lpBuffer, DWORD &bytesRead)
{
	bool ret = false;

	if (lpBuffer != nullptr)
	{
		HANDLE hFile = CreateFileW(file.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			if (ReadFile(hFile, lpBuffer, fileSize, &bytesRead, NULL) && (bytesRead > 0))
			{
				ret = true;
			}

			CloseHandle(hFile);
		}
	}

	return ret;
}

bool TestToolHelpers::InjectIntoProcessViaCreateRemoteThread(const std::wstring &dllToInject,
															 const std::wstring &targetPIDToInject, 
															 const LPVOID &buffer, 
															 const DWORD &bufferSize,
															 LPVOID &remoteBufferAddr)
{
	bool ret = false;

	if (!dllToInject.empty() && TestToolHelpers::IsNumber(targetPIDToInject))
	{
		DWORD targetPID = TestToolHelpers::ToInteger(targetPIDToInject);
		std::wcout << L"[+] About to inject into target PID " << targetPID << std::endl;
		size_t dllPathNameSize = dllToInject.length() * sizeof(wchar_t);
		DWORD currentPID = GetCurrentProcessId();

		// Sanity check to avoid injection to current process and system processes
		if ((targetPID > 4) && (targetPID != currentPID))
		{
			// Getting a handle from target process
			HANDLE hProcess = OpenProcess(
				PROCESS_QUERY_INFORMATION |
				PROCESS_CREATE_THREAD |
				PROCESS_VM_OPERATION |
				PROCESS_VM_WRITE,
				FALSE, targetPID);
			if (hProcess != NULL)
			{
				std::wcout << L"[+] Target PID " << targetPID << L" was succesfully opened" << std::endl;

				// Allocate space in the remote process for the pathname
				LPVOID pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, dllPathNameSize, MEM_COMMIT, PAGE_READWRITE);
				if (pszLibFileRemote != NULL)
				{
					std::wcout << L"[+] " << std::dec << dllPathNameSize << L" bytes of memory were allocated for the DLL into remote process at address "
						<< std::hex << pszLibFileRemote << std::endl;

					// Copy the DLL's pathname to the remote process address space
					DWORD n = WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)dllToInject.c_str(), dllPathNameSize, NULL);
					if (n > 0)
					{
						//Now allocatting memory for buffer
						remoteBufferAddr = (PWSTR)VirtualAllocEx(hProcess, NULL, bufferSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
						if (remoteBufferAddr != NULL)
						{
							std::wcout << L"[+] " << std::dec << bufferSize << L" bytes of memory were allocated for the Gadget DB into remote process at address "
								<< std::hex << remoteBufferAddr << std::endl;

							// Copy the buffer into the remote process address space
							DWORD n = WriteProcessMemory(hProcess, remoteBufferAddr, buffer, bufferSize, NULL);
							if (n > 0)
							{
								// About to create remote thread to start test framework
								// Get the real address of LoadLibraryW in Kernel32.dll
								PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryW");
								if (pfnThreadRtn != NULL)
								{
									HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
									if (hThread != NULL)
									{
										std::wcout << L"[+] Success! DLL injected via InjectorCreateRemoteThread method" << std::endl;
										Sleep(500); //Sleeping for some time to allow DLLMain and its logic to be launched

										ret = true;
									}
									else
									{
										std::wcout << L"[-] There was a problem creating a remote thread in target process" << std::endl;

										wprintf(L"    CreateRemoteThread failed with 0x%x\n", GetLastError());
									}
								}
								else
								{
									std::wcout << L"[-] There was a problem obtaining address of LoadLibraryA function inside kernel32.dll library" << std::endl;
								}
							}
							else
							{
								std::wcout << L"[-] Could not write data into remote process memory at address 0x" << std::hex << remoteBufferAddr << std::endl;
							}
						}
						else
						{
							std::wcout << L"[-] There was a problem allocating memory for the buffer in remote process" << std::endl;
						}
					}
					else
					{
						std::wcout << L"[-] Could not write data into remote process memory at address 0x" << std::hex << pszLibFileRemote << std::endl;
					}
				}
				else
				{
					std::wcout << L"[-] There was a problem allocating memory in target process" << std::endl;
				}

				CloseHandle(hProcess);
			}
			else
			{
				std::wcout << L"[-] There was a problem opening target PID" << std::endl;
			}
		}
		else
		{
			std::wcout << L"[-] An Invalid PID was provided" << std::endl;
		}
	}
	else
	{
		std::wcout << L"[-] There was a problem with given arguments" << std::endl;
	}

	return ret;
}

TestCommon::ARRAYBYTE TestToolHelpers::IPCClient::SendRequest(TestCommon::TestExecutorsMode executorID, unsigned char *dataPayload, int dataSize)
{
	return m_client->request(executorID, dataPayload, dataSize);
}