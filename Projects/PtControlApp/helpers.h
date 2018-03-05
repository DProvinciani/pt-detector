#ifndef _CMD_PARSER_H_
#define _CMD_PARSER_H_

#include <iostream>
#include <string>
#include <vector>

typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

static inline void Xtrace(LPCTSTR lpszFormat, ...)
{
    va_list args;
    va_start(args, lpszFormat);
    int nBuf;
    TCHAR szBuffer[2048] = { 0 }; //fix this
    nBuf = _vsnwprintf_s(szBuffer, 2047, lpszFormat, args);
    ::OutputDebugString(szBuffer);
    va_end(args);
}

// If nullptr is received, the function returns information about the current process
static inline BOOL IsWow64(HANDLE hProcessHandler)
{
    BOOL bIsWow64 = FALSE;

    //IsWow64Process is not available on all supported versions of Windows.
    //Use GetModuleHandle to get a handle to the DLL that contains the function
    //and GetProcAddress to get a pointer to the function if available.

    LPFN_ISWOW64PROCESS fnIsWow64Process;

    fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
        GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

    if (NULL != fnIsWow64Process)
    {
        if (!hProcessHandler)
            hProcessHandler = GetCurrentProcess();
        
        if (!fnIsWow64Process(hProcessHandler, &bIsWow64))
        {
            //handle error
        }
    }
    return bIsWow64;
}

static inline bool IsValidFile(const std::wstring &fileName)
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
        DWORD lpBinaryType = 0;

        if (GetBinaryType(fileName.c_str(), &lpBinaryType))
            ret = true;

        CloseHandle(hFile);
    }

    return ret;
}

class CmdArgsParser 
{
public:
	CmdArgsParser(int argc, wchar_t *argv[])
	{
		for (int i = 1; i < argc; ++i)
		{
			this->cmdTokens.push_back(std::wstring(argv[i]));
		}

	}

	const std::wstring& GetOptionValue(const std::wstring &cmdOption) const
	{
		std::vector<std::wstring>::const_iterator cmdIt;
		cmdIt = std::find(this->cmdTokens.begin(), this->cmdTokens.end(), cmdOption);
		if (cmdIt != this->cmdTokens.end() && ++cmdIt != this->cmdTokens.end())
		{
			return *cmdIt;
		}
		static const std::wstring empty(L"");
		return empty;
	}

	bool WasOptionRequested(const std::wstring &cmdOption) const
	{
		return 
			std::find(this->cmdTokens.begin(), this->cmdTokens.end(), cmdOption) != this->cmdTokens.end();
	}

private:
	std::vector <std::wstring> cmdTokens;
};

#endif
