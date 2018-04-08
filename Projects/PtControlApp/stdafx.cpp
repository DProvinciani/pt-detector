/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver
 *  Filename: stdafx.cpp
 *	Implement Control Application's standard routines
 *  Last revision: 12/01/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson
 *  Microsoft Ltd & TALOS Research and Intelligence Group
 *  All right reserved
 **********************************************************************/
#include "stdafx.h"

CmdArgsParser::CmdArgsParser(int argc, wchar_t *argv[]) {
    for (int i = 1; i < argc; ++i)
        this->cmdTokens.push_back(std::wstring(argv[i]));
}

const std::wstring& CmdArgsParser::GetOptionValue(const std::wstring &cmdOption) const {
    std::vector<std::wstring>::const_iterator cmdIt;
    cmdIt = std::find(this->cmdTokens.begin(), this->cmdTokens.end(), cmdOption);
    if (cmdIt != this->cmdTokens.end() && ++cmdIt != this->cmdTokens.end())
        return *cmdIt;

    static const std::wstring empty(L"");
    return empty;
}

bool CmdArgsParser::HasOption(const std::wstring &cmdOption) const {
    return std::find(this->cmdTokens.begin(), this->cmdTokens.end(), cmdOption) != this->cmdTokens.end();
}

void Xtrace(LPCTSTR lpszFormat, ...) {
    va_list args;
    va_start(args, lpszFormat);
    int nBuf;
    TCHAR szBuffer[2048] = { 0 }; //fix this
    nBuf = _vsnwprintf_s(szBuffer, 2047, lpszFormat, args);
    ::OutputDebugString(szBuffer);
    va_end(args);
}

typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
// If nullptr is received, the function returns information about the current process
BOOL IsWow64(HANDLE hProcessHandler) {
    BOOL bIsWow64 = FALSE;

    //IsWow64Process is not available on all supported versions of Windows.
    //Use GetModuleHandle to get a handle to the DLL that contains the function
    //and GetProcAddress to get a pointer to the function if available.

    LPFN_ISWOW64PROCESS fnIsWow64Process;

    fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
        GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

    if (NULL != fnIsWow64Process) {
        if (!hProcessHandler)
            hProcessHandler = GetCurrentProcess();

        if (!fnIsWow64Process(hProcessHandler, &bIsWow64)) {
            //handle error
        }
    }
    return bIsWow64;
}

bool IsExecutable(const std::wstring &fileName) {
    bool ret = false;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    hFile = CreateFile(fileName.c_str(),              // file to open
        GENERIC_READ,                                 // open for reading
        FILE_SHARE_READ,                              // share for reading
        NULL,                                         // default security
        OPEN_EXISTING,                                // existing file only
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, // normal file
        NULL);                                        // no attr. template

    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD lpBinaryType = 0;

        if (GetBinaryType(fileName.c_str(), &lpBinaryType))
            ret = true;

        CloseHandle(hFile);
    }

    return ret;
}

#pragma region Generic Environment Console functions
// Get Last Win32 Error description
LPTSTR GetWin32ErrorMessage(DWORD errNum) {
    // Retrieve the system error message for the last-error code
    LPVOID lpMsgBuf = NULL;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errNum, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);
    return (LPTSTR)lpMsgBuf;
}

// Read a line of input from a console
DWORD ReadLine(LPTSTR buff, int buffCch) {
    HANDLE hConsole = GetStdHandle(STD_INPUT_HANDLE);
    CONSOLE_READCONSOLE_CONTROL cControl = { 0 };
    DWORD dwCharRead = 0;
    cControl.nLength = sizeof(CONSOLE_READCONSOLE_CONTROL);
    cControl.dwCtrlWakeupMask = (ULONG)L'\n';
    ReadConsole(hConsole, buff, buffCch, &dwCharRead, &cControl);
    return dwCharRead;
}

void SetConsoleColor(ConsoleColor c) {
    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO con_info;
    GetConsoleScreenBufferInfo(hCon, &con_info);
    SetConsoleTextAttribute(hCon, ((BYTE)c & 0xF) | (con_info.wAttributes & 0xF0));
}

int GetCurrentConsoleColor() {
    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO con_info;
    GetConsoleScreenBufferInfo(hCon, &con_info);
    return con_info.wAttributes;
}

// Color WPrintf 
void cl_wprintf(ConsoleColor c, LPTSTR string, LPVOID arg1, LPVOID arg2, LPVOID arg3, LPVOID arg4) {
    ConsoleColor oldColor = (ConsoleColor)GetCurrentConsoleColor();
    SetConsoleColor(c);
    wprintf(string, arg1, arg2, arg3, arg4);
    SetConsoleColor(oldColor);
}
#pragma endregion