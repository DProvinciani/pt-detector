#ifndef _COMMON_H_
#define _COMMON_H_

#include <iostream>
#include <memory>
#include <vector>
#include <map>
#include <iterator>
#include <string>
#include <iomanip>
#include <algorithm>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <wchar.h>
#include <wctype.h>


namespace PtExploitDetectorCommon
{
	enum ExecutorsMode
	{
		GET_REMOTE_FUNCTION_ADDRESS = 0x05,
		NA,
	};

	inline const wchar_t* ExecutorModeToString(ExecutorsMode value)
	{
		switch (value)
		{
		case GET_REMOTE_FUNCTION_ADDRESS:    return L"Get Remote Function Address";
		default:						     return L"[Unknown TestExecutor]";
		}
	}

    inline bool GetFullPathToFile(const std::wstring &fileName, std::wstring &fullPathFile)
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

	static const bool DEFAULT_VERBOSITY_STATUS = false;
	static const ExecutorsMode DEFAULT_EXECUTOR_MODE = ExecutorsMode::NA;
	static const std::wstring DEFAULT_DLL_TO_INJECT = L"PtExploitDetectorAgent.dll";
	static const std::wstring PRE_CHANNEL_TOKEN = L"PTEXPLOITDETECTORAGENTIPC_";

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
}


#endif