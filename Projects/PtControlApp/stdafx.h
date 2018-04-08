/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver
 *  Filename: stdafx.h 
 *	Control Application standard definitions
 *  Last revision: 12/01/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson
 *  Microsoft Ltd & TALOS Research and Intelligence Group
 *  All right reserved
 **********************************************************************/
#pragma once

#include "targetver.h"
#include <stdio.h>
#include <tchar.h>
#include <iostream>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

typedef unsigned long long QWORD;

class CmdArgsParser {
public:
    CmdArgsParser(int argc, wchar_t *argv[]);
    const std::wstring& GetOptionValue(const std::wstring &cmdOption) const;
    bool HasOption(const std::wstring &cmdOption) const;

private:
    std::vector <std::wstring> cmdTokens;
};

// Xtrace logging
void Xtrace(LPCTSTR lpszFormat, ...);

// WOW64 process checker
BOOL IsWow64(HANDLE hProcessHandler);

// Check if a file is an executable
bool IsExecutable(const std::wstring &fileName);

// Get last Win32 error description
LPTSTR GetWin32ErrorMessage(DWORD errNum);

// Read a line of input from a console
DWORD ReadLine(LPTSTR buff, int buffCch);

enum ConsoleColor {
	DARKBLUE = 1, DARKGREEN, DARKTEAL, DARKRED, DARKPINK, DARKYELLOW,
	GRAY, DARKGRAY, BLUE, GREEN, TEAL, RED, PINK, YELLOW, WHITE
};

// Set console text color
void SetConsoleColor(ConsoleColor c);
// Get console text color
int GetCurrentConsoleColor();
// Color WPrintf 
void cl_wprintf(ConsoleColor c, LPTSTR string, LPVOID arg1 = NULL, LPVOID arg2 = NULL, LPVOID arg3 = NULL, LPVOID arg4 = NULL);

#ifdef _DEBUG
#define DbgBreak() __debugbreak()
#else
#define DbgBreak() __noop()
#endif

#define COUNTOF(x) sizeof(x) / sizeof(x[0])