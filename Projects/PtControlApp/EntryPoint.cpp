/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver
 *  Filename: EntryPoint.h
 *  The Control application entry point and startup functions
 *  Last revision: 12/01/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson
 *  Microsoft Ltd & TALOS Research and Intelligence Group
 *  All right reserved
 **********************************************************************/
#include "stdafx.h"
#include "helpers.h"
#include "IntelPtControlApp.h"
#include "pt_dump.h"

 // Global app data
GLOBAL_DATA g_appData;

int wmain(int argc, LPTSTR argv[])
{
    int iReturn = 0;
    std::wstring executableTarget = L"";

    cl_wprintf(DARKYELLOW, L"\r\n    *** Code-Reuse Exploits Detector ***\r\n\r\n");

    system("pause");

    CmdArgsParser inputCmds(argc, argv);

    // verifying necessary parameters
    if (!inputCmds.WasOptionRequested(L"-t"))
    {
        if (!inputCmds.WasOptionRequested(L"-h"))
        {
            cl_wprintf(RED, L"Error\r\n");
            std::wcout << L"Make sure to provide all the required arguments." << std::endl << std::endl;
        }

        ShowHelp();
        return iReturn;
    }

    // validating the path and executable to trace
    executableTarget = inputCmds.GetOptionValue(L"-t");
    if (executableTarget.empty() ||
        !IsValidFile(executableTarget))
    {
        cl_wprintf(RED, L"Error\r\n");
        std::wcout << L"Provided executable is not valid" << std::endl << std::endl;
        return iReturn;
    }
    else // all was ok... lets configure the trace
        iReturn = ConfigureTrace(executableTarget);

    return iReturn;
}

// Show command line usage
void ShowHelp()
{
    std::wcout << L"PtControlApp usage:" << std::endl;
    std::wcout << L"PtControlApp.exe -h for help" << std::endl;
    std::wcout << L"PtControlApp.exe -t <executable_to_trace_fullpath>" << std::endl;
}