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
#include "IntelPtControlApp.h"
#include "pt_dump.h"

 // Global app data
GLOBAL_DATA g_appData;

int wmain(int argc, LPTSTR argv[]) {
    int iReturn = 0;
    std::wstring executableTarget = L"";
    std::wstring parameters = L"";
    CmdArgsParser switches(argc, argv);

    cl_wprintf(DARKYELLOW, L"\r\n    *** Code-Reuse Exploits Detector ***\r\n\r\n");

    // system("pause");

    // verifying necessary parameters
    if (switches.HasOption(L"-d")) {
        std::wcout << L"Dumping binary file: " << std::endl;
        std::wcout << L"    Input:  " << switches.GetOptionValue(L"-d") << std::endl;
        std::wcout << L"    Output: " << switches.GetOptionValue(L"-d") << L".log" << std::endl;
        pt_dump_packets(switches.GetOptionValue(L"-d").c_str());
    }
    else if (switches.HasOption(L"-t")) {
        // validating the path and executable to trace
        executableTarget = switches.GetOptionValue(L"-t");
        if (executableTarget.empty() || !IsExecutable(executableTarget)) {
            cl_wprintf(RED, L"Error\r\n");
            std::wcout << L"Provided executable is not valid" << std::endl << std::endl;
            iReturn = -1;
        }
        else { // all was ok... lets configure the trace
            parameters = switches.GetOptionValue(L"-p");
            iReturn = ConfigureTrace(executableTarget, parameters);
        }
    }
    else {
        if (!switches.HasOption(L"-h")) {
            cl_wprintf(RED, L"Error\r\n");
            std::wcout << L"Invalid arguments." << std::endl << std::endl;
            iReturn = -1;
        }

        ShowHelp();
        return iReturn;
    }

    return iReturn;
}

// Show command line usage
void ShowHelp() {
    std::wcout << L"PtControlApp usage:" << std::endl;
    std::wcout << L"PtControlApp.exe -h for help" << std::endl;
    std::wcout << L"PtControlApp.exe -t <executable_to_trace_fullpath>" << std::endl;
    std::wcout << L"PtControlApp.exe -t <executable_to_trace_fullpath> -p <parameters_for_the_executable>" << std::endl;
    std::wcout << L"PtControlApp.exe -d <binary_pt_trace_file_to_dump_fullpath>" << std::endl << std::endl;

    std::wcout << L"NOTE: The -p switch is optional. If you are using -p switch to pass more than one" << std::endl;
    std::wcout << L"parameter to the executable, please use quotation. ie: -p \"param1 param 2 param 3\"" << std::endl;
}