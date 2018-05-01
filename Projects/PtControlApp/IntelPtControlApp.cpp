/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver
 *  Filename: IntelPtControlApp.cpp
 *	Implement the entire PT driver's Control Application 
 *  Last revision: 12/01/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson
 *  Microsoft Ltd & TALOS Research and Intelligence Group
 *  All right reserved
 **********************************************************************/

#include <crtdbg.h>
#include <iostream>
#include <string.h>
#include "stdafx.h"
#include "IntelPtControlApp.h"
#include "Psapi.h"
#include "pt_dump.h"
#include "UndocNt.h"

const LPTSTR g_ptDeviceName = L"\\\\.\\WindowsIntelPtDev"; // Using \\.\ allows to work with the Device Namespace: https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx
#pragma comment (lib, "ntdll.lib")

// Entry point without command line arguments
int ConfigureTrace(const std::wstring wsExecutableFullPath, const std::wstring wsCommandLine) {
	BOOL bReturn = FALSE;
    DWORD dwLastError = 0;
    SYSTEM_INFO systemInfo = { 0 };                 // Struct to hold system information
	INTEL_PT_CAPABILITIES ptCapabilities = { 0 };   // Struct to hold all the suported Intel PT capabilities
	HANDLE hPtDevice = NULL;				    	// Handle to the PT device
    LPTSTR lpOutputDir = NULL;			    		// Full path tho the output trace files directory
    DWORD dwCpusToUse = 1;							// Number of CPUs in which to run the code (supporting only one by moment)
    KAFFINITY cpuAffinity = 0;						// The processor Affinity mask
    PT_CPU_BUFFER_DESC * pCpuBufferDescArray;		// The CPU PT buffer descriptor array
    PROCESS_INFORMATION processInfo = { 0 };        // The PROCESS INFORMATION structure to hold the information of the traced process
	PT_USER_REQ ptStartStruct = { 0 };				// The Intel PT starting structure
	DWORD dwBytesIo = 0;							// Number of I/O bytes
	BOOLEAN bDoKernelTrace = FALSE;					// TRUE if I would like to do kernel tracing
	BOOLEAN bManuallyAllocBuff = FALSE;				// TRUE if I would like to manually allocate the buffer (used for test purposes)
	BOOLEAN bDeleteFiles = FALSE;					// TRUE if some errors that require the file deletion

#pragma region 0. Verifying system information, IntelPT support and opening IntelPT handler
	// Getting current process information
    if (IsWow64(nullptr))
        std::wcout << L"PtControlApp running under WOW64." << std::endl;
    else
        std::wcout << L"PtControlApp not running under WOW64." << std::endl;

    // Getting system information and asking for Intel PT support
	GetNativeSystemInfo(&systemInfo);
	bReturn = CheckIntelPtSupport(&ptCapabilities);
    std::wcout << L"Intel Processor Tracing support for this CPU: ";
    if (bReturn) 
		cl_wprintf(GREEN, L"YES\r\n"); 
	else {
		cl_wprintf(RED, L"NO\r\n");
		return -1;
	}

	// Opening Intel PT device object
	hPtDevice = CreateFile(g_ptDeviceName, FILE_ALL_ACCESS, 0, NULL, OPEN_EXISTING, 0, NULL);
	dwLastError = GetLastError();

	if (hPtDevice == INVALID_HANDLE_VALUE) {
        cl_wprintf(RED, L"Error 0x%x\r\n", (LPVOID)dwLastError);
        std::wcout << L"Unable to open the Intel PT device object." << std::endl;
		return -1;
	}
	else
		g_appData.hPtDevice = hPtDevice;

	// Create the Exit Event
	g_appData.hExitEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
#pragma endregion

#pragma region 1. Generate output dump files directory 
    std::wcout << L"Creating trace output directory... ";

    // Allocate memory for the file names
    lpOutputDir = new TCHAR[MAX_PATH];
    RtlZeroMemory(lpOutputDir, MAX_PATH * sizeof(TCHAR));

	GetModuleFileName(GetModuleHandle(NULL), lpOutputDir, MAX_PATH);

    SYSTEMTIME currentTime = { 0 };
	GetLocalTime(&currentTime);

	LPTSTR pLastSlash = wcsrchr(lpOutputDir, L'\\');
	if (pLastSlash) pLastSlash[1] = 0; 

	swprintf_s(lpOutputDir, MAX_PATH, L"%s%.2i%.2i-%.2i%.2i%.4i_Dumps",
		lpOutputDir, currentTime.wHour, currentTime.wMinute, currentTime.wMonth, currentTime.wDay, currentTime.wYear);
	CreateDirectory(lpOutputDir, NULL);

    cl_wprintf(GREEN, L"DONE\r\n");
#pragma endregion

#pragma region 2. Calculate the CPU affinity
	/*
	Setting the cpuAffinity
	A process affinity mask is a bit vector in which each bit represents a logical
	processor on which the threads of the process are allowed to run.
	*/
    if (systemInfo.dwNumberOfProcessors > 1) {
        // -1i64 creates a 64 bit variable with all the bits set to 1
        // The cast to DWORD_PTR ensures that the right shift will fill the vacant bits with 0 (because DWORD_PTR is unsigned)
        // The number operation to calculate the number of bits to shift is basically 8*8 = 64 - NumberOfCPUsToUse
		cpuAffinity = ((DWORD_PTR)(-1i64) >> ((sizeof(DWORD_PTR) * 8) - dwCpusToUse));
	}
	else
		cpuAffinity = systemInfo.dwActiveProcessorMask;
#pragma endregion
	
#pragma region 3. Create the CPU buffer data structures and trace files
	std::wcout << L"Creating trace output files... ";
	bReturn = (BOOL)InitPerCpuData(dwCpusToUse, cpuAffinity, lpOutputDir);

	if (bReturn) 
		cl_wprintf(GREEN, L"DONE\r\n");
	else {
        cl_wprintf(RED, L"FAIL\r\n");
        std::wcout << L"    Attempting now ussing TEMP directory... ";

        // If because of any reason the per CPU data files creation fails we try again using the temp directory
		RemoveDirectory(lpOutputDir);
        RtlZeroMemory(lpOutputDir, MAX_PATH * sizeof(TCHAR));
		
        DWORD dwTempPathLenght = GetTempPath(MAX_PATH, lpOutputDir);
		if (lpOutputDir[dwTempPathLenght - 1] == '\\')  lpOutputDir[dwTempPathLenght - 1] = 0;
		
        swprintf_s(lpOutputDir, MAX_PATH, L"%s\\IntelPt_Dumps_%.2i%.2i-%.2i%.2i%.4i",
			lpOutputDir, currentTime.wHour, currentTime.wMinute, currentTime.wMonth, currentTime.wDay, currentTime.wYear);
		CreateDirectory(lpOutputDir, NULL);

		bReturn = (BOOL)InitPerCpuData(dwCpusToUse, cpuAffinity, lpOutputDir);
		if (bReturn)
			cl_wprintf(GREEN, L"DONE\r\n");
        else {
            RemoveDirectory(lpOutputDir);
            cl_wprintf(RED, L"FAIL\r\n");
            std::wcout << L"    Closing IntelPT device handler." << std::endl;
            CloseHandle(hPtDevice);
            return -1;
        }
	}

	pCpuBufferDescArray = g_appData.pCpuBufferDescArray;
#pragma endregion

#pragma region 4. Spawn of the new process and PMI threads
	std::wcout << L"Creating target process... ";

    // TODO: Add the posibility to start the process with different parameters
	bReturn = SpawnSuspendedProcess(wsExecutableFullPath.c_str(), &processInfo, wsCommandLine.c_str());
	if (bReturn) cl_wprintf(GREEN, L"DONE\r\n");
	else {
		wprintf(L"FAIL\r\n");
		FreePerCpuData(TRUE);
		CloseHandle(hPtDevice);
		return -1;
	}

	g_appData.hTargetProcess = processInfo.hProcess;

	bReturn = SetProcessAffinityMask(processInfo.hProcess, cpuAffinity);
	_ASSERT(bReturn);
	if (!bReturn) {
		cl_wprintf(YELLOW, L"WARNING\r\n");
        std::wcout << L"    Unable Set the processor affinity for the spawned process." << std::endl;
	}

	// Create the PMI threads (1 per target CPU)
	for (int i = 0; i < (int)dwCpusToUse; i++) {
		PT_PMI_USER_CALLBACK pmiDescriptor = { 0 };
		HANDLE hNewThread = NULL;
		DWORD newThreadId = 0;

		hNewThread = CreateThread(NULL, 0, PmiThreadProc, (LPVOID)(QWORD)i, CREATE_SUSPENDED, &newThreadId);

        if (hNewThread) {
            // Register this thread and its callback
            pmiDescriptor.dwThrId = newThreadId;
            pmiDescriptor.kCpuAffinity = (1i64 << i);
            pmiDescriptor.lpAddress = PmiCallback;
            bReturn = DeviceIoControl(hPtDevice, IOCTL_PTDRV_REGISTER_PMI_ROUTINE, (LPVOID)&pmiDescriptor, sizeof(PT_PMI_USER_CALLBACK), NULL, 0, &dwBytesIo, NULL);
            if (bReturn) {
                pCpuBufferDescArray[i].dwPmiThreadId = newThreadId;
                pCpuBufferDescArray[i].hPmiThread = hNewThread;
                ResumeThread(hNewThread);
            }
        }
	}
#pragma endregion

#pragma region 5. Getting information about the remote windows APIs
    std::wcout << L"Getting information about windows APIs on target process... ";
    
    std::wstring defaultFileToInject(PtExploitDetectorCommon::DEFAULT_DLL_TO_INJECT);
    std::wstring fullPathToFileToInject;
    PtExploitDetectorCommon::GetFullPathToFile(defaultFileToInject, fullPathToFileToInject);
    bReturn = InjectPtExploitDetectorAgentIntoRemoteProcess(fullPathToFileToInject, processInfo.hProcess);
    if (!bReturn) {
        wprintf(L"FAIL\r\n");
        FreePerCpuData(TRUE);
        CloseHandle(hPtDevice);
        return -1;
    }

    std::wstring channelID(PtExploitDetectorCommon::PRE_CHANNEL_TOKEN + std::to_wstring(processInfo.dwProcessId));
    bReturn = GetRemoteWindowsApis(channelID, g_appData.remoteAPIs);
    if (bReturn) cl_wprintf(GREEN, L"DONE\r\n");
    else {
        wprintf(L"FAIL\r\n");
        FreePerCpuData(TRUE);
        CloseHandle(hPtDevice);
        return -1;
    }
#pragma endregion

#pragma region 6. Set IP filtering (if any) and TRACE options
	HMODULE hRemoteMod = NULL;						// The remote module base address
	MODULEINFO remoteModInfo = { 0 };				// The remote module information

	if (g_appData.bTraceByIp) {
		// Now grab the remote image base address and size
		bReturn = EnumProcessModules(processInfo.hProcess, &hRemoteMod, sizeof(HMODULE), &dwBytesIo);
		bReturn = GetModuleInformation(processInfo.hProcess, hRemoteMod, &remoteModInfo, sizeof(MODULEINFO));

		g_appData.bTraceOnlyKernel = bDoKernelTrace;

		if (!remoteModInfo.lpBaseOfDll) {
			cl_wprintf(RED, L"FAIL\r\n");
            std::wcout << L"    I was not able to find the target process main module base address and size."  << std::endl;
			FreePerCpuData(TRUE);
			CloseHandle(hPtDevice);
			return -1;
		}

		cl_wprintf(PINK, L"\r\n        Using CR3 filtering mode!\r\n");
		wprintf(L"        New Process main module base address: 0x%llX, size 0x%08X.\r\n\r\n",
			(QWORD)remoteModInfo.lpBaseOfDll, remoteModInfo.SizeOfImage);

		// Set the PT_USER_REQUEST structure
		ptStartStruct.IpFiltering.dwNumOfRanges = 0;
		/*ptStartStruct.IpFiltering.Ranges[0].lpStartVa = (LPVOID)((ULONG_PTR)remoteModInfo.lpBaseOfDll);
		ptStartStruct.IpFiltering.Ranges[0].lpEndVa = (LPVOID)((ULONG_PTR)remoteModInfo.lpBaseOfDll + remoteModInfo.SizeOfImage);
		ptStartStruct.IpFiltering.Ranges[0].bStopTrace = FALSE;*/
	}   // END Tracing by IP block

	// Write some information in the output text file:
	WriteCpuTextDumpsHeader(wsExecutableFullPath.c_str(), (ULONG_PTR)remoteModInfo.lpBaseOfDll, remoteModInfo.SizeOfImage);
	ptStartStruct.bTraceUser = !bDoKernelTrace;
	ptStartStruct.bTraceKernel = bDoKernelTrace;
	// For now do not set the frequencies....
	ptStartStruct.dwOptsMask = PT_TRACE_BRANCH_PCKS_MASK | PT_ENABLE_TOPA_MASK;
	ptStartStruct.kCpuAffinity = cpuAffinity;
	ptStartStruct.dwTraceSize = g_appData.dwTraceBuffSize;
#pragma endregion

#pragma region 7. Allocate each PT CPU buffer and Start the tracing and wait the process to exit
	LPVOID * lpBuffArray = new LPVOID[dwCpusToUse];
	RtlZeroMemory(lpBuffArray, sizeof(LPVOID)* dwCpusToUse);
	
    // Start the device Tracing
	wprintf(L"Starting the Tracing and resuming the process... ");
	ptStartStruct.dwProcessId = processInfo.dwProcessId;
	ptStartStruct.kCpuAffinity = cpuAffinity;
	bReturn = DeviceIoControl(hPtDevice, IOCTL_PTDRV_START_TRACE, (LPVOID)&ptStartStruct, sizeof(PT_USER_REQ), lpBuffArray, sizeof(LPVOID) * dwCpusToUse, &dwBytesIo, NULL);
	dwLastError = GetLastError();

	if (bReturn) {
		cl_wprintf(GREEN, L"OK\r\n\r\n");
		g_appData.currentTrace = ptStartStruct;

		// Copy the returned Buffer array
		for (int i = 0; i < (int)g_appData.dwActiveCpus; i++) {
			g_appData.pCpuBufferDescArray[i].lpPtBuff = (LPBYTE)lpBuffArray[i];
			g_appData.pCpuBufferDescArray[i].dwBuffSize = ptStartStruct.dwTraceSize;
		}

        // Resume the target process
		Sleep(100);
		ResumeThread(processInfo.hThread);
        wprintf(L"Waiting for the traced process to exit...\r\n\r\n");
		WaitForSingleObject(processInfo.hProcess, INFINITE);
	}
	else {
		TerminateProcess(processInfo.hProcess, -1);
		cl_wprintf(RED, L"FAIL\r\n");
		cl_wprintf(RED, L"        Start trace failed with error 0x%x\r\n\r\n", (LPVOID)dwLastError);
		bDeleteFiles = TRUE;
	}

	// Set the event and wait for all PMI thread to exit
	SetEvent(g_appData.hExitEvent);
	for (int i = 0; i < (int)dwCpusToUse; i++) {
		WaitForSingleObject(pCpuBufferDescArray[i].hPmiThread, INFINITE);
		CloseHandle(pCpuBufferDescArray[i].hPmiThread);
		pCpuBufferDescArray[i].hPmiThread = NULL;
		pCpuBufferDescArray[i].dwPmiThreadId = 0;
	}
#pragma endregion

#pragma region 8. Get the results of our tracing (like the number of written packets)
    PT_TRACE_DETAILS ptDetails = { 0 };
	
	cl_wprintf(DARKYELLOW, L"    *** PT Trace results ***\r\n");
	
	for (unsigned i = 0; i < dwCpusToUse; i++) {
		RtlZeroMemory(&ptDetails, sizeof(ptDetails));
		bReturn = DeviceIoControl(hPtDevice, IOCTL_PTDR_GET_TRACE_DETAILS, (LPVOID)&i, sizeof(int), (LPVOID)&ptDetails, sizeof(ptDetails), &dwBytesIo, NULL);
		if (bReturn)
			wprintf(L"        Number of acquired packets: %I64i\r\n", ptDetails.qwTotalNumberOfPackets);
		else
			cl_wprintf(RED, L"        Error getting trace details!\r\n");
	}

	wprintf(L"        All the dumps have been saved in \"%s\".\r\n\r\n", lpOutputDir);
#pragma endregion

#pragma region 9. Free the resources and close each files
	// Stop the Tracing (and clear the buffer if not manually allocated)
	bReturn = DeviceIoControl(hPtDevice, IOCTL_PTDRV_CLEAR_TRACE, (LPVOID)&cpuAffinity, sizeof(cpuAffinity), NULL, 0, &dwBytesIo, NULL);

	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);
	FreePerCpuData(bDeleteFiles);
	if (bManuallyAllocBuff)
		bReturn = DeviceIoControl(g_appData.hPtDevice, IOCTL_PTDRV_FREE_BUFFERS, (LPVOID)&cpuAffinity,
			sizeof(cpuAffinity), NULL, 0, &dwBytesIo, NULL);


	CloseHandle(hPtDevice);
#pragma endregion
    return 0;
}

// Check if the current CPU has support for Intel PT
BOOL CheckIntelPtSupport(INTEL_PT_CAPABILITIES * lpPtCapabilities) {
	INTEL_PT_CAPABILITIES ptCapabilities = { 0 };
	int cpuid_ctx[4] = { 0 }; // EAX, EBX, ECX, EDX

	// Processor support for Intel Processor Trace is indicated by CPUID.(EAX=07H,ECX=0H):EBX[bit 25] = 1.
    // For more information see:
    //         - Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 1, Chapter 19
    //         - Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2, Chapter 3 - CPUID-CPU Identification
	__cpuidex(cpuid_ctx, 0x07, 0);
	if (!(cpuid_ctx[1] & (1 << 25))) return FALSE;

	// Now enumerate the Intel Processor Trace capabilities
	RtlZeroMemory(cpuid_ctx, sizeof(cpuid_ctx));
	__cpuidex(cpuid_ctx, 0x14, 0);
	// If the maximum valid sub-leaf is 0 exit immediately
	if (cpuid_ctx[0] == 0) return FALSE;

	ptCapabilities.bCr3Filtering              = (cpuid_ctx[1] & (1 << 0)) != 0;	// EBX
	ptCapabilities.bConfPsbAndCycSupported    = (cpuid_ctx[1] & (1 << 1)) != 0;
	ptCapabilities.bIpFiltering               = (cpuid_ctx[1] & (1 << 2)) != 0;
	ptCapabilities.bMtcSupport                = (cpuid_ctx[1] & (1 << 3)) != 0;
	ptCapabilities.bTopaOutput                = (cpuid_ctx[2] & (1 << 0)) != 0;	// ECX
	ptCapabilities.bTopaMultipleEntries       = (cpuid_ctx[2] & (1 << 1)) != 0;
	ptCapabilities.bSingleRangeSupport        = (cpuid_ctx[2] & (1 << 2)) != 0;
	ptCapabilities.bTransportOutputSupport    = (cpuid_ctx[2] & (1 << 3)) != 0;
	ptCapabilities.bIpPcksAreLip              = (cpuid_ctx[2] & (1 << 31)) != 0;

	// Enmeration part 2:
	RtlZeroMemory(cpuid_ctx, sizeof(cpuid_ctx));
	__cpuidex(cpuid_ctx, 0x14, 1);
	ptCapabilities.numOfAddrRanges            = (BYTE)(cpuid_ctx[0] & 0x7);
	ptCapabilities.mtcPeriodBmp               = (SHORT)((cpuid_ctx[0] >> 16) & 0xFFFF);
	ptCapabilities.cycThresholdBmp            = (SHORT)(cpuid_ctx[1] & 0xFFFF);
	ptCapabilities.psbFreqBmp                 = (SHORT)((cpuid_ctx[1] >> 16) & 0xFFFF);

	if (lpPtCapabilities) *lpPtCapabilities = ptCapabilities;
	return TRUE;
}

// Initialize and open the per-CPU files and data structures
bool InitPerCpuData(DWORD dwCpusToUse, KAFFINITY cpuAffinity, LPTSTR lpOutputDir) {
 	PT_CPU_BUFFER_DESC * pCpuBufferDescArray = NULL;	// The new PER-CPU buffer array
    TCHAR newFileName[MAX_PATH] = { 0 };                // The new file name string
	HANDLE hNewFile = NULL;								// The handle of the new file

	FreePerCpuData(FALSE);

	pCpuBufferDescArray = new PT_CPU_BUFFER_DESC[dwCpusToUse];
	RtlZeroMemory(pCpuBufferDescArray, sizeof(PT_CPU_BUFFER_DESC) * dwCpusToUse);
	g_appData.dwActiveCpus = dwCpusToUse;
	g_appData.kActiveCpusAffinity = cpuAffinity;
	g_appData.pCpuBufferDescArray = pCpuBufferDescArray;

	for (DWORD dwCurrentCpu = 0; dwCurrentCpu < dwCpusToUse; dwCurrentCpu++) {
		PT_CPU_BUFFER_DESC * pCurrentCpuBufferDesc = &pCpuBufferDescArray[dwCurrentCpu];

		RtlZeroMemory(newFileName, MAX_PATH * sizeof(TCHAR));
		swprintf_s(newFileName, MAX_PATH, L"%s\\cpu%.2i_bin.bin", lpOutputDir, dwCurrentCpu);

		// Create the binary file 
		hNewFile = CreateFile(newFileName, FILE_GENERIC_WRITE | DELETE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);

		if (hNewFile != INVALID_HANDLE_VALUE) {
			pCurrentCpuBufferDesc->hBinFile = hNewFile;

            RtlZeroMemory(newFileName, MAX_PATH * sizeof(TCHAR));
			swprintf_s(newFileName, MAX_PATH, L"%s\\cpu%.2i_text.log", lpOutputDir, dwCurrentCpu);

            // Create the text file 
			hNewFile = CreateFile(newFileName, FILE_GENERIC_WRITE | DELETE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);

            if (hNewFile != INVALID_HANDLE_VALUE)
                pCurrentCpuBufferDesc->hTextFile = hNewFile;
            else {
                FreePerCpuData(TRUE);
                return false;
            }
		}
	}
	return true;
}

// Close and flush the per-CPU files and data structures
bool FreePerCpuData(BOOL bDeleteFiles) {
	PT_CPU_BUFFER_DESC * pCurrentCpuBufferDesc = NULL;	// Current CPU buffer descriptor
	BOOLEAN bBuffValid = FALSE;

	if (g_appData.pCpuBufferDescArray == NULL) return false;

	for (int i = 0; i < (int)g_appData.dwActiveCpus; i++) {
		pCurrentCpuBufferDesc = &g_appData.pCpuBufferDescArray[i];
		if (pCurrentCpuBufferDesc->hBinFile) {
			if (bDeleteFiles)
				SetFileInformationByHandle(pCurrentCpuBufferDesc->hBinFile, FileDispositionInfo, (LPVOID)&bDeleteFiles, sizeof(BOOL));
			CloseHandle(pCurrentCpuBufferDesc->hBinFile); pCurrentCpuBufferDesc->hBinFile = NULL;
		}
		if (pCurrentCpuBufferDesc->hTextFile) {
			if (bDeleteFiles)
				SetFileInformationByHandle(pCurrentCpuBufferDesc->hTextFile, FileDispositionInfo, (LPVOID)&bDeleteFiles, sizeof(BOOL));
			CloseHandle(pCurrentCpuBufferDesc->hTextFile); pCurrentCpuBufferDesc->hTextFile = NULL;
		}
		if (pCurrentCpuBufferDesc->lpPtBuff) bBuffValid = TRUE;
	}

	// The actual PT buffer deallocation is done in the main routine (by the PT driver)
	delete[] g_appData.pCpuBufferDescArray;
	g_appData.pCpuBufferDescArray = NULL;
	g_appData.dwActiveCpus = 0;
	g_appData.kActiveCpusAffinity = 0;
	return true;
}

// Write the human readable dump file header
bool WriteCpuTextDumpsHeader(const wchar_t* lpExecutableFullPath, ULONG_PTR qwBase, DWORD dwSize) {
	DWORD dwCurCpuCount = 0;			// Current CPU counter (different from ID)
	DWORD dwNumOfCpus = 0;				// Total number of CPUs
	KAFFINITY kCpuAffinity = 0;			// Current CPU affinity mask
	CHAR fullLine[0x200] = { 0 };		// A full line of log dump
	DWORD dwBytesIo = 0;
	if (!g_appData.pCpuBufferDescArray) return false;

	// Grab some basic data
	dwNumOfCpus = g_appData.dwActiveCpus;
	kCpuAffinity = g_appData.kActiveCpusAffinity;

    const wchar_t* lpExecutableName = nullptr;
    if (lpExecutableFullPath && wcsrchr(lpExecutableFullPath, L'\\'))
        lpExecutableName = wcsrchr(lpExecutableFullPath, L'\\') + 1;

	for (int i = 0; i < sizeof(g_appData.kActiveCpusAffinity) * 8; i++) {
		PT_CPU_BUFFER_DESC * pCurCpuBuff = &g_appData.pCpuBufferDescArray[dwCurCpuCount];
		HANDLE hTextFile = NULL;
		if (!(kCpuAffinity & (1i64 << i))) continue;
		if (dwCurCpuCount > dwNumOfCpus) break;
		hTextFile = pCurCpuBuff->hTextFile;
		if (!hTextFile) { dwCurCpuCount++; continue; }

		sprintf_s(fullLine, COUNTOF(fullLine), "Intel PT Trace file. Version 0.5.\r\nCPU ID : %i\r\n", i);
		WriteFile(hTextFile, fullLine, (DWORD)strlen(fullLine), &dwBytesIo, NULL);
		if (qwBase && dwSize) {
			sprintf_s(fullLine, COUNTOF(fullLine), "Executable name: %S\r\n", lpExecutableName);
			WriteFile(hTextFile, fullLine, (DWORD)strlen(fullLine), &dwBytesIo, NULL);
			sprintf_s(fullLine, COUNTOF(fullLine), "Base address: 0x%016llX - Size 0x%08X\r\n", (QWORD)qwBase, dwSize);
			WriteFile(hTextFile, fullLine, (DWORD)strlen(fullLine), &dwBytesIo, NULL);
		}
		sprintf_s(fullLine, COUNTOF(fullLine), "\r\n");
		WriteFile(hTextFile, fullLine, (DWORD)strlen(fullLine), &dwBytesIo, NULL);
		WriteFile(hTextFile, "Begin Trace Dump:\r\n", (DWORD)strlen("Begin Trace Dump:\r\n"), &dwBytesIo, NULL);

		dwCurCpuCount++;
	}
	return true;
}

// Spawn a suspended process and oblige the loader to load the remote image in memory
BOOL SpawnSuspendedProcess(const std::wstring wsExecutableFullPath, PROCESS_INFORMATION * pProcessInfo, std::wstring wsCommandLine) {
    BOOL bReturn = FALSE;
    STARTUPINFO startupInfo = { 0 };						    // The process Startup options
	PROCESS_INFORMATION processInfo = { 0 };				    // Process information
    BYTE remote_opcodes[] = { 0x90, 0x90, 0xc3, 0x90, 0x90 };   // NOP - RET opcodes
	ULONG_PTR ulBytesIo = 0;				             		// Number of I/O bytes
	LPVOID lpRemoteBuff = NULL;				            		// Remote memory buffer
	HANDLE hRemoteThread = NULL;					          	// The remote thread stub 
	DWORD dwThreadId = 0;					            		// Remote thread ID
	
    if ((wsExecutableFullPath.compare(L"") == 0) || !pProcessInfo)
        return FALSE;

    startupInfo.cb = sizeof(STARTUPINFO);

    if (CreateProcess(wsExecutableFullPath.c_str(), const_cast<LPWSTR>(wsCommandLine.c_str()),
        NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInfo)) {
        // To get the remote image base address I need to instruct the Windows loader
        // to load the target image file in memory, and to compile the PEB

        // First of all allocates remote memory into the memory space of the process
        lpRemoteBuff = VirtualAllocEx(processInfo.hProcess, NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        // Writes a very basic and stupid function in the remote memory
        if (lpRemoteBuff && WriteProcessMemory(processInfo.hProcess, lpRemoteBuff, (LPCVOID)remote_opcodes, sizeof(remote_opcodes), (SIZE_T*)&ulBytesIo)) {
            // Creates and run a remote thread into the process with the recently loaded stupid function as startup routine
            hRemoteThread = CreateRemoteThread(processInfo.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpRemoteBuff, NULL, 0, &dwThreadId);

            if (hRemoteThread) {
                // Wait until the remote thread ends. After that, the PEB is already loaded
                WaitForSingleObject(hRemoteThread, INFINITE);
                if (lpRemoteBuff) VirtualFreeEx(processInfo.hProcess, lpRemoteBuff, 0, MEM_RELEASE);

                CloseHandle(hRemoteThread);
                *pProcessInfo = processInfo;
                bReturn = TRUE;
            }
            else {
                TerminateProcess(processInfo.hProcess, -1);
                CloseHandle(processInfo.hThread);
                CloseHandle(processInfo.hProcess);
                bReturn = FALSE;
            }
        }
        else
            bReturn = FALSE;
    }

    return bReturn;
}

BOOL InjectPtExploitDetectorAgentIntoRemoteProcess(const std::wstring dllToInject, const HANDLE hProcess)
{
    BOOL retValue = FALSE;
    
    if (!dllToInject.empty() || (hProcess != NULL))
    {
        size_t dllPathNameSize = dllToInject.length() * sizeof(wchar_t);

        // Allocate space in the remote process for the pathname
        LPVOID pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, dllPathNameSize, MEM_COMMIT, PAGE_READWRITE);
        if (pszLibFileRemote != NULL)
        {
            // Copy the DLL's pathname to the remote process address space
            DWORD n = WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)dllToInject.c_str(), dllPathNameSize, NULL);
            if (n > 0)
            {
                std::wstring fullPathToLoadLibraryGetter;
                PtExploitDetectorCommon::GetFullPathToFile(L"loadLibrary_x86_address.exe", fullPathToLoadLibraryGetter);
                
                // About to create remote thread to start test framework
                // Get the real address of LoadLibraryW in Kernel32.dll
                PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)_wsystem(fullPathToLoadLibraryGetter.c_str());
                if (pfnThreadRtn != NULL)
                {
                    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
                    if (hThread != NULL)
                    {
                        Sleep(500); //Sleeping for some time to allow DLLMain and its logic to be launched

                        retValue = TRUE;
                    }
                    else
                    {
                        std::wcout << L"    Error creating a remote thread in target process" << std::endl;
                        wprintf(L"    CreateRemoteThread failed with 0x%x\n", GetLastError());
                    }
                }
                else
                {
                    std::wcout << L"    Error obtaining address of LoadLibraryW function inside kernel32.dll library" << std::endl;
                }
            }
            else
            {
                std::wcout << L"    Error copying the DLL's pathname to the remote process address 0x" << std::hex << pszLibFileRemote << std::endl;
            }
        }
        else
        {
            std::wcout << L"    Error allocating memory in target process" << std::endl;
        }
    }
    else
    {
        std::wcout << L"    Bad arguments" << std::endl;
    }

    return retValue;
}

BOOL GetRemoteWindowsApis(const std::wstring channelID, RAPIs& apiAddresses)
{
    BOOL retValue = FALSE;
    
    IPCClient* client = new IPCClient(channelID);

    std::string functionName = "WinExec";

    ARRAYBYTE ret = client->SendRequest(PtExploitDetectorCommon::ExecutorsMode::GET_REMOTE_FUNCTION_ADDRESS,
        (unsigned char *)functionName.c_str(), functionName.length());

    //std::cout << std::endl << "    Function: " << functionName << " --- 0x" << std::hex << *(DWORD*)(&ret[0]) << std::endl;

    apiAddresses.insert(std::pair<UINT32, std::wstring>(*(UINT32*)(&ret[0]), L"WinExec"));

    if (apiAddresses.size() > 0)
        retValue = TRUE;
    
    return retValue;
}

// The PMI interrupt Thread 
DWORD WINAPI PmiThreadProc(LPVOID lpParameter) {
    BOOLEAN bReturn = FALSE;
    HANDLE hKernelEvent = NULL;                                 // Handler to get the event registered by the driver
	LPTSTR lpEventName = L"Global\\" INTEL_PT_PMI_EVENT_NAME;   // The name of the event registered by the driver
    HANDLE hWaitEvents[2] = { 0 };                              // Array to hold the events we are waiting for
    DWORD dwEventIndex = 0;										// The event number that has satisfied the wait
    DWORD dwBytesIo = 0;										// Number of I/O bytes
    PT_PMI_USER_CALLBACK pmiDescriptor = { 0 };                 // PMI structure to fill with information of current PMI routine and then deregister it
	
    DWORD dwCpuNumber = (DWORD)(QWORD)lpParameter;
	PT_CPU_BUFFER_DESC * pCurrentCpuBufferDesc = &g_appData.pCpuBufferDescArray[dwCpuNumber];

	//Xtrace(L"[PtControlApp] Executing PMI interrupt");

    hKernelEvent = OpenEvent(SYNCHRONIZE, FALSE, lpEventName);

	if (!hKernelEvent) return -1;
	hWaitEvents[0] = hKernelEvent;
	hWaitEvents[1] = g_appData.hExitEvent;

	while (TRUE) {
		// Perform an ALERTABLE wait... the function returns when the system queues an I/O completion routine or APC,
        // and the thread runs the routine or function. Otherwise, the function does not return and the completion
        // routine or APC function is not executed.
        // The function can return:
        //                         - The index of the event in the array
        //                         - WAIT_IO_COMPLETION means APC has been queued
		dwEventIndex = WaitForMultipleObjectsEx(2, hWaitEvents, FALSE, INFINITE, TRUE);

        // Although we have registered two events, we will perfom an action only when we are exiting
        // cause the other event is managed by the PMI callback
		if (dwEventIndex - WAIT_OBJECT_0 == 1) {
			DeviceIoControl(g_appData.hPtDevice, IOCTL_PTDRV_PAUSE_TRACE, (LPVOID)&g_appData.kActiveCpusAffinity, sizeof(KAFFINITY), NULL, 0, &dwBytesIo, NULL);
			break;
		}
		// Continue to wait on the PMI Event, and raise the appropriate Callbacks
	}
	// Deregister my callback
	pmiDescriptor.dwThrId = GetCurrentThreadId();
	pmiDescriptor.lpAddress = PmiCallback;
	DeviceIoControl(g_appData.hPtDevice, IOCTL_PTDRV_FREE_PMI_ROUTINE, (LPVOID)&pmiDescriptor, sizeof(PT_PMI_USER_CALLBACK), NULL, 0, &dwBytesIo, NULL);

	// Sleep a bit
	Sleep(500);

	// And write the rest of the log
	if (pCurrentCpuBufferDesc->lpPtBuff && pCurrentCpuBufferDesc->hBinFile) {
		BYTE zeroArray[16] = { 0 };
		DWORD dwEndOffset = 0;

        // This for loop is looking for a zeroArray inside the PtBuff of the CurrentCpuBufferDesc to find in this
        // way the part of the PtBuff with valid data to store.
		for (DWORD i = 0; i < pCurrentCpuBufferDesc->dwBuffSize - sizeof(zeroArray); i += sizeof(zeroArray)) 
			if (RtlCompareMemory(pCurrentCpuBufferDesc->lpPtBuff + i, zeroArray, sizeof(zeroArray)) == sizeof(zeroArray)) {
				dwEndOffset = i; break;
			}
		
		if (!dwEndOffset) dwEndOffset = pCurrentCpuBufferDesc->dwBuffSize;
		bReturn = WriteFile(pCurrentCpuBufferDesc->hBinFile, pCurrentCpuBufferDesc->lpPtBuff, dwEndOffset, &dwBytesIo, NULL);
		if (pCurrentCpuBufferDesc->hTextFile) {
			// Dump the text trace file immediately
            VPACKETS chain;
            QWORD & qwDelta = pCurrentCpuBufferDesc->qwDelta;
			bReturn = pt_dump_packets(pCurrentCpuBufferDesc->lpPtBuff, dwEndOffset, pCurrentCpuBufferDesc->hTextFile, qwDelta, &chain);
			pCurrentCpuBufferDesc->qwDelta += (QWORD)dwEndOffset;

            if (chain.size() > 0) {
                Xtrace(L"[PtControlApp] Executing PMI interrupt. Chains detected: %d", chain.size());
                EvaluateAPIsOnChain(chain);
            }
		}
	}

	return bReturn;
}

// The PMI callback
VOID PmiCallback(DWORD dwCpuId, PVOID lpBuffer, QWORD qwBufferSize) {
    BOOL bReturn = FALSE;
	DWORD dwBytesIo = 0;							// Number of I/O bytes
	
    PT_CPU_BUFFER_DESC * pCurrentCpuBufferDesc = &g_appData.pCpuBufferDescArray[dwCpuId];
    QWORD & qwDelta = pCurrentCpuBufferDesc->qwDelta;
    KAFFINITY currentCpuAffinity = (1i64 << dwCpuId);

	//Xtrace(L"[PtControlApp] Executing PMI callback");

	// Check if there is the main thread, open if so
	if (g_appData.dwMainThreadId && !g_appData.hMainThread)
		g_appData.hMainThread = OpenThread(SYNCHRONIZE | THREAD_SUSPEND_RESUME, FALSE, g_appData.dwMainThreadId);

	// Suspend the main thread if any
	if (g_appData.hMainThread) SuspendThread(g_appData.hMainThread);

	if (pCurrentCpuBufferDesc->hBinFile) {
		bReturn = WriteFile(pCurrentCpuBufferDesc->hBinFile, lpBuffer, (DWORD)qwBufferSize, &dwBytesIo, NULL);
		
		if (pCurrentCpuBufferDesc->hTextFile) {
            // Dump the text trace file immediately
            VPACKETS chain;
            bReturn = pt_dump_packets((LPBYTE)lpBuffer, (DWORD)qwBufferSize, pCurrentCpuBufferDesc->hTextFile, qwDelta, &chain);
            qwDelta += (QWORD)qwBufferSize;
            
            if (chain.size() > 0) {
                Xtrace(L"[PtControlApp] Executing PMI callback. Chains detected: %d", chain.size());
                EvaluateAPIsOnChain(chain);
            }
        }
	}

	RtlZeroMemory((LPBYTE)lpBuffer, (DWORD)qwBufferSize);

	// Resume the tracing and the execution of the target process
	bReturn = DeviceIoControl(g_appData.hPtDevice, IOCTL_PTDRV_RESUME_TRACE, (LPVOID)&currentCpuAffinity, sizeof(KAFFINITY), NULL, 0, &dwBytesIo, NULL);
	
	if (!g_appData.currentTrace.bTraceKernel)
		ZwResumeProcess(g_appData.hTargetProcess);

	if (g_appData.hMainThread) ResumeThread(g_appData.hMainThread);
}

void EvaluateAPIsOnChain(VPACKETS chain)
{
    for (unsigned index = 0; index < chain.size(); ++index)
    {
        if (g_appData.remoteAPIs.find(chain[index].second) != g_appData.remoteAPIs.end())
        {
            Xtrace(L"[PtControlApp] Remote API detected on chain.");
        }
    }
}