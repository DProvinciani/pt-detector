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
#include "stdafx.h"
#include "IntelPtControlApp.h"
#include "Psapi.h"
#include "pt_dump.h"
#include "UndocNt.h"
#include "helpers.h"

const LPTSTR g_ptDeviceName = L"\\\\.\\WindowsIntelPtDev"; // Using \\.\ allows to work with the Device Namespace: https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx
#pragma comment (lib, "ntdll.lib")

// Entry point without command line arguments
int ConfigureTrace(const std::wstring wsExecutableFullPath)
{
	BOOL bReturn = FALSE;
    DWORD dwLastError = 0;
    SYSTEM_INFO systemInfo = { 0 };                 // Struct to hold system information
	INTEL_PT_CAPABILITIES ptCapabilities = { 0 };   // Struct to hold all the suported Intel PT capabilities
	HANDLE hPtDevice = NULL;				    	// Handle to the PT device
    LPTSTR lpOutputDir = NULL;			    		// Full path tho the output trace files directory
    DWORD dwCpusToUse = 1;							// Number of CPUs in which to run the code (supporting only one by moment)
    KAFFINITY cpuAffinity = 0;						// The processor Affinity mask
    PT_CPU_BUFFER_DESC * pCpuBufferDescArray;		// The CPU PT buffer descriptor array
	PT_USER_REQ ptStartStruct = { 0 };				// The Intel PT starting structure
	DWORD dwBytesIo = 0;							// Number of I/O bytes
	BOOLEAN bDoKernelTrace = FALSE;					// TRUE if I would like to do kernel tracing
	BOOLEAN bManuallyAllocBuff = FALSE;				// TRUE if I would like to manually allocate the buffer (used for test purposes)
	BOOLEAN bDeleteFiles = FALSE;					// TRUE if some errors that require the file deletion
	PROCESS_INFORMATION pi = { 0 };

#pragma region 0. Verifying system information, IntelPT support and opening IntelPT handler
	// Getting current process information, system information and asking for Intel PT support
    if (IsWow64(nullptr))
        std::wcout << L"PtControlApp running under WOW64." << std::endl;
    else
        std::wcout << L"PtControlApp not running under WOW64." << std::endl;

	GetNativeSystemInfo(&systemInfo);
	bReturn = CheckIntelPtSupport(&ptCapabilities);
    std::wcout << L"Intel Processor Tracing support for this CPU: ";
    if (bReturn) 
		cl_wprintf(GREEN, L"YES\r\n"); 
	else
	{
		cl_wprintf(RED, L"NO\r\n");
		return 0;
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
	else {
		cpuAffinity = systemInfo.dwActiveProcessorMask;
	}
#pragma endregion
	
#pragma region 3. Create the CPU buffer data structures and trace files
	std::wcout << L"Creating trace output files... ";
	bReturn = (BOOL)InitPerCpuData(cpuAffinity, lpOutputDir);

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

		bReturn = (BOOL)InitPerCpuData(cpuAffinity, lpOutputDir);
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
	wprintf(L"Creating target process... ");
	bReturn = SpawnSuspendedProcess(wsExecutableFullPath.c_str(), NULL, &pi);
	if (bReturn) cl_wprintf(GREEN, L"OK\r\n");
	else {
		wprintf(L"Error!\r\n");
		FreePerCpuData(TRUE);
		CloseHandle(hPtDevice);
		wprintf(L"Press any key to exit...");
		getwchar();
		return -1;
	}
	g_appData.hTargetProcess = pi.hProcess;

	bReturn = SetProcessAffinityMask(pi.hProcess, cpuAffinity);
	_ASSERT(bReturn);
	if (!bReturn) {
		cl_wprintf(YELLOW, L"Warning!\r\n");
		wprintf(L"   Unable Set the processor affinity for the spawned process.\r\n");
	}

	// Create the PMI threads (1 per target CPU)
	for (int i = 0; i < (int)dwCpusToUse; i++) {
		PT_PMI_USER_CALLBACK pmiDesc = { 0 };
		HANDLE hNewThr = NULL;
		DWORD newThrId = 0;

		hNewThr = CreateThread(NULL, 0, PmiThreadProc, (LPVOID)(QWORD)i, CREATE_SUSPENDED, &newThrId);
		// Register this thread and its callback
		pmiDesc.dwThrId = newThrId;
		pmiDesc.kCpuAffinity = (1i64 << i);
		pmiDesc.lpAddress = PmiCallback;
		bReturn = DeviceIoControl(hPtDevice, IOCTL_PTDRV_REGISTER_PMI_ROUTINE, (LPVOID)&pmiDesc, sizeof(PT_PMI_USER_CALLBACK), NULL, 0, &dwBytesIo, NULL);
		if (bReturn) {
			pCpuBufferDescArray[i].dwPmiThreadId = newThrId;
			pCpuBufferDescArray[i].hPmiThread = hNewThr;
			ResumeThread(hNewThr);
		}
	}
#pragma endregion

#pragma region 5. Set IP filtering (if any) and TRACE options
	HMODULE hRemoteMod = NULL;						// The remote module base address
	MODULEINFO remoteModInfo = { 0 };				// The remote module information
	if (g_appData.bTraceByIp) {
		// Now grab the remote image base address and size
		bReturn = EnumProcessModules(pi.hProcess, &hRemoteMod, sizeof(HMODULE), &dwBytesIo);
		bReturn = GetModuleInformation(pi.hProcess, hRemoteMod, &remoteModInfo, sizeof(MODULEINFO));
		dwLastError = GetLastError();

		g_appData.bTraceOnlyKernel = bDoKernelTrace;

		if (!remoteModInfo.lpBaseOfDll) {
			cl_wprintf(RED, L"Error! ");
			wprintf(L"I was not able to find the target process main module base address and size.\r\n");
			FreePerCpuData(TRUE);
			CloseHandle(hPtDevice);
			return -1;
		}

		cl_wprintf(PINK, L"\r\n        Using IP filtering mode!\r\n");
		wprintf(L"        New Process main module base address: 0x%llX, size 0x%08X.\r\n\r\n",
			(QWORD)remoteModInfo.lpBaseOfDll, remoteModInfo.SizeOfImage);

		// Set the PT_USER_REQUEST structure
		ptStartStruct.IpFiltering.dwNumOfRanges = 1;
		ptStartStruct.IpFiltering.Ranges[0].lpStartVa = (LPVOID)((ULONG_PTR)remoteModInfo.lpBaseOfDll);
		ptStartStruct.IpFiltering.Ranges[0].lpEndVa = (LPVOID)((ULONG_PTR)remoteModInfo.lpBaseOfDll + remoteModInfo.SizeOfImage);
		ptStartStruct.IpFiltering.Ranges[0].bStopTrace = FALSE;
	}		// END Tracing by IP block

	// Write some information in the output text file:
	WriteCpuTextDumpsHeader(wsExecutableFullPath.c_str(), (ULONG_PTR)remoteModInfo.lpBaseOfDll, remoteModInfo.SizeOfImage);
	ptStartStruct.bTraceUser = !bDoKernelTrace;
	ptStartStruct.bTraceKernel = bDoKernelTrace;
	// For now do not set the frequencies....
	ptStartStruct.dwOptsMask = PT_TRACE_BRANCH_PCKS_MASK | PT_ENABLE_RET_COMPRESSION_MASK | PT_ENABLE_TOPA_MASK;
	ptStartStruct.kCpuAffinity = cpuAffinity;
	ptStartStruct.dwTraceSize = g_appData.dwTraceBuffSize;
#pragma endregion

#pragma region 6. Allocate each PT CPU buffer and Start the tracing and wait the process to exit
	LPVOID * lpBuffArray = new LPVOID[dwCpusToUse];
	RtlZeroMemory(lpBuffArray, sizeof(LPVOID)* dwCpusToUse);
	
	// Start the device Tracing
	wprintf(L"Starting the Tracing and resuming the process... ");
	ptStartStruct.dwProcessId = pi.dwProcessId;
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
		ResumeThread(pi.hThread);
		wprintf(L"Waiting for the traced process to exit...\r\n\r\n");
		WaitForSingleObject(pi.hProcess, INFINITE);
	}
	else {
		TerminateProcess(pi.hProcess, -1);
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

#pragma region 7. Get the results of our tracing (like the number of written packets)
	PT_TRACE_DETAILS ptDetails = { 0 };
	
	cl_wprintf(DARKYELLOW, L"    *** PT Trace results ***\r\n");
	
	for (int i = 0; i < sizeof(cpuAffinity) * 8; i++) {
		if (!(cpuAffinity & (1i64 << i))) continue;

		RtlZeroMemory(&ptDetails, sizeof(ptDetails));
		bReturn = DeviceIoControl(hPtDevice, IOCTL_PTDR_GET_TRACE_DETAILS, (LPVOID)&i, sizeof(int), (LPVOID)&ptDetails, sizeof(ptDetails), &dwBytesIo, NULL);
		if (bReturn)
			wprintf(L"        Number of acquired packets: %I64i\r\n", ptDetails.qwTotalNumberOfPackets);
		else
			cl_wprintf(RED, L"        Error getting trace details!\r\n");
	}

	wprintf(L"        All the dumps have been saved in \"%s\".\r\n\r\n", lpOutputDir);
#pragma endregion

#pragma region 8. Free the resources and close each files
	// Stop the Tracing (and clear the buffer if not manually allocated)
	bReturn = DeviceIoControl(hPtDevice, IOCTL_PTDRV_CLEAR_TRACE, (LPVOID)&cpuAffinity, sizeof(cpuAffinity), NULL, 0, &dwBytesIo, NULL);

	CloseHandle(pi.hProcess); 
	CloseHandle(pi.hThread);
	FreePerCpuData(bDeleteFiles);
	if (bManuallyAllocBuff)
		bReturn = DeviceIoControl(g_appData.hPtDevice, IOCTL_PTDRV_FREE_BUFFERS, (LPVOID)&cpuAffinity,
			sizeof(cpuAffinity), NULL, 0, &dwBytesIo, NULL);


	CloseHandle(hPtDevice);
#pragma endregion
    return 0;
}

// Check if the current CPU has support for Intel PT
BOOL CheckIntelPtSupport(INTEL_PT_CAPABILITIES * lpPtCapabilities)
{
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
bool InitPerCpuData(KAFFINITY cpuAffinity, LPTSTR lpOutputDir) {
 	PT_CPU_BUFFER_DESC * pCpuBufferDescArray = NULL;	// The new PER-CPU buffer array
    DWORD dwCpusToUse = 0;								// Number of CPUs to use
    DWORD dwCurrentCpu = 0;	    						// Current CPU
    TCHAR newFileName[MAX_PATH] = { 0 };                // The new file name string
	HANDLE hNewFile = NULL;								// The handle of the new file

	FreePerCpuData(FALSE);
	for (int i = 0; i < sizeof(cpuAffinity) * 8; i++)
		if (cpuAffinity & (1i64 << i)) dwCpusToUse++;

	pCpuBufferDescArray = new PT_CPU_BUFFER_DESC[dwCpusToUse];
	RtlZeroMemory(pCpuBufferDescArray, sizeof(PT_CPU_BUFFER_DESC) * dwCpusToUse);
	g_appData.dwActiveCpus = dwCpusToUse;
	g_appData.kActiveCpusAffinity = cpuAffinity;
	g_appData.pCpuBufferDescArray = pCpuBufferDescArray;

	for (int i = 0; sizeof(cpuAffinity) * 8; i++) {
		PT_CPU_BUFFER_DESC * pCurrentCpuBufferDesc = &pCpuBufferDescArray[dwCurrentCpu];
		if (!(cpuAffinity & (1i64 << i))) continue;
		if (dwCurrentCpu >= dwCpusToUse) break;

		RtlZeroMemory(newFileName, MAX_PATH * sizeof(TCHAR));
		swprintf_s(newFileName, MAX_PATH, L"%s\\cpu%.2i_bin.bin", lpOutputDir, i);

		// Create the binary file 
		hNewFile = CreateFile(newFileName, FILE_GENERIC_WRITE | DELETE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);

		if (hNewFile != INVALID_HANDLE_VALUE) {
			pCurrentCpuBufferDesc->hBinFile = hNewFile;

            RtlZeroMemory(newFileName, MAX_PATH * sizeof(TCHAR));
			swprintf_s(newFileName, MAX_PATH, L"%s\\cpu%.2i_text.log", lpOutputDir, i);

            // Create the text file 
			hNewFile = CreateFile(newFileName, FILE_GENERIC_WRITE | DELETE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);

            if (hNewFile != INVALID_HANDLE_VALUE)
                pCurrentCpuBufferDesc->hTextFile = hNewFile;
            else {
                FreePerCpuData(TRUE);
                return false;
            }
		}

		dwCurrentCpu++;
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
BOOL SpawnSuspendedProcess(const wchar_t* lpExecutableFullPath, wchar_t* lpCmdLine, PROCESS_INFORMATION * pOutProcInfo) {
	BYTE remote_opcodes[] = { 0x90, 0x90, 0xc3, 0x90, 0x90 };			// NOP - RET opcodes
	PROCESS_INFORMATION pi = { 0 };					// Process information
	STARTUPINFO si = { 0 };							// The process Startup options
	ULONG_PTR ulBytesIo = 0;						// Number of I/O bytes
	LPVOID lpRemBuff = NULL;						// Remote memory buffer
	HANDLE hRemoteThr = NULL;						// The remote thread stub 
	BOOL bRetVal = FALSE;							// Win32 return value
	DWORD dwThrId = 0;								// Remote thread ID

	si.cb = sizeof(STARTUPINFO);
	bRetVal = CreateProcess(lpExecutableFullPath, lpCmdLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	// To get the remote image base address I need to instruct the Windows loader to load the 
	// Target image file in memory, and to compile the PEB
	lpRemBuff = VirtualAllocEx(pi.hProcess, NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpRemBuff) 
		bRetVal = WriteProcessMemory(pi.hProcess, lpRemBuff, (LPCVOID)remote_opcodes, sizeof(remote_opcodes), (SIZE_T*)&ulBytesIo);
	else
		bRetVal = FALSE;

	if (bRetVal) 
		hRemoteThr = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpRemBuff, NULL, 0, &dwThrId);

	if (hRemoteThr) {
		WaitForSingleObject(hRemoteThr, INFINITE);
		if (lpRemBuff) VirtualFreeEx(pi.hProcess, lpRemBuff, 0, MEM_RELEASE);

		// Get rid of it:
		CloseHandle(hRemoteThr);
		if (pOutProcInfo) *pOutProcInfo = pi;
		return TRUE;
	} else {
		TerminateProcess(pi.hProcess, -1);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return FALSE;
	}
}

// The PMI interrupt Thread 
DWORD WINAPI PmiThreadProc(LPVOID lpParameter) {
	LPTSTR lpEventName = L"Global\\" INTEL_PT_PMI_EVENT_NAME;
	HANDLE hKernelEvt = NULL;
	DWORD dwLastErr = 0;										// Last Win32 error
	DWORD dwBytesIo = 0,										// Number of I/O bytes
		dwEvtNum = 0;											// The event number that has satisfied the wait
	BOOLEAN bRetVal = FALSE;
	DWORD dwCpuNumber = (DWORD)(QWORD)lpParameter;
	HANDLE hWaitEvts[2] = { 0 };
	PT_PMI_USER_CALLBACK pmiDesc = { 0 };
	PT_CPU_BUFFER_DESC * pCurCpuBuff = &g_appData.pCpuBufferDescArray[dwCpuNumber];

	Xtrace(L"[PtControlApp] Executing PMI interrupt");

	hKernelEvt = OpenEvent(SYNCHRONIZE, FALSE, lpEventName);
	dwLastErr = GetLastError();

	if (!hKernelEvt) return -1;
	hWaitEvts[0] = hKernelEvt;
	hWaitEvts[1] = g_appData.hExitEvent;

	while (TRUE) {
		// Perform an ALERTABLE wait
		dwEvtNum = WaitForMultipleObjectsEx(2, hWaitEvts, FALSE, INFINITE, TRUE);

		// WAIT_IO_COMPLETION means APC has been queued
		if (dwEvtNum - WAIT_OBJECT_0 == 1) {
			// We are exiting, pause the Tracing
			DeviceIoControl(g_appData.hPtDevice, IOCTL_PTDRV_PAUSE_TRACE, (LPVOID)&g_appData.kActiveCpusAffinity, sizeof(KAFFINITY), NULL, 0, &dwBytesIo, NULL);
			break;
		}
		// Continue to wait on the PMI Event, and raise the appropriate Callbacks
	}
	// Deregister my callback
	pmiDesc.dwThrId = GetCurrentThreadId();
	pmiDesc.lpAddress = PmiCallback;
	DeviceIoControl(g_appData.hPtDevice, IOCTL_PTDRV_FREE_PMI_ROUTINE, (LPVOID)&pmiDesc, sizeof(PT_PMI_USER_CALLBACK), NULL, 0, &dwBytesIo, NULL);

	// Sleep a bit
	Sleep(500);

	// and write the rest of the log
	if (pCurCpuBuff->lpPtBuff && pCurCpuBuff->hBinFile) {
		BYTE zeroArray[16] = { 0 };
		DWORD dwEndOffset = 0;

		for (DWORD i = 0; i < pCurCpuBuff->dwBuffSize - sizeof(zeroArray); i += sizeof(zeroArray)) 
			if (RtlCompareMemory(pCurCpuBuff->lpPtBuff + i, zeroArray, sizeof(zeroArray)) == sizeof(zeroArray)) {
				dwEndOffset = i; break;
			}
		
		if (!dwEndOffset) dwEndOffset = g_appData.pCpuBufferDescArray[dwCpuNumber].dwBuffSize;
		bRetVal = WriteFile(pCurCpuBuff->hBinFile, pCurCpuBuff->lpPtBuff, dwEndOffset, &dwBytesIo, NULL);
		if (pCurCpuBuff->hTextFile) {
			// Dump the text trace file immediately
			bRetVal = pt_dumpW((LPBYTE)pCurCpuBuff->lpPtBuff, (DWORD)dwEndOffset, pCurCpuBuff->hTextFile, pCurCpuBuff->qwDelta, g_appData.bTraceOnlyKernel);
			pCurCpuBuff->qwDelta += (QWORD)dwEndOffset;
		}
	}

	return 0;
}

// The PMI callback
VOID PmiCallback(DWORD dwCpuId, PVOID lpBuffer, QWORD qwBufferSize) {
	HANDLE hTraceBinFile = NULL;					// The trace BINARY file
	HANDLE hTraceTextFile = NULL;					// The trace Text file
	DWORD dwDescNum = 0;							// The descriptor number
	DWORD dwBytesIo = 0;							// Number of I/O bytes
	BOOL bRetVal = FALSE;							// Returned Win32 value
	DWORD dwLastErr = 0;							// Last Win32 error
	KAFFINITY thisCpuAffinity = (1i64 << dwCpuId);

	Xtrace(L"[PtControlApp] Executing PMI callback");

	// Check if there is the main thread, open if so
	if (g_appData.dwMainThreadId && !g_appData.hMainThread)
		g_appData.hMainThread = OpenThread(SYNCHRONIZE | THREAD_SUSPEND_RESUME, FALSE, g_appData.dwMainThreadId);

	// Convert the CPU ID in descriptor number
	for (int i = 0; i < sizeof(KAFFINITY) * 8; i++) {
		if ((1i64 << i) & g_appData.kActiveCpusAffinity) {
			if (i == dwCpuId) break;
			dwDescNum++;
		}
	}
	// Grab the parameters
	hTraceBinFile = g_appData.pCpuBufferDescArray[dwDescNum].hBinFile;
	hTraceTextFile = g_appData.pCpuBufferDescArray[dwDescNum].hTextFile;
	QWORD & qwDelta = g_appData.pCpuBufferDescArray[dwDescNum].qwDelta;

	// Suspend the main thread if any
	if (g_appData.hMainThread) SuspendThread(g_appData.hMainThread);

	if (hTraceBinFile) {
		bRetVal = WriteFile(hTraceBinFile, lpBuffer, (DWORD)qwBufferSize, &dwBytesIo, NULL);
		
		if (!bRetVal) {
			cl_wprintf(RED, L"Warning! ");
			wprintf(L"Unable to write in the log file. Results could be erroneous.\r\n");
		}
	}

	if (hTraceTextFile) {
		// Dump the text trace file immediately
		bRetVal = pt_dumpW((LPBYTE)lpBuffer, (DWORD)qwBufferSize, hTraceTextFile, qwDelta, g_appData.bTraceOnlyKernel);
		qwDelta += (QWORD)qwBufferSize;
	}
	RtlZeroMemory((LPBYTE)lpBuffer, (DWORD)qwBufferSize);

	// Resume the tracing and the execution of the target process
	bRetVal = DeviceIoControl(g_appData.hPtDevice, IOCTL_PTDRV_RESUME_TRACE, (LPVOID)&thisCpuAffinity, sizeof(KAFFINITY), NULL, 0, &dwBytesIo, NULL);
	
	if (!g_appData.currentTrace.bTraceKernel)
		ZwResumeProcess(g_appData.hTargetProcess);
	if (g_appData.hMainThread) ResumeThread(g_appData.hMainThread);
}