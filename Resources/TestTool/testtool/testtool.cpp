// testtool.cpp : Defines the entry point for the console application.
//

#include "helpers.h"


void ShowHelp()
{
	std::wcerr << L"testtool usage:" << std::endl;
	std::wcerr << L"testtool.exe -h for help" << std::endl;
	std::wcerr << L"testtool.exe -f <testcase_payload_file> -t <target_pid_of_process_to_inject>" << std::endl;
}



int wmain(int argc, wchar_t *argv[])
{
	int ret = 0;
	UINT32 executorMode = TestCommon::DEFAULT_EXECUTOR_MODE;
	std::wstring defaultFileToInject(TestCommon::DEFAULT_DLL_TO_INJECT);
	CmdArgsParser inputCmds(argc, argv);
	TestCommon::TestData testData;

	if (inputCmds.WasOptionRequested(L"-h") ||
		!inputCmds.WasOptionRequested(L"-f") ||
		!inputCmds.WasOptionRequested(L"-t"))
	{
		std::wcerr << L"[-] Make sure to provide all the required arguments" << std::endl;
		ShowHelp();
		return 1;
	}

	const std::wstring &pidToInject = inputCmds.GetOptionValue(L"-t");
	if (pidToInject.empty() ||
		!TestToolHelpers::IsNumber(pidToInject))
	{
		std::wcerr << L"[-] Provided PID is not valid" << std::endl;
		ShowHelp();
		return 1;
	}

	const std::wstring &testcaseFile = inputCmds.GetOptionValue(L"-f");
	std::wstring fullPathTestcaseFile;
	if (TestToolHelpers::IsValidFile(testcaseFile) &&
		TestToolHelpers::GetFullPathToFile(testcaseFile, fullPathTestcaseFile) &&
		!fullPathTestcaseFile.empty())
	{
		std::wcout << "[+] Testcase file is going to be used: " << fullPathTestcaseFile << std::endl;
	}
	else
	{

		std::wcerr << L"[-] Given testcase file cannot be found" << std::endl;
		ShowHelp();
		return 1;
	}

	std::wstring fullPathToFileToInject;
	if (TestToolHelpers::IsValidFile(defaultFileToInject) &&
		TestToolHelpers::GetFullPathToFile(defaultFileToInject, fullPathToFileToInject))
	{
		std::wcout << "[+] Agent DLL to be injected: " << defaultFileToInject << std::endl;
	}
	else
	{
		std::wcerr << L"[-] TestToolAgent DLL file to inject cannot be found" << std::endl;
		ShowHelp();
		return 1;
	}

	//Real work starts here
	ExecutorManager manager;
	auto execROPChain = std::make_shared<ExecutorROPChain>();

	manager.AddExecutor(execROPChain);

	testData.channelID.assign(TestCommon::PRE_CHANNEL_TOKEN + pidToInject);
	testData.fileToInject.assign(fullPathToFileToInject);
	testData.testcaseFile.assign(fullPathTestcaseFile);
	testData.pidToInject.assign(pidToInject);

    std::wcout << "[+] About to Execute ROP Chain against PID: " << pidToInject << std::endl;
    std::wcout << "[+] Using the following file as a payload: " << testcaseFile << std::endl;

	if (manager.RunExecutor(TestCommon::ExecutorsMode::TEST_ROP_CHAIN, testData))
	{
		std::wcout << "[+] Testcase was succesfully executed!" << std::endl;
	}
	else
	{
		std::wcout << "[-] There was a problem executing the requested testcase: " <<
			TestCommon::ExecutorModeToString(TestCommon::ExecutorsMode::TEST_ROP_CHAIN) <<
			std::endl;
	}

    return 0;
}

