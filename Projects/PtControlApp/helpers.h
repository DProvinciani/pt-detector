#ifndef _CMD_PARSER_H_
#define _CMD_PARSER_H_

#include <iostream>
#include <string>
#include <vector>

bool IsValidFile(const std::wstring &fileName)
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
