#include "executors.h"

#define CHAIN_BUFFER_SIZE 64

#pragma warning(disable : 4996)
#pragma runtime_checks( "", off )

int TestToolAgentExecutors::ExecROPChain(unsigned char* ropChain)
{
	int ret = 0;

	TestCommon::Xtrace(L"[TestToolAgent] Entering to ExecROPChain!");

    char ropChainOnStack[CHAIN_BUFFER_SIZE] = { 0 };

    FILE *ropChainFile;
    int filesize;

    ropChainFile = fopen("c:\\rop_chain.txt", "r");
    if (!ropChainFile) {
        printf("Error opening %s\n", "c:\\rop_chain.txt");
        return ret;
    }

    fseek(ropChainFile, 0, SEEK_END);
    filesize = ftell(ropChainFile);
    fseek(ropChainFile, 0, SEEK_SET);

    // Copying the rop chain into the stack, so buffer overflow happens here
    fread(ropChainOnStack, 1, filesize, ropChainFile);

    fclose(ropChainFile);

	if (ropChainOnStack[0]) { //use local variables so compiler won't remove them
        DeleteFile(L"c:\\rop_chain.txt");
        TestCommon::Xtrace(L"[TestToolAgent] Leaving ExecROPChain!");
	}

	return ret;
}
