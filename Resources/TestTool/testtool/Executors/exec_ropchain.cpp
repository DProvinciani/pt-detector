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
                    \"^[G|D]$\": { \"type\": \"string\" }\n\
                },\n\
                \"additionalProperties\": false\n\
            }\n\
        }\n\
    },\n\
\"required\": [\"payload\"],\n\
\"additionalProperties\": false\n\
}"

bool ExecutorROPChain::Execute(TestCommon::TestData &data)
{
	bool retValue = true;
    int retError = 0;

	std::wcout << L"[+] About to execute " << GetDescription() << std::endl;

	if (TestToolHelpers::IsTestDataValid(data))
	{
        DWORD fakeSize = MAX_PAYLOAD_SIZE;
        DWORD bytesRead = 0;

        char fakePayloadJsonText[MAX_PAYLOAD_SIZE] = { 0 };
        
        if (TestToolHelpers::ReadFileToInjectInBuffer(data.testcaseFile, fakeSize, fakePayloadJsonText, bytesRead))
        {
            std::wcout << "[+] Validating payload JSON file" << std::endl;
            
            // Building the schema for JSON payload structure validation
            rapidjson::Document fakePayloadJsonSchema;
            bool errorParsingJsonSchema = fakePayloadJsonSchema.Parse(JSON_PAYLOAD_SCHEMA).HasParseError();

            rapidjson::SchemaDocument schema(fakePayloadJsonSchema);
            rapidjson::SchemaValidator validator(schema);

            // Parsing fake payload JSON document
            rapidjson::Document fakePayloadJsonDocument;
            bool errorParsingJsonDocument = fakePayloadJsonDocument.Parse(fakePayloadJsonText).HasParseError();

            if (!errorParsingJsonSchema && !errorParsingJsonDocument && fakePayloadJsonDocument.Accept(validator))
            {
                const rapidjson::Value& payloadArray = fakePayloadJsonDocument["payload"];

                std::wcout << "[+] Filling the Gadget DB and payload buffer" << std::endl;

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
                    std::vector<std::pair <std::string, unsigned int>> intermediateRopChain;
                    char gadgetDbEncoded[MAX_PAYLOAD_SIZE] = { 0 };
                    unsigned int gadgetOffset = 0;

                    ks_option(ksEngine, KS_OPT_SYNTAX, 0);

                    for (rapidjson::SizeType index = 0; index < payloadArray.Size(); ++index)
                    {
                        unsigned int currentGadgetOffset = 0; // Si descomento lo de arriba tengo que eliminar los tipos de datos aca
                        char * address = NULL;                // Si descomento lo de arriba tengo que eliminar los tipos de datos aca

                        if (payloadArray[index].FindMember("G") != payloadArray[index].MemberEnd()) // Si es un gadget...
                        {
                            std::string currentGadget = payloadArray[index].FindMember("G")->value.GetString(); // Pido el gadget al JSON

                            unsigned char * assemblyBytes = nullptr;
                            size_t assemblySize = 0;
                            size_t count = 0;

                            if (ks_asm(ksEngine, currentGadget.c_str(), 0, &assemblyBytes, &assemblySize, &count))
                            {
                                std::cerr << "[-] TestKeyStone: ks_asm() failed to compile Gadget: " << currentGadget
                                    << "  ---  " << count << " statements " << ks_errno(ksEngine) << " error" << std::endl;
                            }
                            else
                            {
                                std::cout << "[+] Assembled: " << currentGadget << "  --- " << assemblySize << " bytes and " << count << " statements" << std::endl;

                                intermediateRopChain.push_back(std::pair <std::string, unsigned int>("gadget", gadgetOffset));
                                
                                for (unsigned int byteIndex = 0; byteIndex < assemblySize; ++byteIndex, ++gadgetOffset)
                                    gadgetDbEncoded[gadgetOffset] = *(assemblyBytes + byteIndex);
                            }
                        }
                        else
                            intermediateRopChain.push_back(std::pair <std::string, unsigned int>("data", std::stoi(payloadArray[index].FindMember("D")->value.GetString(), nullptr, 16)));

                        //Adding more gadgets to be able to execute an stack pivot
                        if (index == (payloadArray.Size() - 1)) {
                            unsigned char * assemblyBytes = nullptr;
                            size_t assemblySize = 0;
                            size_t count = 0;
                            std::string currentGadget = "SUB ESP, 136 ; RET";

                            if (ks_asm(ksEngine, currentGadget.c_str(), 0, &assemblyBytes, &assemblySize, &count))
                            {
                                std::cerr << "[-] TestKeyStone: ks_asm() failed to compile Gadget: " << currentGadget
                                    << "  ---  " << count << " statements " << ks_errno(ksEngine) << " error" << std::endl;
                            }
                            else
                            {
                                std::cout << "[+] Assembled: " << currentGadget << "  --- " << assemblySize << " bytes and " << count << " statements" << std::endl;

                                intermediateRopChain.push_back(std::pair <std::string, unsigned int>("gadget", gadgetOffset));

                                for (unsigned int byteIndex = 0; byteIndex < assemblySize; ++byteIndex, ++gadgetOffset)
                                    gadgetDbEncoded[gadgetOffset] = *(assemblyBytes + byteIndex);
                            }
                        }
                    }


                    system("pause");
                    //return false;

                    LPVOID gadgetDbRemoteAddr = nullptr;
                    DWORD gadgetDbSize = MAX_PAYLOAD_SIZE;

                    if (TestToolHelpers::InjectIntoProcessViaCreateRemoteThread(data.fileToInject, data.pidToInject, gadgetDbEncoded, gadgetDbSize, gadgetDbRemoteAddr))
                    {
                        std::wcout << "[+] Fixing offsets values from Gadget DB base address" << std::endl;
                        
                        DWORD fakePayload[MAX_PAYLOAD_SIZE] = { 0 };

                        // We go through the intermediateRopChain until one before the last one to avoid put the stack pivot gadget
                        for (unsigned index = 0; index < (intermediateRopChain.size()-1); ++index)
                        {
                            if (intermediateRopChain[index].first == "gadget")
                            {
                                unsigned int currentGadgetOffset = intermediateRopChain[index].second;
                                char * address = (char *)gadgetDbRemoteAddr + currentGadgetOffset;
                                fakePayload[index] = (DWORD)address;

                                std::wcerr << "    GADGET:    " << payloadArray[index].FindMember("G")->value.GetString()
                                    << " --> 0x" << std::hex << (DWORD)address << std::endl;
                            }
                            else if (intermediateRopChain[index].first == "data")
                            {
                                char * payloadData = (char *)intermediateRopChain[index].second;
                                fakePayload[index] = (DWORD)payloadData;

                                std::wcerr << "    DATA:    " << payloadArray[index].FindMember("D")->value.GetString() << std::endl;
                            }
                        }

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

                            // Next we fill with 'A' characters untill make a buffer overflow
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

                            std::wcerr << L"    Prass ENTER to send and execute the ROP chain" << std::endl;
                            std::getchar();

                            //Opening IPC and sending ROP chain here
                            auto IPCClient = new TestToolHelpers::IPCClient(data.channelID);
                            TestCommon::ARRAYBYTE ret = IPCClient->SendRequest(TestCommon::TestExecutorsMode::TEST_ROP_CHAIN, (unsigned char *)fakePayload, fakeSize);
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
                }
                else
                {
                    TestCommon::Xtrace(L"[-] KeyStone: failed on ks_open()");
                    retValue = false;
                }
            }
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
        }
        else
        {
            std::wcerr << L"[-] There was a problem readding the fake payload JSON file. Quitting now." << std::endl;
            retValue = false;
        }
	}

	return retValue;
}